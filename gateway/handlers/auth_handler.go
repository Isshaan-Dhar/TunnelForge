package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/isshaan-dhar/TunnelForge/auth"
	"github.com/isshaan-dhar/TunnelForge/db"
	"github.com/isshaan-dhar/TunnelForge/metrics"
	redisstore "github.com/isshaan-dhar/TunnelForge/redis"
)

type AuthHandler struct {
	db    *db.Store
	auth  *auth.Manager
	redis *redisstore.Store
}

func NewAuthHandler(store *db.Store, authMgr *auth.Manager, redis *redisstore.Store) *AuthHandler {
	return &AuthHandler{db: store, auth: authMgr, redis: redis}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	ExpiresAt string `json:"expires_at"`
	Role      string `json:"role"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	rateKey := "rate_limit:login:" + clientIP + ":" + req.Username
	redisCtx, redisCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer redisCancel()

	count, err := h.redis.IncrementRateLimit(redisCtx, rateKey, 5*time.Minute)
	if err != nil {
		metrics.AuthFailures.Inc()
		h.db.WriteAuditLog(context.Background(), "", req.Username, "LOGIN", "", clientIP, "ERROR", "rate limiter unreachable")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	} else if count > 10 {
		metrics.AuthFailures.Inc()
		h.db.WriteAuditLog(context.Background(), "", req.Username, "LOGIN", "", clientIP, "DENIED", "rate limit exceeded")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	user, err := h.db.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || !user.IsActive {
		h.auth.VerifyPassword("$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi", req.Password)

		metrics.AuthFailures.Inc()
		metrics.AuthAttempts.WithLabelValues("unknown", "failure").Inc()
		h.db.WriteAuditLog(context.Background(), "", req.Username, "LOGIN", "", clientIP, "FAILURE", "user not found or inactive")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := h.auth.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		metrics.AuthFailures.Inc()
		metrics.AuthAttempts.WithLabelValues(user.Role, "failure").Inc()
		h.db.WriteAuditLog(context.Background(), user.ID, user.Username, "LOGIN", "", clientIP, "FAILURE", "invalid password")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, tokenID, expiresAt, err := h.auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h.db.CreateSession(ctx, user.ID, tokenID, clientIP, expiresAt)
	h.db.UpdateLastLogin(ctx, user.ID)

	metrics.AuthAttempts.WithLabelValues(user.Role, "success").Inc()
	metrics.ActiveSessions.Inc()
	h.db.WriteAuditLog(context.Background(), user.ID, user.Username, "LOGIN", "", clientIP, "SUCCESS", "")

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(loginResponse{
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Role:      user.Role,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl > 0 {
		redisCtx, redisCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer redisCancel()
		h.redis.BlacklistToken(redisCtx, claims.TokenID, ttl)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h.db.RevokeSession(ctx, claims.TokenID)

	metrics.ActiveSessions.Dec()
	h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username, "LOGOUT", "", clientIP, "SUCCESS", "")

	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusNoContent)
}
