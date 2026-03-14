package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Role      string `json:"role"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByUsername(r.Context(), req.Username)
	if err != nil || user == nil || !user.IsActive {
		metrics.AuthFailures.Inc()
		metrics.AuthAttempts.WithLabelValues("unknown", "failure").Inc()
		go h.db.WriteAuditLog(context.Background(), "", req.Username, "LOGIN", "", clientIP, "FAILURE", "user not found or inactive")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := h.auth.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		metrics.AuthFailures.Inc()
		metrics.AuthAttempts.WithLabelValues(user.Role, "failure").Inc()
		go h.db.WriteAuditLog(context.Background(), user.ID, user.Username, "LOGIN", "", clientIP, "FAILURE", "invalid password")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, tokenID, expiresAt, err := h.auth.GenerateToken(user.ID, user.Username, user.Role)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	go h.db.CreateSession(context.Background(), user.ID, tokenID, clientIP, expiresAt)
	go h.db.UpdateLastLogin(context.Background(), user.ID)
	metrics.AuthAttempts.WithLabelValues(user.Role, "success").Inc()
	metrics.ActiveSessions.Inc()
	go h.db.WriteAuditLog(context.Background(), user.ID, user.Username, "LOGIN", "", clientIP, "SUCCESS", "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(loginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Role:      user.Role,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	go h.redis.BlacklistToken(context.Background(), claims.TokenID, ttl)
	go h.db.RevokeSession(context.Background(), claims.TokenID)
	metrics.ActiveSessions.Dec()
	go h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username, "LOGOUT", "", clientIP, "SUCCESS", "")

	w.WriteHeader(http.StatusNoContent)
}
