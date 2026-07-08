package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/isshaan-dhar/TunnelForge/auth"
	"github.com/isshaan-dhar/TunnelForge/db"
	"github.com/isshaan-dhar/TunnelForge/metrics"
)

type InternalHandler struct {
	secret string
	db     *db.Store
	auth   *auth.Manager
}

func NewInternalHandler(secret string, store *db.Store, authMgr *auth.Manager) *InternalHandler {
	return &InternalHandler{secret: secret, db: store, auth: authMgr}
}

type anomalyNotification struct {
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
}

type bootstrapRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// FIXED: Protect against length timing attacks by comparing SHA256 hashes instead of raw lengths
func secureCompare(given, actual string) bool {
	hash1 := sha256.Sum256([]byte(given))
	hash2 := sha256.Sum256([]byte(actual))
	return subtle.ConstantTimeCompare(hash1[:], hash2[:]) == 1
}

func (h *InternalHandler) RecordAnomaly(w http.ResponseWriter, r *http.Request) {
	headerSecret := r.Header.Get("X-Internal-Secret")

	if !secureCompare(headerSecret, h.secret) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var n anomalyNotification
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	metrics.AnomaliesDetected.WithLabelValues(n.AnomalyType, n.Severity).Inc()
	w.WriteHeader(http.StatusNoContent)
}

func (h *InternalHandler) BootstrapAdmin(w http.ResponseWriter, r *http.Request) {
	headerSecret := r.Header.Get("X-Internal-Secret")

	if !secureCompare(headerSecret, h.secret) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	var req bootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, err := h.db.CountUsers(ctx)
	if err != nil || count > 0 {
		http.Error(w, "bootstrap locked: users already exist", http.StatusConflict)
		return
	}

	role := req.Role
	if role == "" {
		role = "admin"
	}

	hash, err := h.auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.db.CreateUser(ctx, req.Username, hash, role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
