package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/isshaan-dhar/TunnelForge/db"
	"github.com/isshaan-dhar/TunnelForge/metrics"
)

type InternalHandler struct {
	secret string
	db     *db.Store
}

func NewInternalHandler(secret string, store *db.Store) *InternalHandler {
	return &InternalHandler{secret: secret, db: store}
}

type anomalyNotification struct {
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
}

type bootstrapRequest struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
}

func (h *InternalHandler) RecordAnomaly(w http.ResponseWriter, r *http.Request) {
	headerSecret := r.Header.Get("X-Internal-Secret")

	if subtle.ConstantTimeCompare([]byte(headerSecret), []byte(h.secret)) != 1 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

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

	if subtle.ConstantTimeCompare([]byte(headerSecret), []byte(h.secret)) != 1 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req bootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.db.CreateUser(ctx, req.Username, req.PasswordHash, req.Role); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
