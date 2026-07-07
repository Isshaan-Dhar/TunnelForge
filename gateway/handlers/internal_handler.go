package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/isshaan-dhar/TunnelForge/metrics"
)

type InternalHandler struct {
	secret string
}

func NewInternalHandler(secret string) *InternalHandler {
	return &InternalHandler{secret: secret}
}

type anomalyNotification struct {
	AnomalyType string `json:"anomaly_type"`
	Severity    string `json:"severity"`
}

func (h *InternalHandler) RecordAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Internal-Secret") != h.secret {
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
