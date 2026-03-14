package handlers

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/isshaan-dhar/TunnelForge/auth"
	"github.com/isshaan-dhar/TunnelForge/db"
	"github.com/isshaan-dhar/TunnelForge/metrics"
	"github.com/isshaan-dhar/TunnelForge/policy"
)

type ResourceHandler struct {
	proxy *httputil.ReverseProxy
	db    *db.Store
}

func NewResourceHandler(upstream string, store *db.Store) (*ResourceHandler, error) {
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	return &ResourceHandler{
		proxy: httputil.NewSingleHostReverseProxy(target),
		db:    store,
	}, nil
}

func (h *ResourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	p, err := h.db.GetPolicyByRole(r.Context(), claims.Role)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result := policy.Evaluate(p, r.URL.Path, time.Now())
	if !result.Allowed {
		metrics.PolicyDenials.WithLabelValues(string(result.Reason)).Inc()
		go h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username,
			"ACCESS", r.URL.Path, clientIP, "DENIED", string(result.Reason))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	go h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username,
		"ACCESS", r.URL.Path, clientIP, "ALLOWED", "")
	h.proxy.ServeHTTP(w, r)
}
