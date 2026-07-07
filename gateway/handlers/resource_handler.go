package handlers

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
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

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	cleanPath := path.Clean(r.URL.Path)
	r.URL.Path = cleanPath
	r.URL.RawPath = ""

	p, err := h.db.GetPolicyByRole(r.Context(), claims.Role)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result := policy.Evaluate(p, cleanPath, time.Now())
	if !result.Allowed {
		metrics.PolicyDenials.WithLabelValues(string(result.Reason)).Inc()
		h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username,
			"ACCESS", cleanPath, clientIP, "DENIED", string(result.Reason))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	h.db.WriteAuditLog(context.Background(), claims.UserID, claims.Username,
		"ACCESS", cleanPath, clientIP, "ALLOWED", "")
	h.proxy.ServeHTTP(w, r)
}
