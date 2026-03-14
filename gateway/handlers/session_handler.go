package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/isshaan-dhar/TunnelForge/auth"
)

type SessionHandler struct{}

func NewSessionHandler() *SessionHandler {
	return &SessionHandler{}
}

type sessionResponse struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TokenID  string `json:"token_id"`
	Valid    bool   `json:"valid"`
}

func (h *SessionHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessionResponse{
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
		TokenID:  claims.TokenID,
		Valid:    true,
	})
}
