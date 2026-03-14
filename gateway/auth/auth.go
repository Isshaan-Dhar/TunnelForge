package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	redisstore "github.com/isshaan-dhar/TunnelForge/redis"
)

type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TokenID  string `json:"token_id"`
	jwt.RegisteredClaims
}

type Manager struct {
	secret []byte
	redis  *redisstore.Store
}

type contextKey string

const ClaimsKey contextKey = "claims"

func NewManager(secret string, redis *redisstore.Store) *Manager {
	return &Manager{secret: []byte(secret), redis: redis}
}

func (m *Manager) VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (m *Manager) GenerateToken(userID, username, role string) (string, string, time.Time, error) {
	tokenID := fmt.Sprintf("%s:%s:%d", userID, username, time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		TokenID:  tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	return signed, tokenID, expiresAt, err
}

func (m *Manager) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		claims, err := m.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		blacklisted, err := m.redis.IsTokenBlacklisted(r.Context(), claims.TokenID)
		if err != nil || blacklisted {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaims(r *http.Request) *Claims {
	c, _ := r.Context().Value(ClaimsKey).(*Claims)
	return c
}
