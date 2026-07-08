package config

import (
	"log"
	"net/url"
	"os"
)

type Config struct {
	AppPort        string
	MetricsPort    string
	PostgresDSN    string
	RedisAddr      string
	JWTSecret      string
	UpstreamURL    string
	InternalSecret string
	AllowedOrigin  string
}

func Load() *Config {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" || jwtSecret == "changeme-32-char-secret-here!!!" {
		log.Fatal("FATAL: JWT_SECRET must be explicitly set to a secure string in the environment")
	}

	internalSecret := os.Getenv("INTERNAL_SECRET")
	if internalSecret == "" || internalSecret == "super-secret-sidecar-key" {
		log.Fatal("FATAL: INTERNAL_SECRET must be explicitly set to a secure string in the environment")
	}

	pgPass := os.Getenv("POSTGRES_PASSWORD")
	if pgPass == "" || pgPass == "changeme" {
		log.Fatal("FATAL: POSTGRES_PASSWORD must be explicitly set to a secure string in the environment")
	}

	// FIXED: Safely escape credentials to prevent parsing panics on special characters
	pgUser := getEnv("POSTGRES_USER", "tunnelforge")
	pgHost := getEnv("POSTGRES_HOST", "postgres")
	pgPort := getEnv("POSTGRES_PORT", "5432")
	pgDB := getEnv("POSTGRES_DB", "tunnelforge")

	dsn := "postgres://" + url.QueryEscape(pgUser) + ":" + url.QueryEscape(pgPass) + "@" + pgHost + ":" + pgPort + "/" + url.QueryEscape(pgDB) + "?sslmode=disable&pool_max_conns=50"

	return &Config{
		AppPort:        getEnv("GATEWAY_PORT", "8443"),
		MetricsPort:    "9090",
		PostgresDSN:    dsn,
		RedisAddr:      getEnv("REDIS_ADDR", "redis:6379"),
		JWTSecret:      jwtSecret,
		UpstreamURL:    getEnv("UPSTREAM_URL", "http://client-sim:9000"),
		InternalSecret: internalSecret,
		AllowedOrigin:  getEnv("ALLOWED_ORIGIN", "https://tunnelforge.local"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
