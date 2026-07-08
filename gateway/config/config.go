package config

import (
	"log"
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

	return &Config{
		AppPort:        getEnv("GATEWAY_PORT", "8443"),
		MetricsPort:    "9090",
		PostgresDSN:    "postgres://" + getEnv("POSTGRES_USER", "tunnelforge") + ":" + pgPass + "@" + getEnv("POSTGRES_HOST", "postgres") + ":" + getEnv("POSTGRES_PORT", "5432") + "/" + getEnv("POSTGRES_DB", "tunnelforge") + "?sslmode=disable&pool_max_conns=50",
		RedisAddr:      getEnv("REDIS_ADDR", "redis:6379"),
		JWTSecret:      jwtSecret,
		UpstreamURL:    getEnv("UPSTREAM_URL", "http://client-sim:9000"),
		InternalSecret: internalSecret,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
