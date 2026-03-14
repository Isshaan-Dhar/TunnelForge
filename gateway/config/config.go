package config

import "os"

type Config struct {
	AppPort     string
	MetricsPort string
	PostgresDSN string
	RedisAddr   string
	JWTSecret   string
	UpstreamURL string
}

func Load() *Config {
	return &Config{
		AppPort:     getEnv("GATEWAY_PORT", "8443"),
		MetricsPort: "9090",
		PostgresDSN: "postgres://" + getEnv("POSTGRES_USER", "tunnelforge") + ":" + getEnv("POSTGRES_PASSWORD", "changeme") + "@" + getEnv("POSTGRES_HOST", "postgres") + ":" + getEnv("POSTGRES_PORT", "5432") + "/" + getEnv("POSTGRES_DB", "tunnelforge") + "?sslmode=disable",
		RedisAddr:   getEnv("REDIS_ADDR", "redis:6379"),
		JWTSecret:   getEnv("JWT_SECRET", "changeme-32-char-secret-here!!!"),
		UpstreamURL: "http://client-sim:9000",
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
