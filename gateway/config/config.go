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
	jwtSecret := getEnv("JWT_SECRET", "")
	if len(jwtSecret) < 32 {
		log.Fatal("FATAL: JWT_SECRET environment variable is missing or less than 32 characters. Refusing to start.")
	}

	internalSecret := getEnv("INTERNAL_SECRET", "")
	if len(internalSecret) < 32 {
		log.Fatal("FATAL: INTERNAL_SECRET environment variable is missing or less than 32 characters. Refusing to start.")
	}

	return &Config{
		AppPort:        getEnv("GATEWAY_PORT", "8443"),
		MetricsPort:    "9090",
		PostgresDSN:    "postgres://" + getEnv("POSTGRES_USER", "tunnelforge") + ":" + getEnv("POSTGRES_PASSWORD", "changeme") + "@" + getEnv("POSTGRES_HOST", "postgres") + ":" + getEnv("POSTGRES_PORT", "5432") + "/" + getEnv("POSTGRES_DB", "tunnelforge") + "?sslmode=disable",
		RedisAddr:      getEnv("REDIS_ADDR", "redis:6379"),
		JWTSecret:      jwtSecret,
		UpstreamURL:    "http://client-sim:9000",
		InternalSecret: internalSecret,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
