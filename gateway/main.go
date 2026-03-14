package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/isshaan-dhar/TunnelForge/auth"
	"github.com/isshaan-dhar/TunnelForge/config"
	"github.com/isshaan-dhar/TunnelForge/db"
	"github.com/isshaan-dhar/TunnelForge/handlers"
	"github.com/isshaan-dhar/TunnelForge/metrics"
	redisstore "github.com/isshaan-dhar/TunnelForge/redis"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg := config.Load()

	store, err := db.New(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}
	defer store.Close()

	redis, err := redisstore.New(cfg.RedisAddr)
	if err != nil {
		log.Fatalf("failed to connect to redis: %v", err)
	}
	defer redis.Close()

	authManager := auth.NewManager(cfg.JWTSecret, redis)
	authHandler := handlers.NewAuthHandler(store, authManager, redis)
	sessionHandler := handlers.NewSessionHandler()
	internalHandler := handlers.NewInternalHandler()

	resourceHandler, err := handlers.NewResourceHandler(cfg.UpstreamURL, store)
	if err != nil {
		log.Fatalf("failed to create resource handler: %v", err)
	}

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		log.Printf("Metrics server starting on :%s", cfg.MetricsPort)
		if err := http.ListenAndServe(":"+cfg.MetricsPort, mux); err != nil {
			log.Fatalf("metrics server error: %v", err)
		}
	}()

	go func() {
		for {
			if count, err := store.CountActiveSessions(context.Background()); err == nil {
				metrics.ActiveSessions.Set(float64(count))
			}
			time.Sleep(15 * time.Second)
		}
	}()

	r := chi.NewRouter()
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, req.ProtoMajor)
			next.ServeHTTP(ww, req)
			metrics.RequestDuration.With(prometheus.Labels{
				"method": req.Method,
				"route":  req.URL.Path,
				"status": strconv.Itoa(ww.Status()),
			}).Observe(time.Since(start).Seconds())
		})
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Post("/auth/login", authHandler.Login)
	r.Post("/internal/anomaly", internalHandler.RecordAnomaly)

	r.Group(func(r chi.Router) {
		r.Use(authManager.Middleware)
		r.Post("/auth/logout", authHandler.Logout)
		r.Get("/session/me", sessionHandler.Me)
		r.Mount("/", resourceHandler)
	})

	log.Printf("TunnelForge gateway starting on :%s", cfg.AppPort)
	if err := http.ListenAndServe(":"+cfg.AppPort, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
