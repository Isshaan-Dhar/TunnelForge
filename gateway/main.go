package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
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
	internalHandler := handlers.NewInternalHandler(cfg.InternalSecret, store)

	resourceHandler, err := handlers.NewResourceHandler(cfg.UpstreamURL, store)
	if err != nil {
		log.Fatalf("failed to create resource handler: %v", err)
	}

	metricsSrv := &http.Server{
		Addr:              ":" + cfg.MetricsPort,
		Handler:           promhttp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("Metrics server starting on :%s", cfg.MetricsPort)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(chimiddleware.Timeout(30 * time.Second))

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			next.ServeHTTP(w, req)
		})
	})

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
	r.Post("/internal/bootstrap", internalHandler.BootstrapAdmin)

	r.Group(func(r chi.Router) {
		r.Use(authManager.Middleware)
		r.Post("/auth/logout", authHandler.Logout)
		r.Get("/session/me", sessionHandler.Me)
		r.Mount("/", resourceHandler)
	})

	srv := &http.Server{
		Addr:              ":" + cfg.AppPort,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("TunnelForge gateway starting on :%s", cfg.AppPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Initiating graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := metricsSrv.Shutdown(ctx); err != nil {
		log.Printf("Metrics server forced to shutdown: %v", err)
	}

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Gateway server forced to shutdown: %v", err)
	}

	log.Println("Server exiting successfully")
}
