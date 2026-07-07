package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resource":"api","data":"hello"}`)
	})

	mux.HandleFunc("/api/readonly", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resource":"api/readonly","data":"read-only data"}`)
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"resource":"admin","data":"admin panel"}`)
	})
	srv := &http.Server{
		Addr:              ":9000",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("client-sim starting on :9000")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
