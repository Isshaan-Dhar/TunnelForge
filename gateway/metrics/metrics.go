package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tunnelforge_active_sessions",
		Help: "Current number of active VPN sessions",
	})

	AuthAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_auth_attempts_total",
		Help: "Total authentication attempts",
	}, []string{"role", "status"})

	AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tunnelforge_auth_failures_total",
		Help: "Total failed authentication attempts",
	})

	PolicyDenials = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_policy_denials_total",
		Help: "Total zero-trust policy denials",
	}, []string{"reason"})

	AnomaliesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_anomalies_detected_total",
		Help: "Total behavioral anomalies detected by sidecar",
	}, []string{"anomaly_type", "severity"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tunnelforge_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})
)
