package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "tunnelforge_active_sessions",
		Help: "Current number of active sessions",
	})

	AuthAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_auth_attempts_total",
		Help: "Total number of authentication attempts",
	}, []string{"role", "status"})

	AuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tunnelforge_auth_failures_total",
		Help: "Total number of failed authentications",
	})

	PolicyDenials = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_policy_denials_total",
		Help: "Total number of access denied by policy",
	}, []string{"reason"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tunnelforge_request_duration_seconds",
		Help:    "Duration of HTTP requests",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})

	AnomaliesDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelforge_anomalies_detected_total",
		Help: "Total number of anomalies detected by the sidecar",
	}, []string{"anomaly_type", "severity"})

	AuditQueueDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tunnelforge_audit_queue_drops_total",
		Help: "Total number of audit logs dropped because the asynchronous queue was full",
	})
)
