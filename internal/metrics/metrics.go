// Package metrics provides Prometheus metrics for the proxy.
package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Default histogram buckets for API latency.
var defaultBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// Metrics holds all Prometheus metric collectors for the proxy.
type Metrics struct {
	Registry *prometheus.Registry

	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestsInFlight prometheus.Gauge

	UpstreamDuration  *prometheus.HistogramVec
	UpstreamResponses *prometheus.CounterVec
}

// New creates a Metrics instance with a custom registry and all collectors registered.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		Registry: reg,

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulners_proxy_http_requests_total",
			Help: "Total inbound HTTP requests.",
		}, []string{"method", "status_code", "path_prefix"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "vulners_proxy_http_request_duration_seconds",
			Help:    "Inbound HTTP request latency in seconds.",
			Buckets: defaultBuckets,
		}, []string{"method", "status_code", "path_prefix"}),

		RequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vulners_proxy_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed.",
		}),

		UpstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "vulners_proxy_upstream_request_duration_seconds",
			Help:    "Upstream call latency in seconds.",
			Buckets: defaultBuckets,
		}, []string{"method"}),

		UpstreamResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vulners_proxy_upstream_responses_total",
			Help: "Total upstream responses by method and status code.",
		}, []string{"method", "status_code"}),
	}

	reg.MustRegister(
		m.RequestsTotal,
		m.RequestDuration,
		m.RequestsInFlight,
		m.UpstreamDuration,
		m.UpstreamResponses,
	)

	return m
}

// knownMethods lists the allowed HTTP method label values (bounded cardinality).
var knownMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// NormalizeMethod returns a bounded HTTP method label for Prometheus metrics.
// Non-standard methods are mapped to "other" to prevent cardinality explosion.
func NormalizeMethod(method string) string {
	if knownMethods[method] {
		return method
	}
	return "other"
}

// knownPrefixes lists the allowed path label values (bounded cardinality).
var knownPrefixes = []string{"/api/v3", "/api/v4", "/healthz", "/proxy/status", "/metrics"}

// NormalizePath returns a bounded path label for Prometheus metrics.
func NormalizePath(path string) string {
	for _, prefix := range knownPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+"?") {
			return prefix
		}
	}
	return "other"
}
