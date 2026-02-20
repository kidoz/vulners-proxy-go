package client

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/metrics"
)

func TestVulnersClient_DoStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewVulnersClient(cfg, logger, nil)

	resp, err := c.DoStream(context.Background(), http.MethodGet, srv.URL+"/test", http.Header{}, nil)
	if err != nil {
		t.Fatalf("DoStream() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != `{"status":"ok"}` {
		t.Errorf("body = %q, want %q", string(body), `{"status":"ok"}`)
	}
}

func TestVulnersClient_DoStream_WithMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	c := NewVulnersClient(cfg, logger, m)

	resp, err := c.DoStream(context.Background(), http.MethodGet, srv.URL+"/test", http.Header{}, nil)
	if err != nil {
		t.Fatalf("DoStream() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify upstream metrics were recorded.
	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	var foundDuration, foundResponses bool
	for _, f := range families {
		switch f.GetName() {
		case "vulners_proxy_upstream_request_duration_seconds":
			for _, metric := range f.GetMetric() {
				if metric.GetHistogram().GetSampleCount() > 0 {
					foundDuration = true
				}
			}
		case "vulners_proxy_upstream_responses_total":
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["method"] == "GET" && labels["status_code"] == "200" {
					foundResponses = true
					if v := metric.GetCounter().GetValue(); v != 1 {
						t.Errorf("upstream_responses_total counter = %v, want 1", v)
					}
				}
			}
		}
	}
	if !foundDuration {
		t.Error("expected upstream_request_duration_seconds with at least one sample")
	}
	if !foundResponses {
		t.Error("expected upstream_responses_total with method=GET, status_code=200")
	}
}

func TestVulnersClient_DoStream_ErrorWithMetrics(t *testing.T) {
	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  1,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.New()
	c := NewVulnersClient(cfg, logger, m)

	_, err := c.DoStream(context.Background(), http.MethodGet, "http://127.0.0.1:1/nonexistent", http.Header{}, nil)
	if err == nil {
		t.Fatal("DoStream() expected error for unreachable host, got nil")
	}

	// Verify duration was still recorded on error.
	families, gatherErr := m.Registry.Gather()
	if gatherErr != nil {
		t.Fatalf("Gather() error = %v", gatherErr)
	}

	found := false
	for _, f := range families {
		if f.GetName() == "vulners_proxy_upstream_request_duration_seconds" {
			for _, metric := range f.GetMetric() {
				if metric.GetHistogram().GetSampleCount() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected upstream_request_duration_seconds recorded even on error")
	}
}

func TestVulnersClient_DoStream_Error(t *testing.T) {
	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  1,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewVulnersClient(cfg, logger, nil)

	_, err := c.DoStream(context.Background(), http.MethodGet, "http://127.0.0.1:1/nonexistent", http.Header{}, nil)
	if err == nil {
		t.Fatal("DoStream() expected error for unreachable host, got nil")
	}
}

func TestVulnersClient_DoStream_CanceledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a slow upstream; the request should be canceled before this completes.
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  30,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewVulnersClient(cfg, logger, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.DoStream(ctx, http.MethodGet, srv.URL+"/slow", http.Header{}, nil)
	if err == nil {
		t.Fatal("DoStream() expected error for canceled context, got nil")
	}
}
