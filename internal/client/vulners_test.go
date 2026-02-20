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
	c := NewVulnersClient(cfg, logger)

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

func TestVulnersClient_DoStream_Error(t *testing.T) {
	cfg := &config.Config{
		Upstream: config.UpstreamConfig{
			TimeoutSeconds:  1,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewVulnersClient(cfg, logger)

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
	c := NewVulnersClient(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.DoStream(ctx, http.MethodGet, srv.URL+"/slow", http.Header{}, nil)
	if err == nil {
		t.Fatal("DoStream() expected error for canceled context, got nil")
	}
}
