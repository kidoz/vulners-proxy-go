package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/client"
	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/service"
)

func TestProxyHandler_Handle_ConfigAPIKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apiKey") != "config-key" {
			t.Errorf("apiKey = %q, want %q", r.URL.Query().Get("apiKey"), "config-key")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: "config-key"},
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger)
	svc, err := newTestProxyService(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	h := NewProxyHandler(svc, logger)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/?query=test", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["result"] != "ok" {
		t.Errorf("body.result = %q, want %q", body["result"], "ok")
	}
}

func TestProxyHandler_Handle_HeaderAPIKey(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("apiKey") != "header-key" {
			t.Errorf("apiKey = %q, want %q", r.URL.Query().Get("apiKey"), "header-key")
		}
		// X-Api-Key should NOT be forwarded as a header
		if r.Header.Get("X-Api-Key") != "" {
			t.Errorf("X-Api-Key header should not be forwarded upstream")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: ""}, // no config key
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger)
	svc, err := newTestProxyService(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	h := NewProxyHandler(svc, logger)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/?query=test", http.NoBody)
	req.Header.Set("X-Api-Key", "header-key")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestProxyHandler_Handle_MissingAPIKey(t *testing.T) {
	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: ""}, // no config key
		Upstream: config.UpstreamConfig{
			BaseURL:         "https://vulners.com",
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger)
	svc, err := newTestProxyService(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	h := NewProxyHandler(svc, logger)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/", http.NoBody)
	// No X-Api-Key header, no config key
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error"] == "" {
		t.Error("expected non-empty error message in response")
	}
}

func TestProxyHandler_Handle_POST(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":"` + string(body) + `"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger)
	svc, err := newTestProxyService(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	h := NewProxyHandler(svc, logger)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v3/search/lucene/", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestProxyHandler_Handle_CanceledContext(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait until client context is done.
		<-r.Context().Done()
		// Do not write a response — the client has disconnected.
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  30,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger)
	svc, err := newTestProxyService(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService: %v", err)
	}
	h := NewProxyHandler(svc, logger)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/?query=test", http.NoBody)
	// Create a pre-canceled context to simulate client disconnect.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Handle(c); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	// Should get a 502/504 error response, not 200.
	if rec.Code == http.StatusOK {
		t.Error("expected non-200 status for canceled context")
	}
}

func TestProxyHandler_mapError_DNSError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &ProxyHandler{logger: logger}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	dnsErr := &net.DNSError{Err: "no such host", Name: "vulners.com"}
	wrapped := fmt.Errorf("forward to upstream: %w", dnsErr)

	if err := h.mapError(c, wrapped); err != nil {
		t.Fatalf("mapError() returned error: %v", err)
	}

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error"] != "upstream host unreachable" {
		t.Errorf("error = %q, want %q", body["error"], "upstream host unreachable")
	}
}

func TestProxyHandler_mapError_URLError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &ProxyHandler{logger: logger}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v3/search/lucene/", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	urlErr := &url.Error{Op: "Get", URL: "https://vulners.com/api", Err: fmt.Errorf("connection refused")}
	wrapped := fmt.Errorf("forward to upstream: %w", urlErr)

	if err := h.mapError(c, wrapped); err != nil {
		t.Fatalf("mapError() returned error: %v", err)
	}

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error"] != "upstream connection failed" {
		t.Errorf("error = %q, want %q", body["error"], "upstream connection failed")
	}
}

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want string
	}{
		{
			name: "redacts apiKey in URL",
			err:  `Get "https://vulners.com/api/v3/search?apiKey=secret123&query=test": connection refused`,
			want: `Get "https://vulners.com/api/v3/search?apiKey=[REDACTED]&query=test": connection refused`,
		},
		{
			name: "redacts apiKey at end of URL",
			err:  `Get "https://vulners.com/api/v3/search?apiKey=secret123": EOF`,
			want: `Get "https://vulners.com/api/v3/search?apiKey=[REDACTED]": EOF`,
		},
		{
			name: "no apiKey unchanged",
			err:  "connection refused",
			want: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeError(fmt.Errorf("%s", tt.err))
			if got != tt.want {
				t.Errorf("sanitizeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

// newTestProxyService creates a ProxyService that accepts any upstream host (for httptest).
func newTestProxyService(c *client.VulnersClient, cfg *config.Config, logger *slog.Logger) (*service.ProxyService, error) {
	return service.NewProxyServiceForTest(c, cfg, logger)
}
