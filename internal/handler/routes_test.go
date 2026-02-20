package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/client"
	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/service"
)

func TestRegisterRoutes_Wiring(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
	svc, err := service.NewProxyServiceForTest(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyServiceForTest: %v", err)
	}

	proxy := NewProxyHandler(svc, logger)
	health := NewHealthHandler(cfg, "test")

	e := echo.New()
	RegisterRoutes(e, proxy, health)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"GET /healthz", http.MethodGet, "/healthz", http.StatusOK},
		{"GET /proxy/status", http.MethodGet, "/proxy/status", http.StatusOK},
		{"GET /api/v3/search/lucene/", http.MethodGet, "/api/v3/search/lucene/?query=test", http.StatusOK},
		{"POST /api/v3/search/lucene/", http.MethodPost, "/api/v3/search/lucene/", http.StatusOK},
		{"GET /api/v4/search/lucene/", http.MethodGet, "/api/v4/search/lucene/?query=test", http.StatusOK},
		{"GET /unknown returns 404/405", http.MethodGet, "/unknown", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, http.NoBody)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
