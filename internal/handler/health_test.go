package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/config"
)

func TestHealthz(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthHandler(&config.Config{}, "test")
	if err := h.Healthz(c); err != nil {
		t.Fatalf("Healthz() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestStatus(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/proxy/status", http.NoBody)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := &config.Config{
		Upstream: config.UpstreamConfig{BaseURL: "https://vulners.com"},
	}
	h := NewHealthHandler(cfg, "1.2.3")
	if err := h.Status(c); err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body.status = %q, want %q", body["status"], "ok")
	}
	if body["version"] != "1.2.3" {
		t.Errorf("body.version = %q, want %q", body["version"], "1.2.3")
	}
	if body["upstream_url"] != "https://vulners.com" {
		t.Errorf("body.upstream_url = %q, want %q", body["upstream_url"], "https://vulners.com")
	}
}
