package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestRequestLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e := echo.New()
	e.Use(RequestLogger(logger))
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(buf.String(), "request") {
		t.Errorf("expected log output for /test, got %q", buf.String())
	}
}

func TestRequestLogger_HealthzAtDebugLevel(t *testing.T) {
	// With Info level, /healthz should NOT appear in output (it logs at Debug).
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	e := echo.New()
	e.Use(RequestLogger(logger))
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no log output at Info level for /healthz, got %q", buf.String())
	}
}

func TestRequestLogger_HealthzVisibleAtDebugLevel(t *testing.T) {
	// With Debug level, /healthz SHOULD appear in output.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := echo.New()
	e.Use(RequestLogger(logger))
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if !strings.Contains(buf.String(), "request") {
		t.Errorf("expected log output at Debug level for /healthz, got %q", buf.String())
	}
}
