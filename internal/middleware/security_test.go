package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestSecurityHeaders_AddsHeaders(t *testing.T) {
	e := echo.New()
	e.Use(SecurityHeaders())
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if v := rec.Header().Get("X-Content-Type-Options"); v != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", v, "nosniff")
	}
	if v := rec.Header().Get("X-Frame-Options"); v != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", v, "DENY")
	}
}

func TestSecurityHeaders_StripsHopByHop(t *testing.T) {
	e := echo.New()
	e.Use(SecurityHeaders())

	var gotConnection string
	e.GET("/test", func(c echo.Context) error {
		gotConnection = c.Request().Header.Get("Connection")
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if gotConnection != "" {
		t.Errorf("Connection header should be stripped, got %q", gotConnection)
	}
}
