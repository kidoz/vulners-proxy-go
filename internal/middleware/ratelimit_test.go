package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
)

func TestRateLimiter_Enabled(t *testing.T) {
	e := echo.New()

	// 1 request per second, burst of 1 — second request should be rejected.
	store := echomw.NewRateLimiterMemoryStore(rate.Limit(1))
	e.Use(echomw.RateLimiter(store))
	e.GET("/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// First request should succeed.
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Subsequent requests should be rate-limited (429).
	got429 := false
	for range 10 {
		req = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		rec = httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected at least one 429 response after burst, got none")
	}
}
