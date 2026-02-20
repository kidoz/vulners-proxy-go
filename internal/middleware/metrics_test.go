package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/metrics"
)

func TestMetricsMiddleware_IncrementsCounter(t *testing.T) {
	m := metrics.New()

	e := echo.New()
	e.Use(MetricsMiddleware(m))
	e.GET("/api/v3/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v3/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	found := false
	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_requests_total" {
			for _, metric := range f.GetMetric() {
				for _, lp := range metric.GetLabel() {
					if lp.GetName() == "path_prefix" && lp.GetValue() == "/api/v3" {
						found = true
						if v := metric.GetCounter().GetValue(); v != 1 {
							t.Errorf("counter value = %v, want 1", v)
						}
					}
				}
			}
		}
	}
	if !found {
		t.Error("expected vulners_proxy_http_requests_total with path_prefix=/api/v3")
	}
}

func TestMetricsMiddleware_RecordsDuration(t *testing.T) {
	m := metrics.New()

	e := echo.New()
	e.Use(MetricsMiddleware(m))
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	found := false
	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_request_duration_seconds" {
			for _, metric := range f.GetMetric() {
				if metric.GetHistogram().GetSampleCount() > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected vulners_proxy_http_request_duration_seconds with at least one sample")
	}
}

func TestMetricsMiddleware_HTTPErrorStatus(t *testing.T) {
	m := metrics.New()

	e := echo.New()
	e.Use(MetricsMiddleware(m))
	e.GET("/api/v3/test", func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound, "not found")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v3/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_requests_total" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["path_prefix"] == "/api/v3" {
					if labels["status_code"] != "404" {
						t.Errorf("status_code = %q, want %q", labels["status_code"], "404")
					}
					return
				}
			}
		}
	}
	t.Error("expected vulners_proxy_http_requests_total with path_prefix=/api/v3")
}

func TestMetricsMiddleware_UnknownMethodNormalized(t *testing.T) {
	m := metrics.New()

	e := echo.New()
	e.Use(MetricsMiddleware(m))
	// Echo router returns 405 for unregistered methods; register a route so
	// the middleware runs for the path but use a non-standard method via Any.
	e.Any("/api/v3/test", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest("XYZZY", "/api/v3/test", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_requests_total" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["path_prefix"] == "/api/v3" {
					if labels["method"] != "other" {
						t.Errorf("method = %q, want %q", labels["method"], "other")
					}
					return
				}
			}
		}
	}
	t.Error("expected vulners_proxy_http_requests_total with path_prefix=/api/v3 and method=other")
}

func TestMetricsMiddleware_RouterNotFound(t *testing.T) {
	m := metrics.New()

	e := echo.New()
	e.Use(MetricsMiddleware(m))
	// No routes registered; request should yield 404.

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", http.NoBody)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_requests_total" {
			for _, metric := range f.GetMetric() {
				labels := make(map[string]string)
				for _, lp := range metric.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				if labels["path_prefix"] == "other" && labels["method"] == "GET" {
					if labels["status_code"] != "404" {
						t.Errorf("status_code = %q, want %q", labels["status_code"], "404")
					}
					return
				}
			}
		}
	}
	t.Error("expected vulners_proxy_http_requests_total with path_prefix=other, method=GET, status_code=404")
}
