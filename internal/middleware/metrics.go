package middleware

import (
	"errors"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/metrics"
)

// MetricsMiddleware returns an Echo middleware that records Prometheus metrics
// for each inbound request.
func MetricsMiddleware(m *metrics.Metrics) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			m.RequestsInFlight.Inc()
			defer m.RequestsInFlight.Dec()

			start := time.Now()

			err := next(c)

			// Resolve the actual status code. When a handler returns an
			// *echo.HTTPError, the response status hasn't been written yet;
			// Echo's central error handler will do that later. We inspect
			// the error to get the correct code for metrics.
			statusCode := c.Response().Status
			if err != nil {
				var he *echo.HTTPError
				if errors.As(err, &he) {
					statusCode = he.Code
				}
			}

			status := strconv.Itoa(statusCode)
			method := metrics.NormalizeMethod(c.Request().Method)
			path := metrics.NormalizePath(c.Request().URL.Path)
			duration := time.Since(start).Seconds()

			m.RequestsTotal.WithLabelValues(method, status, path).Inc()
			m.RequestDuration.WithLabelValues(method, status, path).Observe(duration)

			return err
		}
	}
}
