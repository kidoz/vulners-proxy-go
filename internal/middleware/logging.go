// Package middleware provides Echo middleware for logging and security.
package middleware

import (
	"log/slog"
	"time"

	"github.com/labstack/echo/v4"
)

// healthPaths are paths logged at Debug level to reduce noise from frequent
// liveness/readiness probes.
var healthPaths = map[string]bool{
	"/healthz":      true,
	"/proxy/status": true,
}

// RequestLogger returns an Echo middleware that logs each request with slog.
// Health-check paths are logged at Debug level; all other paths at Info.
func RequestLogger(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			err := next(c)

			req := c.Request()
			res := c.Response()

			attrs := []any{
				"method", req.Method,
				"path", req.URL.Path,
				"status", res.Status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", res.Header().Get(echo.HeaderXRequestID),
				"remote_ip", c.RealIP(),
				"bytes_out", res.Size,
			}

			if healthPaths[req.URL.Path] {
				logger.Debug("request", attrs...)
			} else {
				logger.Info("request", attrs...)
			}

			return err
		}
	}
}
