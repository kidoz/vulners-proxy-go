// Package middleware provides Echo middleware for logging and security.
package middleware

import (
	"log/slog"
	"time"

	"github.com/labstack/echo/v4"
)

// RequestLogger returns an Echo middleware that logs each request with slog.
func RequestLogger(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			err := next(c)

			req := c.Request()
			res := c.Response()

			logger.Info("request",
				"method", req.Method,
				"path", req.URL.Path,
				"status", res.Status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", res.Header().Get(echo.HeaderXRequestID),
				"remote_ip", c.RealIP(),
				"bytes_out", res.Size,
			)

			return err
		}
	}
}
