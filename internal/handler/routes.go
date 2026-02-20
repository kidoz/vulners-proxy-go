package handler

import (
	"github.com/labstack/echo/v4"
)

// RegisterRoutes wires all route handlers onto the Echo instance.
func RegisterRoutes(e *echo.Echo, proxy *ProxyHandler, health *HealthHandler) {
	e.GET("/healthz", health.Healthz)
	e.GET("/proxy/status", health.Status)

	e.Any("/api/v3/*", proxy.Handle)
	e.Any("/api/v4/*", proxy.Handle)
}
