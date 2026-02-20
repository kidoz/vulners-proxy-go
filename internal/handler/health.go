package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/config"
)

// Version is a string type for dependency injection of the build version.
type Version string

// HealthHandler serves health and status endpoints.
type HealthHandler struct {
	cfg     *config.Config
	version Version
}

// NewHealthHandler creates a HealthHandler.
func NewHealthHandler(cfg *config.Config, v Version) *HealthHandler {
	return &HealthHandler{cfg: cfg, version: v}
}

// Healthz returns a simple OK response for liveness probes.
func (h *HealthHandler) Healthz(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// Status returns proxy status information.
func (h *HealthHandler) Status(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"status":       "ok",
		"version":      string(h.version),
		"upstream_url": h.cfg.Upstream.BaseURL,
	})
}
