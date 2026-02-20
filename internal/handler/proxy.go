package handler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/labstack/echo/v4"

	"vulners-proxy-go/internal/model"
	"vulners-proxy-go/internal/service"
)

// apiKeyPattern matches apiKey query parameter values in URLs embedded in error messages.
var apiKeyPattern = regexp.MustCompile(`(?i)(apiKey=)[^&\s"]+`)

// ProxyHandler forwards API requests to the upstream Vulners API.
type ProxyHandler struct {
	service *service.ProxyService
	logger  *slog.Logger
}

// NewProxyHandler creates a ProxyHandler.
func NewProxyHandler(svc *service.ProxyService, logger *slog.Logger) *ProxyHandler {
	return &ProxyHandler{
		service: svc,
		logger:  logger.With("component", "proxy_handler"),
	}
}

// Handle proxies the request to the upstream Vulners API and streams the response back.
func (h *ProxyHandler) Handle(c echo.Context) error {
	req := c.Request()

	pr := &model.ProxyRequest{
		Ctx:    req.Context(),
		Method: req.Method,
		Path:   req.URL.Path,
		Query:  req.URL.Query(),
		Header: req.Header,
		Body:   req.Body,
	}

	resp, err := h.service.Forward(pr)
	if err != nil {
		return h.mapError(c, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy filtered response headers
	for key, vals := range resp.Header {
		for _, v := range vals {
			c.Response().Header().Add(key, v)
		}
	}

	c.Response().WriteHeader(resp.StatusCode)

	// Stream the upstream body directly to the client. If io.Copy fails
	// mid-stream (e.g. client disconnect, network error), the HTTP status
	// code has already been sent, so the client receives a truncated
	// response with the original status. This is an inherent trade-off of
	// streaming proxies — we log the error for observability.
	if _, err := io.Copy(c.Response(), resp.Body); err != nil {
		h.logger.Error("streaming response body",
			"err", err,
			"path", req.URL.Path,
		)
	}

	return nil
}

func (h *ProxyHandler) mapError(c echo.Context, err error) error {
	h.logger.Error("proxy error",
		"err", sanitizeError(err),
		"path", c.Request().URL.Path,
	)

	if errors.Is(err, service.ErrMissingAPIKey) {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "API key required: set api_key in config or send X-Api-Key header",
		})
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return c.JSON(http.StatusGatewayTimeout, map[string]string{
			"error": "upstream request timed out",
		})
	}

	if errors.Is(err, context.Canceled) {
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": "client disconnected",
		})
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": "upstream host unreachable",
		})
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return c.JSON(http.StatusBadGateway, map[string]string{
			"error": "upstream connection failed",
		})
	}

	return c.JSON(http.StatusBadGateway, map[string]string{
		"error": "upstream request failed",
	})
}

// sanitizeError redacts API keys from error messages that may contain upstream URLs.
func sanitizeError(err error) string {
	return apiKeyPattern.ReplaceAllString(err.Error(), "${1}[REDACTED]")
}
