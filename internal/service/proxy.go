// Package service implements the core proxy forwarding logic.
package service

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"vulners-proxy-go/internal/client"
	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/model"
)

// ErrMissingAPIKey is returned when no API key is available from config or request header.
var ErrMissingAPIKey = errors.New("API key required: set vulners.api_key in config or send X-Api-Key header")

// allowedUpstreamHosts restricts which hosts the proxy will forward to.
var allowedUpstreamHosts = map[string]bool{
	"vulners.com": true,
}

// forwardableRequestHeaders are the only request headers forwarded upstream.
var forwardableRequestHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Accept-Language",
	"Content-Type",
	"Content-Length",
}

// forwardableResponseHeaders are the only response headers forwarded to the client.
var forwardableResponseHeaders = map[string]bool{
	"Content-Type":     true,
	"Content-Length":   true,
	"Content-Encoding": true,
	"Cache-Control":    true,
	"Date":             true,
	"X-Request-Id":     true,
}

const userAgent = "vulners-proxy-go/1.0"

// ProxyService handles the forwarding logic for proxy requests.
type ProxyService struct {
	client  *client.VulnersClient
	cfg     *config.Config
	logger  *slog.Logger
	baseURL *url.URL
}

// NewProxyService creates a ProxyService.
func NewProxyService(c *client.VulnersClient, cfg *config.Config, logger *slog.Logger) (*ProxyService, error) {
	u, err := url.Parse(cfg.Upstream.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base_url: %w", err)
	}

	if !allowedUpstreamHosts[u.Hostname()] {
		return nil, fmt.Errorf("upstream host %q is not in the allowlist", u.Hostname())
	}

	return &ProxyService{
		client:  c,
		cfg:     cfg,
		logger:  logger.With("component", "proxy_service"),
		baseURL: u,
	}, nil
}

// NewProxyServiceForTest creates a ProxyService without host allowlist validation.
// This is intended only for tests that use httptest servers on localhost.
func NewProxyServiceForTest(c *client.VulnersClient, cfg *config.Config, logger *slog.Logger) (*ProxyService, error) {
	u, err := url.Parse(cfg.Upstream.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream base_url: %w", err)
	}

	return &ProxyService{
		client:  c,
		cfg:     cfg,
		logger:  logger.With("component", "proxy_service"),
		baseURL: u,
	}, nil
}

// Forward sends a ProxyRequest to the upstream Vulners API and returns the response.
// The caller is responsible for closing the response body.
//
// The API key is resolved in order: config value → X-Api-Key request header.
// If neither is present, ErrMissingAPIKey is returned.
func (s *ProxyService) Forward(pr *model.ProxyRequest) (*model.ProxyResponse, error) {
	apiKey := s.resolveAPIKey(pr.Header)
	if apiKey == "" {
		return nil, ErrMissingAPIKey
	}

	upstreamURL := s.buildUpstreamURL(pr.Path, pr.Query, apiKey)
	header := s.filterRequestHeaders(pr.Header)

	s.logger.Debug("forwarding request",
		"method", pr.Method,
		"path", pr.Path,
	)

	resp, err := s.client.DoStream(pr.Ctx, pr.Method, upstreamURL, header, pr.Body)
	if err != nil {
		return nil, fmt.Errorf("forward to upstream: %w", err)
	}

	resp.Header = s.filterResponseHeaders(resp.Header)
	return resp, nil
}

// resolveAPIKey returns the API key from config, falling back to the X-Api-Key request header.
func (s *ProxyService) resolveAPIKey(header http.Header) string {
	if s.cfg.Vulners.APIKey != "" {
		return s.cfg.Vulners.APIKey
	}
	return header.Get("X-Api-Key")
}

func (s *ProxyService) buildUpstreamURL(path string, query url.Values, apiKey string) string {
	u := *s.baseURL
	u.Path = path

	q := make(url.Values)
	for k, v := range query {
		q[k] = v
	}
	q.Set("apiKey", apiKey)
	u.RawQuery = q.Encode()

	return u.String()
}

func (s *ProxyService) filterRequestHeaders(src http.Header) http.Header {
	dst := make(http.Header)
	for _, key := range forwardableRequestHeaders {
		if vals := src.Values(key); len(vals) > 0 {
			dst[http.CanonicalHeaderKey(key)] = vals
		}
	}
	// Forward any X-Vulners-* headers
	for key, vals := range src {
		if strings.HasPrefix(strings.ToLower(key), "x-vulners-") {
			dst[http.CanonicalHeaderKey(key)] = vals
		}
	}
	dst.Set("User-Agent", userAgent)
	return dst
}

func (s *ProxyService) filterResponseHeaders(src http.Header) http.Header {
	dst := make(http.Header)
	for key, vals := range src {
		if forwardableResponseHeaders[http.CanonicalHeaderKey(key)] {
			dst[key] = vals
		}
	}
	return dst
}
