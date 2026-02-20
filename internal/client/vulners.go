// Package client provides the upstream HTTP client for the Vulners API.
package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/metrics"
	"vulners-proxy-go/internal/model"
)

// VulnersClient sends requests to the upstream Vulners API.
type VulnersClient struct {
	httpClient *http.Client
	logger     *slog.Logger
	metrics    *metrics.Metrics
}

// NewVulnersClient creates a VulnersClient with connection pooling and timeouts.
// The metrics parameter is optional; pass nil to disable upstream metrics recording.
func NewVulnersClient(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics) *VulnersClient {
	transport := &http.Transport{
		MaxIdleConns:        cfg.Upstream.IdleConnections,
		MaxIdleConnsPerHost: cfg.Upstream.IdleConnections,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &VulnersClient{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.Upstream.TimeoutSeconds) * time.Second,
		},
		logger:  logger.With("component", "vulners_client"),
		metrics: m,
	}
}

// Do executes an HTTP request against the upstream and returns the raw response.
// The caller is responsible for closing the response body.
func (c *VulnersClient) Do(req *http.Request) (*model.ProxyResponse, error) {
	c.logger.Debug("upstream request",
		"method", req.Method,
		"path", req.URL.Path,
	)

	start := time.Now()
	resp, err := c.httpClient.Do(req) //nolint:bodyclose // body ownership transfers to caller via ProxyResponse
	duration := time.Since(start).Seconds()

	method := metrics.NormalizeMethod(req.Method)

	if err != nil {
		if c.metrics != nil {
			c.metrics.UpstreamDuration.WithLabelValues(method).Observe(duration)
		}
		return nil, fmt.Errorf("upstream request: %w", err)
	}

	if c.metrics != nil {
		status := strconv.Itoa(resp.StatusCode)
		c.metrics.UpstreamDuration.WithLabelValues(method).Observe(duration)
		c.metrics.UpstreamResponses.WithLabelValues(method, status).Inc()
	}

	return &model.ProxyResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       resp.Body,
	}, nil
}

// DoStream executes a request and returns the response body as a stream.
// The caller is responsible for closing the returned ReadCloser.
// The provided context controls the lifetime of the upstream request:
// when the context is canceled (e.g. client disconnects), the upstream
// request is also canceled.
func (c *VulnersClient) DoStream(ctx context.Context, method, url string, header http.Header, body io.Reader) (*model.ProxyResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	req.Header = header

	return c.Do(req)
}
