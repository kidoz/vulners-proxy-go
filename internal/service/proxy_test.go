package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"vulners-proxy-go/internal/client"
	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/model"
)

func TestFilterRequestHeaders(t *testing.T) {
	s := &ProxyService{}
	src := http.Header{
		"Accept":          {"application/json"},
		"Content-Type":    {"application/json"},
		"Authorization":   {"Bearer secret"},
		"Connection":      {"keep-alive"},
		"X-Vulners-Token": {"abc123"},
		"X-Custom-Header": {"should-be-dropped"},
		"X-Api-Key":       {"should-be-dropped"},
		"X-Real-Ip":       {"1.2.3.4"},
		"X-Forwarded-For": {"1.2.3.4, 5.6.7.8"},
	}

	dst := s.filterRequestHeaders(src)

	tests := []struct {
		name    string
		key     string
		wantLen int
	}{
		{"Accept forwarded", "Accept", 1},
		{"Content-Type forwarded", "Content-Type", 1},
		{"X-Vulners-Token forwarded", "X-Vulners-Token", 1},
		{"Authorization stripped", "Authorization", 0},
		{"Connection stripped", "Connection", 0},
		{"X-Custom-Header stripped", "X-Custom-Header", 0},
		{"X-Api-Key stripped by filter", "X-Api-Key", 0},
		{"X-Real-Ip stripped", "X-Real-Ip", 0},
		{"X-Forwarded-For stripped", "X-Forwarded-For", 0},
		{"User-Agent injected", "User-Agent", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(dst.Values(tt.key))
			if got != tt.wantLen {
				t.Errorf("header %q: got %d values, want %d", tt.key, got, tt.wantLen)
			}
		})
	}

	if ua := dst.Get("User-Agent"); ua != userAgent {
		t.Errorf("User-Agent = %q, want %q", ua, userAgent)
	}
}

func TestFilterResponseHeaders(t *testing.T) {
	s := &ProxyService{}
	src := http.Header{
		"Content-Type":           {"application/json"},
		"Content-Length":         {"42"},
		"Transfer-Encoding":      {"chunked"},
		"Set-Cookie":             {"session=abc"},
		"X-Content-Type-Options": {"nosniff"},
		"Date":                   {"Mon, 01 Jan 2025 00:00:00 GMT"},
	}

	dst := s.filterResponseHeaders(src)

	tests := []struct {
		name    string
		key     string
		wantLen int
	}{
		{"Content-Type forwarded", "Content-Type", 1},
		{"Content-Length forwarded", "Content-Length", 1},
		{"Date forwarded", "Date", 1},
		{"Set-Cookie stripped", "Set-Cookie", 0},
		{"X-Content-Type-Options stripped", "X-Content-Type-Options", 0},
		{"Transfer-Encoding stripped (hop-by-hop)", "Transfer-Encoding", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(dst.Values(tt.key))
			if got != tt.wantLen {
				t.Errorf("header %q: got %d values, want %d", tt.key, got, tt.wantLen)
			}
		})
	}
}

func TestBuildUpstreamURL(t *testing.T) {
	baseURL, _ := url.Parse("https://vulners.com")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{}
	s := &ProxyService{
		baseURL: baseURL,
		cfg:     cfg,
		logger:  logger,
	}

	tests := []struct {
		name  string
		path  string
		query url.Values
		want  string
	}{
		{
			name:  "path with query params",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"query": {"cve-2024-1234"}},
			want:  "query=cve-2024-1234",
		},
		{
			name:  "no query params",
			path:  "/api/v3/search/lucene/",
			query: url.Values{},
			want:  "",
		},
		{
			name:  "apiKey stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"apiKey": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "apikey lowercase stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"apikey": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "ApiKey mixed case stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"ApiKey": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "APIKEY uppercase stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"APIKEY": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "api_key underscore stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"api_key": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "API_KEY uppercase underscore stripped",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"API_KEY": {"secret"}, "query": {"test"}},
			want:  "query=test",
		},
		{
			name:  "only apiKey stripped leaves empty query",
			path:  "/api/v3/search/lucene/",
			query: url.Values{"apiKey": {"secret"}},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.buildUpstreamURL(tt.path, tt.query)
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			if u.RawQuery != tt.want {
				t.Errorf("query = %q, want %q", u.RawQuery, tt.want)
			}
			if u.Path != tt.path {
				t.Errorf("path = %q, want %q", u.Path, tt.path)
			}
		})
	}
}

func TestResolveAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		configKey string
		headerKey string
		want      string
	}{
		{
			name:      "config key takes precedence",
			configKey: "config-key",
			headerKey: "header-key",
			want:      "config-key",
		},
		{
			name:      "falls back to X-Api-Key header",
			configKey: "",
			headerKey: "header-key",
			want:      "header-key",
		},
		{
			name:      "empty when neither set",
			configKey: "",
			headerKey: "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ProxyService{
				cfg: &config.Config{
					Vulners: config.VulnersConfig{APIKey: tt.configKey},
				},
			}
			header := http.Header{}
			if tt.headerKey != "" {
				header.Set("X-Api-Key", tt.headerKey)
			}

			got := s.resolveAPIKey(header)
			if got != tt.want {
				t.Errorf("resolveAPIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestForward_HappyPath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" {
			t.Errorf("X-Api-Key = %q, want %q", r.Header.Get("X-Api-Key"), "test-key")
		}
		if r.URL.Query().Get("apiKey") != "" {
			t.Errorf("apiKey query param should be stripped, got %q", r.URL.Query().Get("apiKey"))
		}
		if r.URL.Query().Get("query") != "cve-2024-1234" {
			t.Errorf("query param = %q, want %q", r.URL.Query().Get("query"), "cve-2024-1234")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger, nil)
	svc, err := NewProxyServiceForTest(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyServiceForTest: %v", err)
	}

	pr := &model.ProxyRequest{
		Ctx:    context.Background(),
		Method: http.MethodGet,
		Path:   "/api/v3/search/lucene/",
		Query:  url.Values{"query": {"cve-2024-1234"}, "apiKey": {"should-be-stripped"}},
		Header: http.Header{},
	}

	resp, err := svc.Forward(pr)
	if err != nil {
		t.Fatalf("Forward() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(body) != `{"result":"ok"}` {
		t.Errorf("body = %q, want %q", string(body), `{"result":"ok"}`)
	}
}

func TestForward_FiltersResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=abc")
		w.Header().Set("X-Internal-Debug", "secret")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Vulners: config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{
			BaseURL:         upstream.URL,
			TimeoutSeconds:  10,
			IdleConnections: 10,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vc := client.NewVulnersClient(cfg, logger, nil)
	svc, err := NewProxyServiceForTest(vc, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyServiceForTest: %v", err)
	}

	pr := &model.ProxyRequest{
		Ctx:    context.Background(),
		Method: http.MethodGet,
		Path:   "/api/v3/test",
		Query:  url.Values{},
		Header: http.Header{},
	}

	resp, err := svc.Forward(pr)
	if err != nil {
		t.Fatalf("Forward() error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want %q", resp.Header.Get("Content-Type"), "application/json")
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("Set-Cookie should be stripped, got %q", resp.Header.Get("Set-Cookie"))
	}
	if resp.Header.Get("X-Internal-Debug") != "" {
		t.Errorf("X-Internal-Debug should be stripped, got %q", resp.Header.Get("X-Internal-Debug"))
	}
}

func TestForward_MissingAPIKey(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	baseURL, _ := url.Parse("https://vulners.com")
	s := &ProxyService{
		cfg:     &config.Config{},
		logger:  logger,
		baseURL: baseURL,
	}

	pr := &model.ProxyRequest{
		Ctx:    context.Background(),
		Method: http.MethodGet,
		Path:   "/api/v3/search/lucene/",
		Query:  url.Values{},
		Header: http.Header{},
	}

	_, err := s.Forward(pr)
	if err == nil {
		t.Fatal("Forward() expected ErrMissingAPIKey, got nil")
	}
	if !errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("Forward() error = %v, want ErrMissingAPIKey", err)
	}
}

func TestNewProxyService_AllowlistRejectsUnknownHost(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Vulners:  config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{BaseURL: "https://evil.com"},
	}
	_, err := NewProxyService(nil, cfg, logger)
	if err == nil {
		t.Fatal("NewProxyService() expected error for disallowed host, got nil")
	}
}

func TestNewProxyService_AllowlistAcceptsVulners(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{
		Vulners:  config.VulnersConfig{APIKey: "test-key"},
		Upstream: config.UpstreamConfig{BaseURL: "https://vulners.com"},
	}
	svc, err := NewProxyService(nil, cfg, logger)
	if err != nil {
		t.Fatalf("NewProxyService() error = %v", err)
	}
	if svc == nil {
		t.Fatal("NewProxyService() returned nil service")
	}
}
