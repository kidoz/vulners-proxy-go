package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cliWithPath returns a CLI struct pointing at the given config file.
func cliWithPath(path string) *CLI {
	return &CLI{Config: path}
}

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[server]
host = "127.0.0.1"
port = 9000
body_max_bytes = 5242880

[vulners]
api_key = "test-key-12345"

[upstream]
base_url = "https://vulners.com"
timeout_seconds = 60
idle_connections = 50

[log]
level = "debug"
format = "text"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != 9000 {
		t.Errorf("Server.Port = %d, want %d", cfg.Server.Port, 9000)
	}
	if cfg.Vulners.APIKey != "test-key-12345" {
		t.Errorf("Vulners.APIKey = %q, want %q", cfg.Vulners.APIKey, "test-key-12345")
	}
	if cfg.Upstream.TimeoutSeconds != 60 {
		t.Errorf("Upstream.TimeoutSeconds = %d, want %d", cfg.Upstream.TimeoutSeconds, 60)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %q, want %q", cfg.Log.Format, "text")
	}
}

func TestLoad_EmptyAPIKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[vulners]
api_key = ""

[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v; empty api_key should be allowed for X-Api-Key mode", err)
	}
	if cfg.Vulners.APIKey != "" {
		t.Errorf("Vulners.APIKey = %q, want empty", cfg.Vulners.APIKey)
	}
}

func TestLoad_PlaceholderAPIKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[vulners]
api_key = "YOUR_API_KEY_HERE"

[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for placeholder api_key, got nil")
	}
}

func TestLoad_InvalidLogLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[vulners]
api_key = "test-key-12345"

[upstream]
base_url = "https://vulners.com"

[log]
level = "verbose"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for invalid log level, got nil")
	}
}

func TestLoad_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[vulners]
api_key = "test-key-12345"

[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("default Server.Host = %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.Port != 8000 {
		t.Errorf("default Server.Port = %d, want %d", cfg.Server.Port, 8000)
	}
	if cfg.Server.BodyMaxBytes != 10*1024*1024 {
		t.Errorf("default Server.BodyMaxBytes = %d, want %d", cfg.Server.BodyMaxBytes, 10*1024*1024)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default Log.Level = %q, want %q", cfg.Log.Level, "info")
	}
	if cfg.Log.Format != "json" {
		t.Errorf("default Log.Format = %q, want %q", cfg.Log.Format, "json")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(cliWithPath("/nonexistent/config.toml"))
	if err == nil {
		t.Fatal("Load() expected error for missing file, got nil")
	}
}

func TestLoad_CLIOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[server]
host = "0.0.0.0"
port = 8000

[vulners]
api_key = "toml-key"

[upstream]
base_url = "https://vulners.com"

[log]
level = "info"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cli := &CLI{
		Config:   path,
		Host:     "127.0.0.1",
		Port:     3000,
		APIKey:   "cli-key",
		LogLevel: "debug",
	}

	cfg, err := Load(cli)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want %q (CLI override)", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("Server.Port = %d, want %d (CLI override)", cfg.Server.Port, 3000)
	}
	if cfg.Vulners.APIKey != "cli-key" {
		t.Errorf("Vulners.APIKey = %q, want %q (CLI override)", cfg.Vulners.APIKey, "cli-key")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want %q (CLI override)", cfg.Log.Level, "debug")
	}
}

func TestLoad_HTTPUpstreamRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[vulners]
api_key = "test-key"

[upstream]
base_url = "http://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for HTTP upstream, got nil")
	}
}

func TestLoad_NegativePort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[server]
port = -1

[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for negative port, got nil")
	}
}

func TestLoad_NegativeBodyMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[server]
body_max_bytes = -1

[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for negative body_max_bytes, got nil")
	}
}

func TestLoad_NegativeTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"
timeout_seconds = -5
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for negative timeout, got nil")
	}
}

func TestLoad_RateLimitConfig_Enabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[server.rate_limit]
enabled = true
requests_per_second = 50.0
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Server.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled = true")
	}
	if cfg.Server.RateLimit.RequestsPerSecond != 50.0 {
		t.Errorf("RateLimit.RequestsPerSecond = %v, want 50.0", cfg.Server.RateLimit.RequestsPerSecond)
	}
}

func TestLoad_RateLimitConfig_Disabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled = false by default")
	}
}

func TestLoad_RateLimitConfig_BadValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[server.rate_limit]
enabled = true
requests_per_second = 0
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for rate limit enabled with requests_per_second=0, got nil")
	}
	if !strings.Contains(err.Error(), "requests_per_second") {
		t.Errorf("error = %q, want mention of requests_per_second", err)
	}
}

func TestWarnPermissions_Loose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# test"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{filePath: path}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg.WarnPermissions(logger)

	if !strings.Contains(buf.String(), "readable by group/others") {
		t.Errorf("expected permission warning, got: %q", buf.String())
	}
}

func TestWarnPermissions_Strict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# test"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{filePath: path}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg.WarnPermissions(logger)

	if buf.Len() != 0 {
		t.Errorf("expected no warning for 0600 file, got: %q", buf.String())
	}
}

func TestFindConfigInPaths_Found(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[upstream]\nbase_url = \"https://vulners.com\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := findConfigInPaths([]string{path})
	if got != path {
		t.Errorf("findConfigInPaths() = %q, want %q", got, path)
	}
}

func TestFindConfigInPaths_NotFound(t *testing.T) {
	got := findConfigInPaths([]string{"/nonexistent/a.toml", "/nonexistent/b.toml"})
	if got != "" {
		t.Errorf("findConfigInPaths() = %q, want empty", got)
	}
}

func TestFindConfigInPaths_Priority(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	path1 := filepath.Join(dir1, "config.toml")
	path2 := filepath.Join(dir2, "config.toml")
	for _, p := range []string{path1, path2} {
		if err := os.WriteFile(p, []byte("[upstream]\nbase_url = \"https://vulners.com\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := findConfigInPaths([]string{path1, path2})
	if got != path1 {
		t.Errorf("findConfigInPaths() = %q, want first match %q", got, path1)
	}
}

func TestLoad_MetricsPathDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[metrics]
enabled = true
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Metrics.Path != "/metrics" {
		t.Errorf("Metrics.Path = %q, want %q", cfg.Metrics.Path, "/metrics")
	}
}

func TestLoad_MetricsPathNoLeadingSlash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[metrics]
enabled = true
path = "metrics"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err == nil {
		t.Fatal("Load() expected error for metrics.path without leading slash, got nil")
	}
	if !strings.Contains(err.Error(), "metrics.path") {
		t.Errorf("error = %q, want mention of metrics.path", err)
	}
}

func TestLoad_MetricsPathConflictsWithAPIRoute(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"api/v3 exact", "/api/v3"},
		{"api/v3 sub", "/api/v3/metrics"},
		{"api/v4 exact", "/api/v4"},
		{"healthz", "/healthz"},
		{"proxy/status", "/proxy/status"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			data := `
[upstream]
base_url = "https://vulners.com"

[metrics]
enabled = true
path = "` + tt.path + `"
`
			if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := Load(cliWithPath(cfgPath))
			if err == nil {
				t.Fatalf("Load() expected error for metrics.path=%q conflicting with route, got nil", tt.path)
			}
			if !strings.Contains(err.Error(), "conflicts") {
				t.Errorf("error = %q, want mention of conflict", err)
			}
		})
	}
}

func TestLoad_MetricsPathValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[metrics]
enabled = true
path = "/custom-metrics"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Metrics.Path != "/custom-metrics" {
		t.Errorf("Metrics.Path = %q, want %q", cfg.Metrics.Path, "/custom-metrics")
	}
}

func TestLoad_MetricsDisabledSkipsPathValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
[upstream]
base_url = "https://vulners.com"

[metrics]
enabled = false
path = "bad-no-slash"
`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(cliWithPath(path))
	if err != nil {
		t.Fatalf("Load() error = %v; disabled metrics should skip path validation", err)
	}
}

func TestServerConfig_Addr(t *testing.T) {
	sc := &ServerConfig{Host: "127.0.0.1", Port: 3000}
	want := "127.0.0.1:3000"
	if got := sc.Addr(); got != want {
		t.Errorf("Addr() = %q, want %q", got, want)
	}
}
