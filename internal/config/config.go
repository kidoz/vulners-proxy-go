// Package config handles TOML configuration loading and validation.
package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// configSearchPaths lists paths checked in order when no explicit config is given.
var configSearchPaths = []string{
	"/etc/vulners-proxy/config.toml",
	"configs/config.toml",
}

// CLI holds command-line arguments parsed by Kong.
type CLI struct {
	Config   string `kong:"short='c',help='Path to TOML config file.',env='CONFIG_PATH'"`
	Host     string `kong:"help='Listen host (overrides config).',env='HOST'"`
	Port     int    `kong:"short='p',help='Listen port (overrides config).',env='PORT'"`
	APIKey   string `kong:"help='Vulners API key (overrides config).',env='VULNERS_API_KEY'"`
	LogLevel string `kong:"help='Log level: debug|info|warn|error (overrides config).',env='LOG_LEVEL'"`
}

// Config is the top-level application configuration.
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Vulners  VulnersConfig  `toml:"vulners"`
	Upstream UpstreamConfig `toml:"upstream"`
	Log      LogConfig      `toml:"log"`
	Metrics  MetricsConfig  `toml:"metrics"`

	filePath string // resolved config file path (unexported)
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host         string          `toml:"host"`
	Port         int             `toml:"port"` // 0 means "use default" (8000); TOML cannot distinguish 0 from unset
	BodyMaxBytes int64           `toml:"body_max_bytes"`
	RateLimit    RateLimitConfig `toml:"rate_limit"`
}

// RateLimitConfig controls per-IP request rate limiting.
type RateLimitConfig struct {
	Enabled           bool    `toml:"enabled"`
	RequestsPerSecond float64 `toml:"requests_per_second"`
}

// VulnersConfig holds Vulners API credentials.
type VulnersConfig struct {
	APIKey string `toml:"api_key"`
}

// UpstreamConfig holds upstream connection settings.
type UpstreamConfig struct {
	BaseURL         string `toml:"base_url"`
	TimeoutSeconds  int    `toml:"timeout_seconds"`
	IdleConnections int    `toml:"idle_connections"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"`
}

// Load reads the TOML config file and applies CLI overrides.
// When no explicit path is given (via --config or CONFIG_PATH), it searches
// /etc/vulners-proxy/config.toml then configs/config.toml.
func Load(cli *CLI) (*Config, error) {
	path := cli.Config
	if path == "" {
		path = findConfig()
	}
	if path == "" {
		return nil, fmt.Errorf("config: no config file found (searched %v)", configSearchPaths)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.filePath = path
	cfg.applyCLI(cli)

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: validate: %w", err)
	}

	cfg.setDefaults()
	return &cfg, nil
}

// applyCLI overrides config values with non-zero CLI flags.
func (c *Config) applyCLI(cli *CLI) {
	if cli.Host != "" {
		c.Server.Host = cli.Host
	}
	if cli.Port != 0 {
		c.Server.Port = cli.Port
	}
	if cli.APIKey != "" {
		c.Vulners.APIKey = cli.APIKey
	}
	if cli.LogLevel != "" {
		c.Log.Level = cli.LogLevel
	}
}

func (c *Config) validate() error {
	if c.Vulners.APIKey == "YOUR_API_KEY_HERE" {
		return fmt.Errorf("vulners.api_key contains placeholder value; set a real key or leave empty for per-request X-Api-Key mode")
	}

	// Upstream URL: required and must be HTTPS.
	if c.Upstream.BaseURL == "" {
		return fmt.Errorf("upstream.base_url is required")
	}
	u, err := url.Parse(c.Upstream.BaseURL)
	if err != nil {
		return fmt.Errorf("upstream.base_url is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("upstream.base_url must use HTTPS; got %q", c.Upstream.BaseURL)
	}

	// Numeric bounds.
	if c.Server.Port < 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 0–65535; got %d", c.Server.Port)
	}
	if c.Server.BodyMaxBytes < 0 {
		return fmt.Errorf("server.body_max_bytes must be non-negative; got %d", c.Server.BodyMaxBytes)
	}
	if c.Upstream.TimeoutSeconds < 0 {
		return fmt.Errorf("upstream.timeout_seconds must be non-negative; got %d", c.Upstream.TimeoutSeconds)
	}
	if c.Upstream.IdleConnections < 0 {
		return fmt.Errorf("upstream.idle_connections must be non-negative; got %d", c.Upstream.IdleConnections)
	}
	if c.Server.RateLimit.Enabled && c.Server.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("server.rate_limit.requests_per_second must be > 0 when rate limiting is enabled; got %v", c.Server.RateLimit.RequestsPerSecond)
	}

	// Log fields.
	level := strings.ToLower(c.Log.Level)
	switch level {
	case "debug", "info", "warn", "error", "":
		// valid
	default:
		return fmt.Errorf("log.level must be one of: debug, info, warn, error; got %q", c.Log.Level)
	}
	format := strings.ToLower(c.Log.Format)
	switch format {
	case "json", "text", "":
		// valid
	default:
		return fmt.Errorf("log.format must be one of: json, text; got %q", c.Log.Format)
	}

	// Metrics path validation (only when metrics are enabled).
	if c.Metrics.Enabled && c.Metrics.Path != "" {
		p := c.Metrics.Path
		if p[0] != '/' {
			return fmt.Errorf("metrics.path must start with '/'; got %q", p)
		}
		for _, reserved := range []string{"/api/v3", "/api/v4", "/healthz", "/proxy/status"} {
			if p == reserved || strings.HasPrefix(p, reserved+"/") {
				return fmt.Errorf("metrics.path %q conflicts with reserved route %q", p, reserved)
			}
		}
	}

	return nil
}

// setDefaults fills zero-valued fields with sensible defaults.
// For integer fields (Port, BodyMaxBytes, etc.), zero means "unset" because TOML
// cannot distinguish between an explicit 0 and an omitted key. Setting port=0 in
// the config file therefore results in the default port (8000).
func (c *Config) setDefaults() {
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8000
	}
	if c.Server.BodyMaxBytes == 0 {
		c.Server.BodyMaxBytes = 10 * 1024 * 1024 // 10 MB
	}
	if c.Upstream.TimeoutSeconds == 0 {
		c.Upstream.TimeoutSeconds = 120
	}
	if c.Upstream.IdleConnections == 0 {
		c.Upstream.IdleConnections = 100
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
}

// findConfig returns the first config path that exists, or empty string.
func findConfig() string {
	return findConfigInPaths(configSearchPaths)
}

// findConfigInPaths returns the first path that exists on disk, or empty string.
func findConfigInPaths(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Addr returns the server listen address as host:port.
func (c *ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// WarnPermissions logs a warning if the config file is readable by group or others.
func (c *Config) WarnPermissions(logger *slog.Logger) {
	if c.filePath == "" {
		return
	}
	info, err := os.Stat(c.filePath)
	if err != nil {
		return
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		logger.Warn("config file is readable by group/others; consider chmod 600",
			"path", c.filePath,
			"mode", fmt.Sprintf("%04o", perm),
		)
	}
}
