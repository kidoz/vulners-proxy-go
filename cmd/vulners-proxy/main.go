package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/labstack/echo/v4"
	echomw "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/fx"
	"golang.org/x/time/rate"

	"vulners-proxy-go/internal/client"
	"vulners-proxy-go/internal/config"
	"vulners-proxy-go/internal/handler"
	"vulners-proxy-go/internal/metrics"
	"vulners-proxy-go/internal/middleware"
	"vulners-proxy-go/internal/service"
)

// Set by goreleaser ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var cli config.CLI
	kong.Parse(&cli,
		kong.Name("vulners-proxy"),
		kong.Description("Reverse proxy for the Vulners API."),
		kong.Vars{"version": fmt.Sprintf("%s (%s, %s)", version, commit, date)},
	)

	fx.New(
		fx.Provide(
			func() *config.CLI { return &cli },
			func() handler.Version { return handler.Version(version) },
			config.Load,
			newLogger,
			newMetrics,
			newEcho,
			client.NewVulnersClient,
			service.NewProxyService,
			handler.NewProxyHandler,
			handler.NewHealthHandler,
		),
		fx.Invoke(handler.RegisterRoutes, warnConfigPermissions, startServer),
	).Run()
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	switch strings.ToLower(cfg.Log.Format) {
	case "text":
		h = slog.NewTextHandler(os.Stdout, opts)
	default:
		h = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(h)
}

func newMetrics(cfg *config.Config) *metrics.Metrics {
	if !cfg.Metrics.Enabled {
		return nil
	}
	return metrics.New()
}

func newEcho(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Inbound timeouts to mitigate slow-client attacks.
	e.Server.ReadTimeout = 30 * time.Second
	// WriteTimeout is disabled (0) to avoid cutting off valid long-running streamed
	// responses. Protection is provided by the upstream client timeout, ReadTimeout,
	// and IdleTimeout.
	e.Server.WriteTimeout = 0
	e.Server.IdleTimeout = 120 * time.Second
	e.Server.ReadHeaderTimeout = 10 * time.Second

	e.Use(echomw.Recover())
	e.Use(echomw.RequestID())
	e.Use(middleware.RequestLogger(logger))
	if m != nil {
		e.Use(middleware.MetricsMiddleware(m))
	}
	e.Use(echomw.BodyLimit(fmt.Sprintf("%dB", cfg.Server.BodyMaxBytes)))
	e.Use(middleware.SecurityHeaders())

	if cfg.Server.RateLimit.Enabled {
		store := echomw.NewRateLimiterMemoryStore(rate.Limit(cfg.Server.RateLimit.RequestsPerSecond))
		e.Use(echomw.RateLimiterWithConfig(echomw.RateLimiterConfig{
			Store: store,
			IdentifierExtractor: func(c echo.Context) (string, error) {
				// Use the direct TCP peer address, not X-Forwarded-For or
				// X-Real-IP, to prevent rate-limit bypass via spoofed headers.
				// If the proxy sits behind a trusted load balancer, configure
				// Echo's TrustProxy settings and switch to c.RealIP() instead.
				ip, _, err := net.SplitHostPort(c.Request().RemoteAddr)
				if err != nil {
					// RemoteAddr may lack a port (e.g. Unix socket); use it as-is.
					return c.Request().RemoteAddr, nil //nolint:nilerr // fallback is intentional
				}
				return ip, nil
			},
		}))
		logger.Info("rate limiter enabled", "rps", cfg.Server.RateLimit.RequestsPerSecond)
	}

	if m != nil {
		e.GET(cfg.Metrics.Path, echo.WrapHandler(promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})))
		logger.Info("metrics endpoint enabled", "path", cfg.Metrics.Path)
	}

	return e
}

func warnConfigPermissions(cfg *config.Config, logger *slog.Logger) {
	cfg.WarnPermissions(logger)
}

func startServer(lc fx.Lifecycle, e *echo.Echo, cfg *config.Config, logger *slog.Logger) {
	lc.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			addr := cfg.Server.Addr()
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("bind %s: %w", addr, err)
			}
			logger.Info("starting server", "addr", addr)
			go func() {
				if err := e.Server.Serve(ln); err != nil && err != http.ErrServerClosed {
					logger.Error("server error", "err", err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("shutting down server")
			return e.Shutdown(ctx)
		},
	})
}
