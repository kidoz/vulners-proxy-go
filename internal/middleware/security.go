package middleware

import (
	"github.com/labstack/echo/v4"
)

// hopByHopHeaders are headers that should not be forwarded by proxies.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// SecurityHeaders returns an Echo middleware that adds security headers
// and strips hop-by-hop headers from responses.
func SecurityHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Strip hop-by-hop headers from incoming request
			for _, h := range hopByHopHeaders {
				c.Request().Header.Del(h)
			}

			err := next(c)

			// Add security headers to response
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			c.Response().Header().Set("X-Frame-Options", "DENY")

			return err
		}
	}
}
