// Package model defines shared types for the proxy.
package model

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

// ProxyRequest represents a client request to be forwarded upstream.
type ProxyRequest struct {
	Ctx    context.Context
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   io.ReadCloser
}

// ProxyResponse represents the upstream response to be streamed back.
type ProxyResponse struct {
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
}
