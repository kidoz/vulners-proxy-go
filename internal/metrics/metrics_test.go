package metrics

import (
	"testing"
)

func TestNew_GathersMetrics(t *testing.T) {
	m := New()

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	// Should include at least Go runtime and process collectors.
	if len(families) == 0 {
		t.Fatal("expected non-empty metric families from Gather()")
	}

	// Verify our custom metrics exist by incrementing one and gathering again.
	m.RequestsTotal.WithLabelValues("GET", "200", "/api/v3").Inc()

	families, err = m.Registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	found := false
	for _, f := range families {
		if f.GetName() == "vulners_proxy_http_requests_total" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected vulners_proxy_http_requests_total in gathered metrics")
	}
}

func TestNormalizeMethod(t *testing.T) {
	tests := []struct {
		method string
		want   string
	}{
		{"GET", "GET"},
		{"POST", "POST"},
		{"PUT", "PUT"},
		{"DELETE", "DELETE"},
		{"PATCH", "PATCH"},
		{"HEAD", "HEAD"},
		{"OPTIONS", "OPTIONS"},
		{"FOOBAR", "other"},
		{"get", "other"},
		{"X-CUSTOM", "other"},
		{"", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := NormalizeMethod(tt.method)
			if got != tt.want {
				t.Errorf("NormalizeMethod(%q) = %q, want %q", tt.method, got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v3/search/lucene/", "/api/v3"},
		{"/api/v4/search/lucene/", "/api/v4"},
		{"/healthz", "/healthz"},
		{"/proxy/status", "/proxy/status"},
		{"/metrics", "/metrics"},
		{"/unknown", "other"},
		{"/", "other"},
		{"/api/v5/foo", "other"},
		{"/api/v3", "/api/v3"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := NormalizePath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
