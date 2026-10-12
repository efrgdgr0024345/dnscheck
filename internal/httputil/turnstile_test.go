// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package httputil

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testRoundTrip func(*http.Request) (*http.Response, error)

func (f testRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func TestTurnstileBindsHostnameActionAndStatus(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		status     int
		want       bool
	}{
		{"valid", `{"success":true,"hostname":"example.invalid","action":"claim"}`, 200, true},
		{"wrong hostname", `{"success":true,"hostname":"other.invalid","action":"claim"}`, 200, false},
		{"wrong action", `{"success":true,"hostname":"example.invalid","action":"login"}`, 200, false},
		{"missing context", `{"success":true}`, 200, false},
		{"HTTP failure", `{"success":true,"hostname":"example.invalid","action":"claim"}`, 503, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &TurnstileClient{Secret: "test-only", ExpectedHostname: "example.invalid", HttpClient: http.Client{Transport: testRoundTrip(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tt.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tt.body)), Request: r}, nil
			})}}
			got, err := c.VerifyContext(context.Background(), "test-token")
			if got != tt.want || (tt.want && err != nil) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}
