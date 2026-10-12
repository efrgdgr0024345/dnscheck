// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package httputil

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictRequestParsing(t *testing.T) {
	tests := []struct {
		name, query, contentType, body string
		want                           error
	}{
		{"duplicate JSON", "", "application/json", `{"key":"one","key":"one"}`, ErrAmbiguousValues},
		{"different JSON duplicate", "", "application/json", `{"key":"one","key":"two"}`, ErrAmbiguousValues},
		{"JSON null", "", "application/json", `{"key":null}`, ErrValueUnexpectedType},
		{"JSON object", "", "application/json", `{"key":{}}`, ErrValueUnexpectedType},
		{"duplicate form", "", "application/x-www-form-urlencoded", "key=one&key=one", ErrAmbiguousValues},
		{"query/body duplicate", "key=one", "application/json", `{"key":"one"}`, ErrAmbiguousValues},
		{"duplicate query", "key=one&key=one", "", "", ErrAmbiguousValues},
		{"oversize", "", "application/json", strings.Repeat("x", MaxRequestBodyBytes+1), ErrBodyTooLarge},
		{"unsupported content", "", "text/plain", "secret", ErrUnsupportedMediaType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://example.invalid/?"+tt.query, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			err := ParseRequest(req).Validate("key")
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
	for _, body := range []string{`{"key":"x"} {}`, `{"key":`, `[]`, `"x"`} {
		req := httptest.NewRequest(http.MethodPost, "http://example.invalid/", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if err := ParseRequest(req).Validate("key"); err == nil {
			t.Fatalf("malformed body accepted: %s", body)
		}
	}
	for _, query := range []string{"key=%ZZ", "key=x;other=y"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid/?"+query, nil)
		if err := ParseRequest(req).Validate("key"); err == nil {
			t.Fatal("malformed query accepted")
		}
	}
}
func TestBearerCredentialSourcesAreUnambiguous(t *testing.T) {
	token := NewRandomToken()
	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	got, err := ParseRequest(req).Credential("key")
	if err != nil || got != token {
		t.Fatalf("Bearer not accepted: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "http://example.invalid/?key="+token, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err = ParseRequest(req).Credential("key"); !errors.Is(err, ErrQueryCredential) {
		t.Fatalf("URL credential accepted: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "http://example.invalid/", strings.NewReader("key="+token))
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err = ParseRequest(req).Credential("key"); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("two sources accepted: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Authorization", "Bearer "+token)
	if _, err = ParseRequest(req).Credential("key"); !errors.Is(err, ErrInvalidAuthorization) {
		t.Fatalf("two headers accepted: %v", err)
	}
}
func TestTokenFormat(t *testing.T) {
	token := NewRandomToken()
	if !IsRandomToken(token) {
		t.Fatal("generated token rejected")
	}
	for _, bad := range []string{"password", strings.Repeat("A", 42), strings.Repeat("A", 44), strings.Repeat("A", 42) + "B", strings.Repeat("+", 43)} {
		if IsRandomToken(bad) {
			t.Fatal("invalid or noncanonical token accepted")
		}
	}
}

func TestBodyLimitStillReturns413BehindHTTPMaxBytesReader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.invalid/", strings.NewReader(strings.Repeat("x", MaxRequestBodyBytes+1)))
	req.ContentLength = -1 // Simulate an unknown-length/chunked request.
	response := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(response, req.Body, MaxRequestBodyBytes)
	err := ParseRequest(req).Validate("key")
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("HTTP body limiter mapped to wrong error: %v", err)
	}
	RequestError(response, err)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got status %d", response.Code)
	}
}
