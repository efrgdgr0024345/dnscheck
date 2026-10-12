// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package httputil

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type TurnstileClient struct {
	Secret           string
	ExpectedHostname string
	ExpectedAction   string
	HttpClient       http.Client
}

func (c *TurnstileClient) Verify(token string) (bool, error) {
	return c.VerifyContext(context.Background(), token)
}
func (c *TurnstileClient) VerifyContext(ctx context.Context, token string) (bool, error) {
	if c == nil || c.Secret == "" || c.ExpectedHostname == "" {
		return false, errors.New("Turnstile secret and expected hostname must be configured")
	}
	if token == "" || len(token) > 2048 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	values := url.Values{"secret": {c.Secret}, "response": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(values.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, errors.New("Turnstile verification service returned an unsuccessful status")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxRequestBodyBytes+1))
	if err != nil {
		return false, err
	}
	if len(data) > MaxRequestBodyBytes {
		return false, errors.New("Turnstile response too large")
	}
	var body struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	if err = json.Unmarshal(data, &body); err != nil {
		return false, errors.New("invalid Turnstile response")
	}
	action := c.ExpectedAction
	if action == "" {
		action = "claim"
	}
	return body.Success && strings.EqualFold(body.Hostname, c.ExpectedHostname) && body.Action == action, nil
}
