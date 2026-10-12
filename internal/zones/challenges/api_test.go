// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package challenges

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
)

func TestChallengeAPIIsReadOnlyForGetAndBoundsUniqueValues(t *testing.T) {
	secret := httputil.NewRandomToken()
	store := &ttlstore.SimpleTtlStore{}
	h := &HTTPHandler{ChallengeStore: store, Zone: "challenge.example.invalid."}
	call := func(method, path, body, credential string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://example.invalid"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	token := httputil.NewRandomToken()
	if w := call(http.MethodGet, "/?txt="+token, "", secret); w.Code != 405 {
		t.Fatalf("GET mutation accepted: %d", w.Code)
	}
	if w := call(http.MethodPost, "/?secret="+secret, fmt.Sprintf(`{"txt":%q}`, token), ""); w.Code != 400 {
		t.Fatalf("URL credential accepted: %d", w.Code)
	}
	if w := call(http.MethodPost, "/", fmt.Sprintf(`{"txt":%q}`, token), "password"); w.Code != 400 {
		t.Fatalf("password accepted: %d", w.Code)
	}
	if w := call(http.MethodGet, "/", "", secret); w.Code != 200 {
		t.Fatalf("domain read failed: %d", w.Code)
	}
	for i := 0; i < 25; i++ {
		if w := call(http.MethodPut, "/", fmt.Sprintf(`{"txt":%q}`, token), secret); w.Code != 201 {
			t.Fatalf("idempotent refresh failed: %d %s", w.Code, w.Body.String())
		}
	}
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(secret)), h.Zone)
	for i := 1; i < MaxChallengesPerName; i++ {
		if w := call(http.MethodPost, "/", fmt.Sprintf(`{"txt":%q}`, httputil.NewRandomToken()), secret); w.Code != 201 {
			t.Fatalf("add failed: %d %s", w.Code, w.Body.String())
		}
	}
	if w := call(http.MethodPost, "/", fmt.Sprintf(`{"txt":%q}`, httputil.NewRandomToken()), secret); w.Code != 429 {
		t.Fatalf("unbounded challenge set: %d", w.Code)
	}
	if w := call(http.MethodDelete, "/", fmt.Sprintf(`{"txt":%q}`, token), secret); w.Code != 204 {
		t.Fatalf("individual cleanup failed: %d", w.Code)
	}
	values, err := store.Values(domain)
	if err != nil || len(values) != MaxChallengesPerName-1 {
		t.Fatalf("unexpected challenge count: %d %v", len(values), err)
	}
	for _, value := range values {
		if string(value) == token {
			t.Fatal("deleted challenge retained")
		}
	}
}
