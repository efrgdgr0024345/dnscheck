// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dyn

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

func TestDynamicDNSRequiresSafeCredentialAndMutationTransport(t *testing.T) {
	token := httputil.NewRandomToken()
	store := &ttlstore.SimpleTtlStore{}
	h := &HTTPHandler{DataStore: store, Zone: "dyn.example.invalid."}
	for _, tt := range []struct {
		name, method, path, body, credential string
		status                               int
	}{
		{"password", http.MethodPost, "/", `{"ip":"192.0.2.1"}`, "password", 400},
		{"URL secret", http.MethodPost, "/?secret=" + token, `{"ip":"192.0.2.1"}`, "", 400},
		{"GET mutation", http.MethodGet, "/?ip=192.0.2.1", "", token, 405},
		{"duplicate body", http.MethodPost, "/", `{"ip":"192.0.2.1","ip":"192.0.2.1"}`, token, 400},
		{"read derived domain", http.MethodGet, "/", "", token, 200},
		{"update", http.MethodPost, "/", `{"ip":"192.0.2.1"}`, token, 200},
		{"delete", http.MethodDelete, "/", "", token, 204},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.invalid"+tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.credential != "" {
				req.Header.Set("Authorization", "Bearer "+tt.credential)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("got %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("credential response cacheable")
			}
			if tt.status >= 400 {
				keys, err := store.List("")
				if err != nil || len(keys) > 0 {
					t.Fatalf("invalid request mutated state: %v %v", keys, err)
				}
			}
		})
	}
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(token)), h.Zone)
	if exists, err := store.Exists(domain + ":ip4"); err != nil || exists {
		t.Fatal("delete left IPv4 record")
	}
}
