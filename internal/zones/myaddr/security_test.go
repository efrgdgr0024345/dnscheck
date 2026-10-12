// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package myaddr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
	"github.com/valkey-io/valkey-go"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (f testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func testCaptcha() *httputil.TurnstileClient {
	return &httputil.TurnstileClient{Secret: "isolated-test", ExpectedHostname: "example.invalid", ExpectedAction: "claim", HttpClient: http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"success":true,"hostname":"example.invalid","action":"claim"}`)), Request: req}, nil
	})}}
}
func forBackends(t *testing.T, fn func(*testing.T, ttlstore.TtlStore, ttlstore.TtlStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { s := &ttlstore.SimpleTtlStore{}; fn(t, s, s) })
	t.Run("valkey", func(t *testing.T) {
		addr := os.Getenv("DNSCHECK_TEST_VALKEY_ADDR")
		if addr == "" {
			t.Skip("set DNSCHECK_TEST_VALKEY_ADDR to an isolated local Valkey; test clears DB14")
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			t.Fatal("integration tests require an explicit loopback address")
		}
		client := func() *ttlstore.ValkeyClient {
			c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, SelectDB: 14, ForceSingleClient: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			return &ttlstore.ValkeyClient{Client: c}
		}
		a, b := client(), client()
		if err := a.Do(context.Background(), a.B().Flushdb().Build()).Error(); err != nil {
			t.Fatal(err)
		}
		fn(t, a, b)
	})
}
func seedName(t *testing.T, name string, s ttlstore.TtlStore) string {
	t.Helper()
	key := httputil.NewRandomToken()
	ok, err := claimRegistration(name, keyHash(key), s)
	if err != nil || !ok {
		t.Fatalf("cannot seed registration: %v %v", ok, err)
	}
	return key
}
func request(method, path, body, key string) *http.Request {
	req := httptest.NewRequest(method, "http://example.invalid"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	return req
}
func serve(h http.Handler, method, path, body, key string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(method, path, body, key))
	return w
}
func waitFor(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", label)
	}
}

type claimBarrier struct {
	ttlstore.TtlStore
	name    string
	arrived chan struct{}
	release chan struct{}
}

func (b *claimBarrier) Apply(checks []ttlstore.Condition, ops []ttlstore.Mutation) (bool, error) {
	for _, c := range checks {
		if c.Key == b.name+":reg" && c.Value == nil {
			b.arrived <- struct{}{}
			<-b.release
			break
		}
	}
	return b.TtlStore.Apply(checks, ops)
}
func TestConcurrentClaimsOnlyIssueOneOwnerKey(t *testing.T) {
	forBackends(t, func(t *testing.T, a, b ttlstore.TtlStore) {
		const name = "race-name"
		arrived := make(chan struct{}, 2)
		release := make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		stores := []ttlstore.TtlStore{&claimBarrier{a, name, arrived, release}, &claimBarrier{b, name, arrived, release}}
		responses := make(chan *httptest.ResponseRecorder, 2)
		for i := range stores {
			go func(i int) {
				h := &RegistrationHandler{DataStore: stores[i], TurnstileClient: testCaptcha()}
				responses <- serve(h, http.MethodPost, "/reg", fmt.Sprintf(`{"name":%q,"challenge":"independent-%d"}`, name, i), "")
			}(i)
		}
		waitFor(t, arrived, "first claim")
		waitFor(t, arrived, "second claim")
		close(release)
		var winner string
		success, conflict := 0, 0
		for i := 0; i < 2; i++ {
			select {
			case w := <-responses:
				switch w.Code {
				case http.StatusOK:
					success++
					var out struct{ Name, Key string }
					if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					winner = out.Key
					if w.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("new key response is cacheable")
					}
				case http.StatusConflict:
					conflict++
				default:
					t.Fatalf("claim status %d: %s", w.Code, w.Body.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("claim did not finish")
			}
		}
		if success != 1 || conflict != 1 {
			t.Fatalf("got %d owners and %d conflicts", success, conflict)
		}
		keys, err := a.List("hash:")
		if err != nil || len(keys) != 1 {
			t.Fatalf("orphan reverse keys: %v %v", keys, err)
		}
		w := serve(&UpdateHandler{DataStore: b}, http.MethodPost, "/update", `{"ip":"192.0.2.10"}`, winner)
		if w.Code != http.StatusOK {
			t.Fatalf("winner cannot update: %d %s", w.Code, w.Body.String())
		}
	})
}

func TestStaleReverseMappingCannotReadUpdateOrDelete(t *testing.T) {
	forBackends(t, func(t *testing.T, a, b ttlstore.TtlStore) {
		const name = "owner-name"
		owner := seedName(t, name, a)
		stale := httputil.NewRandomToken()
		if err := a.Set("hash:"+keyHash(stale), []byte(name), RegistrationTtl); err != nil {
			t.Fatal(err)
		}
		tests := []struct {
			h            http.Handler
			method, body string
		}{
			{&RegistrationHandler{DataStore: b}, http.MethodGet, ""},
			{&RegistrationHandler{DataStore: b}, http.MethodDelete, ""},
			{&UpdateHandler{DataStore: b}, http.MethodPost, `{"ip":"192.0.2.20"}`},
		}
		for _, tt := range tests {
			w := serve(tt.h, tt.method, "/", tt.body, stale)
			if w.Code != http.StatusForbidden {
				t.Fatalf("stale key accepted by %s: %d %s", tt.method, w.Code, w.Body.String())
			}
		}
		reg, err := LoadRegistration(name, a)
		if err != nil || reg == nil || reg.Hash != keyHash(owner) {
			t.Fatalf("current owner changed: %v", err)
		}
	})
}

type commitBarrier struct {
	ttlstore.TtlStore
	name    string
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *commitBarrier) Apply(checks []ttlstore.Condition, ops []ttlstore.Mutation) (bool, error) {
	if len(ops) > 0 {
		for _, c := range checks {
			if c.Key == b.name+":reg" && c.Value != nil {
				b.once.Do(func() { close(b.entered); <-b.release })
				break
			}
		}
	}
	return b.TtlStore.Apply(checks, ops)
}
func TestInFlightMutationCannotUndoSuspension(t *testing.T) {
	for _, kind := range []string{"ip", "challenge"} {
		t.Run(kind, func(t *testing.T) {
			forBackends(t, func(t *testing.T, a, b ttlstore.TtlStore) {
				const name = "suspend-name"
				key := seedName(t, name, a)
				barrier := &commitBarrier{TtlStore: a, name: name, entered: make(chan struct{}), release: make(chan struct{})}
				defer func() {
					select {
					case <-barrier.release:
					default:
						close(barrier.release)
					}
				}()
				body := `{"ip":"192.0.2.50"}`
				if kind == "challenge" {
					body = fmt.Sprintf(`{"acme_challenge":%q}`, httputil.NewRandomToken())
				}
				done := make(chan struct{})
				var update *httptest.ResponseRecorder
				go func() {
					defer close(done)
					update = serve(&UpdateHandler{DataStore: barrier}, http.MethodPost, "/update", body, key)
				}()
				waitFor(t, barrier.entered, "update awaiting commit")
				admin := serve(&AdminHandler{DataStore: b}, "SUSPEND", "/admin?name="+name, "", "")
				if admin.Code != http.StatusNoContent {
					t.Fatalf("suspension failed: %d %s", admin.Code, admin.Body.String())
				}
				close(barrier.release)
				waitFor(t, done, "update completion")
				if update.Code != http.StatusForbidden {
					t.Fatalf("revoked update accepted: %d %s", update.Code, update.Body.String())
				}
				reg, err := LoadRegistration(name, b)
				if err != nil || reg == nil || reg.Status != RegistrationSuspended || reg.Hash != "" {
					t.Fatalf("suspension was undone: %+v %v", reg, err)
				}
				for _, dataKey := range []string{"hash:" + keyHash(key), name + ":ip4", name + ":ip6", name + ":challenge"} {
					exists, err := b.Exists(dataKey)
					if err != nil || exists {
						t.Fatalf("revoked state restored at %s: %v", dataKey, err)
					}
				}
			})
		})
	}
}
func TestOldDeleteCannotRemoveAReclaimedName(t *testing.T) {
	forBackends(t, func(t *testing.T, a, b ttlstore.TtlStore) {
		const name = "reuse-name"
		oldKey := seedName(t, name, a)
		barrier := &commitBarrier{TtlStore: a, name: name, entered: make(chan struct{}), release: make(chan struct{})}
		defer func() {
			select {
			case <-barrier.release:
			default:
				close(barrier.release)
			}
		}()
		done := make(chan struct{})
		var oldDelete *httptest.ResponseRecorder
		go func() {
			defer close(done)
			oldDelete = serve(&RegistrationHandler{DataStore: barrier}, http.MethodDelete, "/reg", "", oldKey)
		}()
		waitFor(t, barrier.entered, "old deletion")
		admin := serve(&AdminHandler{DataStore: b}, http.MethodDelete, "/admin?name="+name, "", "")
		if admin.Code != http.StatusNoContent {
			t.Fatalf("admin delete failed: %d", admin.Code)
		}
		newKey := seedName(t, name, b)
		close(barrier.release)
		waitFor(t, done, "old deletion completion")
		if oldDelete.Code != http.StatusForbidden {
			t.Fatalf("stale deletion accepted: %d", oldDelete.Code)
		}
		reg, err := LoadRegistration(name, b)
		if err != nil || reg == nil || reg.Hash != keyHash(newKey) {
			t.Fatalf("new ownership lost: %+v %v", reg, err)
		}
	})
}
func TestClaimQuotaFailureLeavesNoRegistrationOrIndex(t *testing.T) {
	forBackends(t, func(t *testing.T, a, _ ttlstore.TtlStore) {
		switch s := a.(type) {
		case *ttlstore.SimpleTtlStore:
			s.MaxSize = 1
		case *ttlstore.ValkeyClient:
			s.MaxSize = 1
		}
		h := &RegistrationHandler{DataStore: a, TurnstileClient: testCaptcha()}
		w := serve(h, http.MethodPost, "/reg", `{"name":"quota-name","challenge":"valid-test"}`, "")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("expected quota failure: %d %s", w.Code, w.Body.String())
		}
		keys, err := a.List("")
		if err != nil || len(keys) != 0 {
			t.Fatalf("partial claim persisted: %v %v", keys, err)
		}
	})
}
func TestGetCannotUpdateAndExpiryIsExplicit(t *testing.T) {
	forBackends(t, func(t *testing.T, a, _ ttlstore.TtlStore) {
		key := seedName(t, "expiry-name", a)
		w := serve(&UpdateHandler{DataStore: a}, http.MethodGet, "/update?ip=192.0.2.1", "", key)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET mutation accepted: %d", w.Code)
		}
		w = serve(&UpdateHandler{DataStore: a}, http.MethodPost, "/update", `{"ip":"192.0.2.1"}`, key)
		if w.Code != http.StatusOK {
			t.Fatalf("update failed: %d %s", w.Code, w.Body.String())
		}
		reg, err := LoadRegistration("expiry-name", a)
		if err != nil || reg == nil || reg.Status != RegistrationActive || reg.Expires() != reg.Updated+RegistrationTtl {
			t.Fatalf("incorrect active expiration: %+v %v", reg, err)
		}
		// Equal timestamps must not cause an active record to report pending TTL.
		reg.Created = reg.Updated
		if reg.Expires() != reg.Updated+RegistrationTtl {
			t.Fatal("timestamp equality changed lifecycle")
		}
	})
}
func TestRegisteredChallengesAreUniqueBoundedAndDeletedIndividually(t *testing.T) {
	forBackends(t, func(t *testing.T, a, _ ttlstore.TtlStore) {
		const name = "acme-name"
		key := seedName(t, name, a)
		handler := &UpdateHandler{DataStore: a}
		tokens := make([]string, 9)
		for i := range tokens {
			tokens[i] = httputil.NewRandomToken()
		}
		for i := 0; i < 20; i++ {
			w := serve(handler, http.MethodPost, "/update", fmt.Sprintf(`{"acme_challenge":%q}`, tokens[0]), key)
			if w.Code != http.StatusOK {
				t.Fatalf("duplicate refresh failed: %d %s", w.Code, w.Body.String())
			}
		}
		for i := 1; i < 8; i++ {
			w := serve(handler, http.MethodPost, "/update", fmt.Sprintf(`{"acme_challenge":%q}`, tokens[i]), key)
			if w.Code != http.StatusOK {
				t.Fatalf("challenge add failed: %d %s", w.Code, w.Body.String())
			}
		}
		regBefore, err := LoadRegistration(name, a)
		if err != nil {
			t.Fatal(err)
		}
		w := serve(handler, http.MethodPost, "/update", fmt.Sprintf(`{"acme_challenge":%q}`, tokens[8]), key)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("ninth challenge accepted: %d", w.Code)
		}
		regAfter, err := LoadRegistration(name, a)
		if err != nil || regAfter.Revision != regBefore.Revision {
			t.Fatal("failed challenge partially renewed registration")
		}
		w = serve(handler, http.MethodDelete, "/update", fmt.Sprintf(`{"acme_challenge":%q}`, tokens[0]), key)
		if w.Code != http.StatusNoContent {
			t.Fatalf("single deletion failed: %d %s", w.Code, w.Body.String())
		}
		vals, err := a.Values(name + ":challenge")
		if err != nil || len(vals) != 7 {
			t.Fatalf("challenge set incorrect: %d %v", len(vals), err)
		}
		for _, v := range vals {
			if string(v) == tokens[0] {
				t.Fatal("deleted challenge still present")
			}
		}
	})
}
