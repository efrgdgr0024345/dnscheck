// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAdministrativeAuthentication(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	called := false
	handler := requireAdminToken(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name, authorization, query string
		want                       int
	}{
		{"missing", "", "", http.StatusUnauthorized},
		{"wrong", "Bearer wrong", "", http.StatusUnauthorized},
		{"query credential", "", "?token=" + token, http.StatusUnauthorized},
		{"correct", "Bearer " + token, "", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest("GET", "/admin/myaddr"+tc.query, nil)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want || called != (tc.want == http.StatusNoContent) {
				t.Fatalf("status=%d, handler called=%v", w.Code, called)
			}
		})
	}
	req := httptest.NewRequest("GET", "/admin/myaddr", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate credentials accepted: %d", w.Code)
	}
}

func TestAdminTokenFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.token")
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadAdminToken(path); err != nil || got != token {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminToken(path); err == nil {
		t.Fatal("accepted a publicly readable token")
	}
}

func TestSocketDoesNotOverwriteFilesOrActiveListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenUnixSocket(path, 0660); err == nil {
		ln.Close()
		t.Fatal("replaced a regular file")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ln, err := listenUnixSocket(path, 0660)
	if err != nil {
		if os.Getenv("DNSCHECK_REQUIRE_UNIX_SOCKETS") != "1" && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EAFNOSUPPORT)) {
			t.Skipf("executor does not permit Unix sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer ln.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0660 {
		t.Fatalf("incorrect socket permissions: %v", err)
	}
	if other, err := listenUnixSocket(path, 0660); err == nil {
		other.Close()
		t.Fatal("replaced an active socket")
	}
}
