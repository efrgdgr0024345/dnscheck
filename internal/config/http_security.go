// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// Administrative access is a separate, opt-in listener. A random credential is
// required even for clients that have filesystem access to the private socket.
func loadAdminToken(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open administrative token file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("administrative token must be a regular file accessible only by its owner (mode 0600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 {
		return "", errors.New("cannot read administrative token file or token is too large")
	}
	token := strings.TrimSpace(string(b))
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 || len(token) != 43 {
		return "", errors.New("administrative token must be 32 random bytes encoded as unpadded base64url")
	}
	return token, nil
}

func requireAdminToken(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") || token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "administrative authentication required", http.StatusUnauthorized)
			return
		}
		got := sha256.Sum256([]byte(strings.TrimPrefix(auth[0], "Bearer ")))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "administrative authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Link", "<https://github.com/efrgdgr0024345/dnscheck>; rel=\"source\"")
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func listenUnixSocket(path string, mode os.FileMode) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket filesystem entry")
		}
		conn, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("socket is already accepting connections")
		}
		// Remove only a stale socket. A permission error must not be treated as
		// evidence that the socket is unused.
		if !errors.Is(dialErr, os.ErrNotExist) && !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot verify existing socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
