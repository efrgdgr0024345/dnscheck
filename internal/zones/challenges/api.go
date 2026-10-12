// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package challenges

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
)

const ChallengeTtl = 120
const MaxChallengesPerName = 8

type HTTPHandler struct {
	ChallengeStore ttlstore.TtlStore
	Zone           string
}

func IsValidChallenge(s string) bool { return httputil.IsRandomToken(s) }

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	httputil.NoStore(w)
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	values := httputil.ParseRequest(req)
	if err := values.Validate("secret", "txt"); err != nil {
		httputil.RequestError(w, err)
		return
	}
	secret, err := values.Credential("secret")
	if err != nil {
		httputil.RequestError(w, err)
		return
	}
	if !httputil.IsRandomToken(secret) {
		http.Error(w, "secret must be a generated 32-byte base64url token (43 characters)", http.StatusBadRequest)
		return
	}
	txt, _ := values.GetString("txt")
	if req.Method == http.MethodGet {
		if vals, _ := values.Values("txt"); len(vals) > 0 {
			w.Header().Set("Allow", "POST, PUT")
			http.Error(w, "GET is read-only; use POST or PUT to add a challenge", http.StatusMethodNotAllowed)
			return
		}
	}
	if txt != "" && !IsValidChallenge(txt) {
		http.Error(w, "invalid txt challenge", http.StatusBadRequest)
		return
	}
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(secret)), h.Zone)
	if req.Method == http.MethodDelete {
		if txt == "" {
			http.Error(w, "must specify txt to delete one challenge", http.StatusBadRequest)
			return
		}
		if err = h.ChallengeStore.Remove(domain, []byte(txt)); err != nil {
			writeStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if txt == "" {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, domain)
		return
	}
	_, err = h.ChallengeStore.Apply(nil, []ttlstore.Mutation{{Kind: ttlstore.AddValue, Key: domain, Value: []byte(txt), TTL: ChallengeTtl, MaxValues: MaxChallengesPerName}})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "OK")
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, ttlstore.ErrCapacity) {
		http.Error(w, "challenge capacity exceeded; remove an old challenge or retry after expiry", http.StatusTooManyRequests)
		return
	}
	log.Printf("[error] challenge store operation failed: %v", err)
	http.Error(w, "server error", http.StatusInternalServerError)
}
