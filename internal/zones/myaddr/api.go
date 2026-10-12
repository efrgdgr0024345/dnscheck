// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package myaddr

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/challenges"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/dyn"
)

const (
	PendingTtl          = 3600
	RegistrationTtl     = 120 * 86400
	registrationRetries = 4
)

var (
	errUnauthorized     = errors.New("invalid or revoked registration key")
	errConcurrentChange = errors.New("registration changed concurrently; retry the request")
)

type RegistrationStatus string

const (
	RegistrationPending   RegistrationStatus = "pending"
	RegistrationActive    RegistrationStatus = "active"
	RegistrationSuspended RegistrationStatus = "suspended"
)

// RegistrationRecord v2 records lifecycle state explicitly. Revision changes
// for every mutation, including same-second renewals, and is part of each CAS.
// Hash is never replaced by an ordinary address/challenge update.
type RegistrationRecord struct {
	Version   int
	Created   uint32
	Updated   uint32
	Hash      string
	Status    RegistrationStatus
	ExpiresAt uint32
	Revision  uint64
}

func (r *RegistrationRecord) Expires() uint32                { return r.ExpiresAt }
func (r *RegistrationRecord) MarshalBinary() ([]byte, error) { return json.Marshal(r) }
func (r *RegistrationRecord) UnmarshalBinary(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		return fmt.Errorf("%w: registration v2 required", ttlstore.ErrLegacyFormat)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ttlstore.ErrLegacyFormat
	}
	if r.Version != 2 || r.Created == 0 || r.Updated < r.Created || r.ExpiresAt <= r.Updated || r.Revision == 0 {
		return ttlstore.ErrLegacyFormat
	}
	switch r.Status {
	case RegistrationPending, RegistrationActive:
		if len(r.Hash) != 64 {
			return ttlstore.ErrLegacyFormat
		}
	case RegistrationSuspended:
		if r.Hash != "" {
			return ttlstore.ErrLegacyFormat
		}
	default:
		return ttlstore.ErrLegacyFormat
	}
	return nil
}
func loadRegistration(name string, store ttlstore.TtlStore) (*RegistrationRecord, []byte, error) {
	data, err := store.Get(name + ":reg")
	if err != nil || data == nil {
		return nil, data, err
	}
	reg := new(RegistrationRecord)
	if err = reg.UnmarshalBinary(data); err != nil {
		return nil, nil, err
	}
	return reg, data, nil
}
func LoadRegistration(name string, store ttlstore.TtlStore) (*RegistrationRecord, error) {
	reg, _, err := loadRegistration(name, store)
	return reg, err
}
func keyHash(key string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(key))) }

// claimRegistration inserts the registration and its key index together. Old
// address/challenge remnants are removed in the same transaction before reuse.
func claimRegistration(name, hash string, store ttlstore.TtlStore) (bool, error) {
	now := uint32(time.Now().Unix())
	reg := &RegistrationRecord{Version: 2, Created: now, Updated: now, Hash: hash, Status: RegistrationPending, ExpiresAt: now + PendingTtl, Revision: 1}
	data, err := reg.MarshalBinary()
	if err != nil {
		return false, err
	}
	return store.Apply([]ttlstore.Condition{{Key: name + ":reg"}, {Key: "hash:" + hash}}, []ttlstore.Mutation{
		{Kind: ttlstore.DeleteKey, Key: name + ":ip4"},
		{Kind: ttlstore.DeleteKey, Key: name + ":ip6"},
		{Kind: ttlstore.DeleteKey, Key: name + ":challenge"},
		{Kind: ttlstore.SetValue, Key: name + ":reg", Value: data, TTL: PendingTtl},
		{Kind: ttlstore.SetValue, Key: "hash:" + hash, Value: []byte(name), TTL: PendingTtl},
	})
}

type ownership struct {
	name string
	hash string
	reg  *RegistrationRecord
	raw  []byte
}

func authorize(key string, store ttlstore.TtlStore) (*ownership, error) {
	if !httputil.IsRandomToken(key) {
		return nil, errUnauthorized
	}
	hash := keyHash(key)
	nameBytes, err := store.Get("hash:" + hash)
	if err != nil {
		return nil, err
	}
	name := string(nameBytes)
	if !IsValidName(name) || name != dnsutil.ToLowerAscii(name) {
		return nil, errUnauthorized
	}
	reg, raw, err := loadRegistration(name, store)
	if err != nil {
		return nil, err
	}
	if reg == nil || reg.Status == RegistrationSuspended || reg.Hash != hash || reg.ExpiresAt <= uint32(time.Now().Unix()) {
		return nil, errUnauthorized
	}
	return &ownership{name: name, hash: hash, reg: reg, raw: raw}, nil
}
func (o *ownership) conditions() []ttlstore.Condition {
	return []ttlstore.Condition{{Key: o.name + ":reg", Value: o.raw}, {Key: "hash:" + o.hash, Value: []byte(o.name)}}
}
func (o *ownership) renew(activate bool) ([]ttlstore.Mutation, error) {
	now := uint32(time.Now().Unix())
	reg := *o.reg
	if reg.ExpiresAt <= now {
		return nil, errUnauthorized
	}
	reg.Updated = now
	reg.Revision++
	if activate {
		reg.Status = RegistrationActive
		reg.ExpiresAt = now + RegistrationTtl
	}
	data, err := reg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ttl := reg.ExpiresAt - now
	return []ttlstore.Mutation{
		{Kind: ttlstore.SetValue, Key: o.name + ":reg", Value: data, TTL: ttl},
		{Kind: ttlstore.SetValue, Key: "hash:" + o.hash, Value: []byte(o.name), TTL: ttl},
	}, nil
}
func deleteMutations(name, hash string) []ttlstore.Mutation {
	ops := []ttlstore.Mutation{
		{Kind: ttlstore.DeleteKey, Key: name + ":reg"},
		{Kind: ttlstore.DeleteKey, Key: name + ":ip4"},
		{Kind: ttlstore.DeleteKey, Key: name + ":ip6"},
		{Kind: ttlstore.DeleteKey, Key: name + ":challenge"},
	}
	if hash != "" {
		ops = append(ops, ttlstore.Mutation{Kind: ttlstore.DeleteKey, Key: "hash:" + hash})
	}
	return ops
}
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthorized):
		http.Error(w, errUnauthorized.Error(), http.StatusForbidden)
	case errors.Is(err, errConcurrentChange):
		http.Error(w, errConcurrentChange.Error(), http.StatusConflict)
	case errors.Is(err, ttlstore.ErrCapacity):
		http.Error(w, "record capacity exceeded; retry later or remove unused records", http.StatusTooManyRequests)
	default:
		log.Printf("[error] myaddr store operation failed: %v", err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}
func IsValidName(s string) bool {
	if len(s) < 6 || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9' && i > 0:
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

type AdminHandler struct{ DataStore ttlstore.TtlStore }

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	httputil.NoStore(w)
	switch req.Method {
	case http.MethodGet, http.MethodDelete, "SUSPEND":
	default:
		w.Header().Set("Allow", "GET, DELETE, SUSPEND")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	values := httputil.ParseRequest(req)
	if err := values.Validate("name"); err != nil {
		httputil.RequestError(w, err)
		return
	}
	name, _ := values.GetString("name")
	if name != "" {
		if !IsValidName(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		name = dnsutil.ToLowerAscii(name)
	}
	if req.Method == http.MethodGet {
		if name != "" {
			reg, err := LoadRegistration(name, h.DataStore)
			if err != nil {
				storeError(w, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(reg)
			return
		}
		keys, err := h.DataStore.List("")
		if err != nil {
			storeError(w, err)
			return
		}
		names := make([]string, 0)
		for _, key := range keys {
			if strings.HasSuffix(key, ":reg") {
				names = append(names, strings.TrimSuffix(key, ":reg"))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
		return
	}
	if name == "" {
		http.Error(w, "must specify name", http.StatusBadRequest)
		return
	}
	for attempt := 0; attempt < registrationRetries; attempt++ {
		reg, raw, err := loadRegistration(name, h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		if reg == nil {
			http.Error(w, "registration not found", http.StatusNotFound)
			return
		}
		ops := deleteMutations(name, reg.Hash)
		if req.Method == "SUSPEND" {
			now := uint32(time.Now().Unix())
			suspended := *reg
			suspended.Status = RegistrationSuspended
			suspended.Hash = ""
			suspended.Updated = now
			suspended.ExpiresAt = now + RegistrationTtl
			suspended.Revision++
			data, err := suspended.MarshalBinary()
			if err != nil {
				storeError(w, err)
				return
			}
			// Replace the registration deletion with the explicit suspension record.
			ops[0] = ttlstore.Mutation{Kind: ttlstore.SetValue, Key: name + ":reg", Value: data, TTL: RegistrationTtl}
		}
		applied, err := h.DataStore.Apply([]ttlstore.Condition{{Key: name + ":reg", Value: raw}}, ops)
		if err != nil {
			storeError(w, err)
			return
		}
		if applied {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	storeError(w, errConcurrentChange)
}

type RegistrationHandler struct {
	DataStore       ttlstore.TtlStore
	TurnstileClient *httputil.TurnstileClient
}

func (h *RegistrationHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	httputil.NoStore(w)
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	values := httputil.ParseRequest(req)
	if req.Method == http.MethodPost {
		if err := values.Validate("name", "challenge"); err != nil {
			httputil.RequestError(w, err)
			return
		}
		name, err := httputil.RequiredString(values, "name")
		if err != nil {
			httputil.RequestError(w, err)
			return
		}
		if !IsValidName(name) {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		challenge, err := httputil.RequiredString(values, "challenge")
		if err != nil {
			httputil.RequestError(w, err)
			return
		}
		verified, err := h.TurnstileClient.VerifyContext(req.Context(), challenge)
		if err != nil {
			log.Print("[error] registration challenge verification unavailable")
			http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
			return
		}
		if !verified {
			http.Error(w, "invalid challenge", http.StatusBadRequest)
			return
		}
		name = dnsutil.ToLowerAscii(name)
		key := httputil.NewRandomToken()
		applied, err := claimRegistration(name, keyHash(key), h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		if !applied {
			http.Error(w, "name already exists", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Name string `json:"name"`
			Key  string `json:"key"`
		}{name, key})
		return
	}
	if err := values.Validate("key"); err != nil {
		httputil.RequestError(w, err)
		return
	}
	key, err := values.Credential("key")
	if err != nil {
		httputil.RequestError(w, err)
		return
	}
	for attempt := 0; attempt < registrationRetries; attempt++ {
		owner, err := authorize(key, h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		if req.Method == http.MethodDelete {
			applied, err := h.DataStore.Apply(owner.conditions(), deleteMutations(owner.name, owner.hash))
			if err != nil {
				storeError(w, err)
				return
			}
			if applied {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			continue
		}
		out := struct {
			Name       string `json:"name"`
			Registered uint32 `json:"registered"`
			Updated    uint32 `json:"updated"`
			Expires    uint32 `json:"expires"`
			IPv4       net.IP `json:"ip4,omitempty"`
			IPv6       net.IP `json:"ip6,omitempty"`
		}{Name: owner.name, Registered: owner.reg.Created, Updated: owner.reg.Updated, Expires: owner.reg.Expires()}
		ip, err := dyn.LoadIPv4(owner.name, h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		if ip != nil {
			out.IPv4 = ip.IP
		}
		ip, err = dyn.LoadIPv6(owner.name, h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		if ip != nil {
			out.IPv6 = ip.IP
		}
		// Recheck ownership and revision after reading the related records.
		current, err := h.DataStore.Apply(owner.conditions(), nil)
		if err != nil {
			storeError(w, err)
			return
		}
		if !current {
			continue
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	storeError(w, errConcurrentChange)
}

type UpdateHandler struct{ DataStore ttlstore.TtlStore }

func (h *UpdateHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	httputil.NoStore(w)
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		w.Header().Set("Allow", "POST, PUT, DELETE")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}
	values := httputil.ParseRequest(req)
	if err := values.Validate("key", "ip", "acme_challenge"); err != nil {
		httputil.RequestError(w, err)
		return
	}
	key, err := values.Credential("key")
	if err != nil {
		httputil.RequestError(w, err)
		return
	}
	ipString, _ := values.GetString("ip")
	challenge, _ := values.GetString("acme_challenge")
	var ip net.IP
	if ipString != "" {
		if ipString == "self" {
			ipString = req.Header.Get("X-Real-IP")
		}
		ip = net.ParseIP(ipString)
		if ip == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
	}
	if challenge != "" && !challenges.IsValidChallenge(challenge) {
		http.Error(w, "invalid acme_challenge", http.StatusBadRequest)
		return
	}
	if req.Method == http.MethodDelete {
		if ip != nil {
			http.Error(w, "delete removes both address families; do not specify ip", http.StatusBadRequest)
			return
		}
	} else if (ip == nil) == (challenge == "") {
		http.Error(w, "specify exactly one of ip and acme_challenge", http.StatusBadRequest)
		return
	}
	for attempt := 0; attempt < registrationRetries; attempt++ {
		owner, err := authorize(key, h.DataStore)
		if err != nil {
			storeError(w, err)
			return
		}
		ops, err := owner.renew(req.Method != http.MethodDelete)
		if err != nil {
			storeError(w, err)
			return
		}
		if req.Method == http.MethodDelete {
			if challenge != "" {
				ops = append(ops, ttlstore.Mutation{Kind: ttlstore.RemoveValue, Key: owner.name + ":challenge", Value: []byte(challenge)})
			} else {
				ops = append(ops, ttlstore.Mutation{Kind: ttlstore.DeleteKey, Key: owner.name + ":ip4"}, ttlstore.Mutation{Kind: ttlstore.DeleteKey, Key: owner.name + ":ip6"})
			}
		} else if ip != nil {
			suffix := ":ip6"
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
				suffix = ":ip4"
			}
			data, err := (&dyn.AddressRecord{Updated: uint32(time.Now().Unix()), IP: ip}).MarshalBinary()
			if err != nil {
				storeError(w, err)
				return
			}
			ops = append(ops, ttlstore.Mutation{Kind: ttlstore.SetValue, Key: owner.name + suffix, Value: data, TTL: dyn.AddressTtl})
		} else {
			ops = append(ops, ttlstore.Mutation{Kind: ttlstore.AddValue, Key: owner.name + ":challenge", Value: []byte(challenge), TTL: challenges.ChallengeTtl, MaxValues: challenges.MaxChallengesPerName})
		}
		applied, err := h.DataStore.Apply(owner.conditions(), ops)
		if err != nil {
			storeError(w, err)
			return
		}
		if applied {
			if req.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintln(w, "OK")
			}
			return
		}
	}
	storeError(w, errConcurrentChange)
}
