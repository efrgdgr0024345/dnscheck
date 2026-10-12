// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dyn

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
)

const AddressTtl = 90 * 86400

type AddressRecord struct {
	Updated uint32
	IP      net.IP
}

func (r *AddressRecord) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 4+len(r.IP))
	binary.BigEndian.PutUint32(data, r.Updated)
	copy(data[4:], r.IP)
	return
}

func (r *AddressRecord) UnmarshalBinary(data []byte) error {
	if !(len(data) == 8 || len(data) == 20) {
		return fmt.Errorf("invalid AddressRecord length (%d)", len(data))
	}
	r.Updated = binary.BigEndian.Uint32(data)
	r.IP = make(net.IP, len(data)-4)
	copy(r.IP, data[4:])
	return nil
}

func LoadIPv4(name string, store ttlstore.TtlStore) (ip *AddressRecord, err error) {
	var data []byte
	data, err = store.Get(name + ":ip4")
	if err == nil && data != nil {
		ip = new(AddressRecord)
		err = ip.UnmarshalBinary(data)
	}
	return
}

func LoadIPv6(name string, store ttlstore.TtlStore) (ip *AddressRecord, err error) {
	var data []byte
	data, err = store.Get(name + ":ip6")
	if err == nil && data != nil {
		ip = new(AddressRecord)
		err = ip.UnmarshalBinary(data)
	}
	return
}

func UpdateIP(name string, ip net.IP, store ttlstore.TtlStore) error {
	var suffix string
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		suffix = ":ip4"
	} else {
		suffix = ":ip6"
	}
	data, err := (&AddressRecord{
		Updated: uint32(time.Now().Unix()),
		IP:      ip,
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return store.Set(name+suffix, data, AddressTtl)
}

type HTTPHandler struct {
	DataStore ttlstore.TtlStore
	Zone      string
}

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
	if err := values.Validate("secret", "ip"); err != nil {
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
	ipStr, _ := values.GetString("ip")
	if req.Method == http.MethodGet {
		if vals, _ := values.Values("ip"); len(vals) > 0 {
			w.Header().Set("Allow", "POST, PUT")
			http.Error(w, "GET is read-only; use POST or PUT to update an address", http.StatusMethodNotAllowed)
			return
		}
	}
	var ip net.IP
	if ipStr != "" {
		if ipStr == "self" {
			ipStr = req.Header.Get("X-Real-IP")
		}
		ip = net.ParseIP(ipStr)
		if ip == nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
	}
	domain := fmt.Sprintf("%x.%s", sha256.Sum224([]byte(secret)), h.Zone)
	if req.Method == http.MethodDelete {
		if ipStr != "" {
			http.Error(w, "delete removes both address families; do not specify ip", http.StatusBadRequest)
			return
		}
		_, err = h.DataStore.Apply(nil, []ttlstore.Mutation{{Kind: ttlstore.DeleteKey, Key: domain + ":ip4"}, {Kind: ttlstore.DeleteKey, Key: domain + ":ip6"}})
		if err != nil {
			writeStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ip == nil {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, domain)
		return
	}
	if err = UpdateIP(domain, ip, h.DataStore); err != nil {
		writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "OK")
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, ttlstore.ErrCapacity) {
		http.Error(w, "record capacity exceeded; retry later", http.StatusTooManyRequests)
		return
	}
	log.Printf("[error] dynamic DNS store operation failed: %v", err)
	http.Error(w, "server error", http.StatusInternalServerError)
}
