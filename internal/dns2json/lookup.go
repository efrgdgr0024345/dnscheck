// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dns2json

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const (
	LookupTimeout        = 5 * time.Second
	LookupResponseMaxTtl = 86400
	MaxUdpMsgSize        = 1400
)

type LookupHandler struct {
	Upstream      string
	Network       string
	TLSName       string
	AllowInsecure bool
	once          sync.Once
	limiter       *rate.Limiter
	active        chan struct{}
}

// Validate rejects an unauthenticated connection to an external resolver unless
// the operator has explicitly opted in. A local validating resolver is allowed.
func (h *LookupHandler) Validate() error {
	host, _, err := net.SplitHostPort(h.Upstream)
	if err != nil {
		return fmt.Errorf("LookupUpstream must be host:port: %w", err)
	}
	network := h.Network
	if network == "" {
		network = "udp"
	}
	switch network {
	case "udp", "tcp":
		ip := net.ParseIP(host)
		if !h.AllowInsecure && (ip == nil || !ip.IsLoopback()) {
			return errors.New("plaintext DNS lookup requires a loopback resolver; configure tcp-tls or explicitly allow insecure upstream DNS")
		}
	case "tcp-tls":
	default:
		return errors.New("LookupNetwork must be udp, tcp or tcp-tls")
	}
	return nil
}

func (h *LookupHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.Validate(); err != nil {
		http.Error(w, "DNS lookup upstream is not configured safely", http.StatusServiceUnavailable)
		return
	}
	h.once.Do(func() {
		h.limiter = rate.NewLimiter(20, 40)
		h.active = make(chan struct{}, 32)
	})
	if !h.limiter.Allow() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "lookup rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	select {
	case h.active <- struct{}{}:
		defer func() { <-h.active }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many active lookups", http.StatusTooManyRequests)
		return
	}
	qname := req.PathValue("name")
	if _, ok := dns.IsDomainName(qname); !ok {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	qtype := dns.StringToType[strings.ToUpper(req.PathValue("type"))]
	if qtype == 0 {
		http.Error(w, "invalid type", http.StatusBadRequest)
		return
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.SetEdns0(MaxUdpMsgSize, true)
	msg.AuthenticatedData = true // request the resolver's AD assertion, not local validation
	network := h.Network
	if network == "" {
		network = "udp"
	}
	client := &dns.Client{Net: network, Timeout: LookupTimeout}
	if network == "tcp-tls" {
		client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: h.TLSName}
	}
	ctx, cancel := context.WithTimeout(req.Context(), LookupTimeout)
	defer cancel()
	received, _, err := client.ExchangeContext(ctx, msg, h.Upstream)
	if network == "udp" && ctx.Err() == nil && (err != nil || (received != nil && received.Truncated)) {
		// retry over tcp
		client.Net = "tcp"
		received, _, err = client.ExchangeContext(ctx, msg, h.Upstream)
	}
	if err != nil || received == nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			http.Error(w, "dns timeout", http.StatusGatewayTimeout)
		} else {
			log.Printf("[error] dns2json.LookupHandler.ServeHTTP: Exchange: %v", err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}
	type record struct {
		Name string `json:"name"`
		Type uint16 `json:"type"`
		Data string `json:"data"`
	}
	type response struct {
		Status            int
		AD                bool
		TC                bool
		UpstreamTransport string
		Validation        string
		Answer            []record `json:",omitempty"`
		Authority         []record `json:",omitempty"`
	}
	maxAge := uint32(LookupResponseMaxTtl)
	resp := &response{Status: received.Rcode, AD: received.AuthenticatedData, TC: received.Truncated, UpstreamTransport: client.Net, Validation: "not-validated-locally"}
	if len(received.Answer) > 0 {
		resp.Answer = make([]record, len(received.Answer))
		for i, rr := range received.Answer {
			hdr := rr.Header()
			if hdr.Ttl < maxAge {
				maxAge = hdr.Ttl
			}
			resp.Answer[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	if len(received.Ns) > 0 {
		resp.Authority = make([]record, len(received.Ns))
		for i, rr := range received.Ns {
			hdr := rr.Header()
			if hdr.Ttl < maxAge {
				maxAge = hdr.Ttl
			}
			if hdr.Rrtype == dns.TypeSOA && len(received.Answer) == 0 {
				if rr.(*dns.SOA).Minttl < maxAge {
					maxAge = rr.(*dns.SOA).Minttl
				}
			}
			resp.Authority[i] = record{hdr.Name, hdr.Rrtype, rr.String()[len(hdr.String()):]}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if (resp.Status == dns.RcodeSuccess || resp.Status == dns.RcodeNameError) &&
		(len(resp.Answer) > 0 || len(resp.Authority) > 0) {
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(maxAge), 10))
	}
	json.NewEncoder(w).Encode(resp)
}
