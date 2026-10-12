// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dns2json

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRejectsUnprotectedExternalResolver(t *testing.T) {
	for _, tc := range []struct {
		host, network string
		allow, valid  bool
	}{
		{"192.0.2.1:53", "udp", false, false},
		{"resolver.example:53", "tcp", false, false},
		{"127.0.0.1:5353", "udp", false, true},
		{"[::1]:5353", "tcp", false, true},
		{"resolver.example:853", "tcp-tls", false, true},
		{"192.0.2.1:53", "udp", true, true},
		{"127.0.0.1:53", "invalid", true, false},
	} {
		h := &LookupHandler{Upstream: tc.host, Network: tc.network, AllowInsecure: tc.allow}
		if valid := h.Validate() == nil; valid != tc.valid {
			t.Fatalf("%+v: valid=%v", tc, valid)
		}
	}
}

func lookupRequest(ctx context.Context) *http.Request {
	r := httptest.NewRequest("GET", "/dns/example.test/A", nil).WithContext(ctx)
	r.SetPathValue("name", "example.test")
	r.SetPathValue("type", "A")
	return r
}

func TestLookupCancellationStopsNetworkWait(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := &LookupHandler{Upstream: conn.LocalAddr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, lookupRequest(ctx))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ignored request timeout: %v", elapsed)
	}
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("expected timeout status, got %d", w.Code)
	}
}

func TestTruncatedUDPUsesTCPAndLabelsResolverAssertion(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var udpQueries, tcpQueries atomic.Int32
	udpServer := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		resp := new(dns.Msg).SetReply(r)
		resp.Truncated = true
		w.WriteMsg(resp)
	})}
	tcpServer := &dns.Server{Listener: tcp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		tcpQueries.Add(1)
		resp := new(dns.Msg).SetReply(r)
		resp.AuthenticatedData = true
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.7")}}
		w.WriteMsg(resp)
	})}
	go udpServer.ActivateAndServe()
	go tcpServer.ActivateAndServe()
	defer udpServer.Shutdown()
	defer tcpServer.Shutdown()
	h := &LookupHandler{Upstream: tcp.Addr().String()}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, lookupRequest(context.Background()))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup failed: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		AD                            bool
		UpstreamTransport, Validation string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 || !response.AD || response.UpstreamTransport != "tcp" || response.Validation != "not-validated-locally" {
		t.Fatalf("fallback or trust label incorrect: %+v, UDP=%d TCP=%d", response, udpQueries.Load(), tcpQueries.Load())
	}
}
