// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnscheck

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const testWatcherID = "0123456789abcdef0123456789abcdef"

func TestDNSCheckInitializationJoinsRefreshWorker(t *testing.T) {
	provider, err := dnsutil.GenerateDnssecProvider("test.example.", dns.ED25519, 1800)
	if err != nil {
		t.Fatal(err)
	}
	private, err := provider.PrivKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	h := &DnscheckHandler{DnssecProvider: provider, Zone: "test.example.", Ns: []string{"ns.example."}}
	if err := h.InitContext(context.Background(), private[:1]); err == nil {
		t.Fatal("malformed private key did not return an initialization error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.InitContext(ctx, private); err != nil {
		t.Fatal(err)
	}
	if h.soaSig.Load() == nil || h.BadDnssecProvider == nil || h.BadDnssecProvider.KeyTagOverride != provider.SigningKey.KeyTag() {
		t.Fatal("signed diagnostic handler did not initialize both signing modes")
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- h.WaitForRefresh() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("diagnostic SOA refresher survived context cancellation")
	}
}

type testUDPWriter struct{ response *dns.Msg }

func (*testUDPWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (*testUDPWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53000}
}
func (w *testUDPWriter) WriteMsg(m *dns.Msg) error           { w.response = m.Copy(); return nil }
func (*testUDPWriter) Write(b []byte) (int, error)           { return len(b), nil }
func (*testUDPWriter) Close() error                          { return nil }
func (*testUDPWriter) TsigStatus() error                     { return nil }
func (*testUDPWriter) TsigTimersOnly(bool)                   {}
func (*testUDPWriter) Hijack()                               {}
func (*testUDPWriter) ConnectionState() *tls.ConnectionState { return nil }

func newSignedTestHandler(t *testing.T) *DnscheckHandler {
	t.Helper()
	provider, err := dnsutil.GenerateDnssecProvider("test.example.", dns.MLDSA44, 1800)
	if err != nil {
		t.Fatal(err)
	}
	h := &DnscheckHandler{
		DnssecProvider: provider, Zone: "test.example.", Ns: []string{"ns.example."},
		HostMasterMbox: "hostmaster.test.example.", Watchers: &SimpleWatcherHub{MaxSize: 100},
		LargeResponseLimiter: rate.NewLimiter(0, 10), SigningLimiter: rate.NewLimiter(0, 100),
	}
	// Populate the normal cached SOA signature without starting a refresh goroutine.
	sigs, err := provider.Sign(h.SOA(nil, false), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.soaSig.Store(sigs[0].(*dns.RRSIG))
	return h
}

func runDNSQuery(t *testing.T, h *DnscheckHandler, name string, qtype uint16, udpSize uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg).SetQuestion(name, qtype)
	req.SetEdns0(udpSize, true)
	w := new(testUDPWriter)
	h.ServeDNS(w, req)
	if w.response == nil {
		t.Fatal("no response")
	}
	return w.response
}

func TestLargeSignedUDPResponsesCannotBypassLimits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		qname      string
		qtype      uint16
		cap        int
		budget     int
		advertised uint16
		wantRcode  int
		maxBytes   int
	}{
		{"negative default", "1234.test.example.", dns.TypeCAA, 0, 0, 65535, dns.RcodeSuccess, dnsutil.MaxUdpMsgSize},
		{"negative diagnostic exhausted", "1234-notruncate.test.example.", dns.TypeCAA, 4096, 0, 65535, dns.RcodeRefused, dnsutil.MaxUdpMsgSize},
		{"TXT diagnostic exhausted", "1234-txtfill1-notruncate.test.example.", dns.TypeTXT, 4096, 0, 65535, dns.RcodeRefused, dnsutil.MaxUdpMsgSize},
		{"negative safe default", "1234-notruncate.test.example.", dns.TypeCAA, 0, 10, 65535, dns.RcodeSuccess, dnsutil.MaxUdpMsgSize},
		{"negative explicit ceiling", "1234-notruncate.test.example.", dns.TypeCAA, 65535, 10, 65535, dns.RcodeSuccess, 4096},
		{"client ceiling", "1234-notruncate.test.example.", dns.TypeCAA, 4096, 10, 1232, dns.RcodeSuccess, 1232},
		{"DNSKEY default", "test.example.", dns.TypeDNSKEY, 0, 0, 65535, dns.RcodeSuccess, dnsutil.MaxUdpMsgSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSignedTestHandler(t)
			h.MaxDiagnosticUDPSize = tc.cap
			h.LargeResponseLimiter = rate.NewLimiter(0, tc.budget)
			resp := runDNSQuery(t, h, tc.qname, tc.qtype, tc.advertised)
			if resp.Rcode != tc.wantRcode {
				t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
			}
			packed, err := resp.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if len(packed) > tc.maxBytes {
				t.Fatalf("response has %d bytes, maximum %d", len(packed), tc.maxBytes)
			}
			if tc.wantRcode == dns.RcodeSuccess && tc.maxBytes == dnsutil.MaxUdpMsgSize && !resp.Truncated {
				t.Fatal("large ML-DSA answer should request reliable-transport fallback")
			}
		})
	}
}

func TestLargeDiagnosticUDPBudgetsAreByteWeighted(t *testing.T) {
	h := newSignedTestHandler(t)
	h.MaxDiagnosticUDPSize = 4096
	// Enough for the early work admission, but not a multi-packet-size answer.
	h.LargeResponseLimiter = rate.NewLimiter(0, 1)
	resp := runDNSQuery(t, h, "1234-notruncate.test.example.", dns.TypeCAA, 4096)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("expected byte budget to reject large non-TXT answer: %s (%d bytes)", dns.RcodeToString[resp.Rcode], resp.Len())
	}
}

func TestSigningWorkIsLimitedBeforeProof(t *testing.T) {
	h := newSignedTestHandler(t)
	h.SigningLimiter = rate.NewLimiter(0, 0)
	resp := runDNSQuery(t, h, "1234.test.example.", dns.TypeCAA, 1400)
	if resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
		t.Fatalf("signing budget should return a small refusal: %v", resp)
	}
}

type countingWatcher struct{ count atomic.Int64 }

func (w *countingWatcher) Send(*dns.Msg, string, net.Addr, *tls.ConnectionState) { w.count.Add(1) }

func TestWatcherRegistrationIsAtomicAndCleanupIsOwnerBound(t *testing.T) {
	hub := &SimpleWatcherHub{MaxSize: 1}
	var wg sync.WaitGroup
	var successes atomic.Int64
	var ownerMu sync.Mutex
	var releaseOwner func()
	for range 32 {
		wg.Go(func() {
			release, err := hub.Register(testWatcherID, new(countingWatcher))
			if err == nil {
				successes.Add(1)
				ownerMu.Lock()
				releaseOwner = release
				ownerMu.Unlock()
			} else if !errors.Is(err, ErrWatcherExists) {
				t.Errorf("duplicate error: %v", err)
			}
		})
	}
	wg.Wait()
	if successes.Load() != 1 || hub.Size() != 1 {
		t.Fatalf("claims=%d size=%d", successes.Load(), hub.Size())
	}
	if _, err := hub.Register("different", new(countingWatcher)); !errors.Is(err, ErrWatcherCapacity) {
		t.Fatalf("capacity error: %v", err)
	}
	releaseOwner()
	second := new(countingWatcher)
	releaseSecond, err := hub.Register(testWatcherID, second)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseSecond()
	releaseOwner() // Late cleanup must not remove the replacement owner.
	if hub.Get(testWatcherID) != second {
		t.Fatal("stale cleanup removed the current registration")
	}
}

func TestInvalidRequestsNeverReachWatchers(t *testing.T) {
	for _, mutation := range []func(*dns.Msg){
		func(m *dns.Msg) { m.Opcode = dns.OpcodeUpdate },
		func(m *dns.Msg) { m.Question[0].Qclass = dns.ClassCHAOS },
		func(m *dns.Msg) { m.Question[0].Qtype = dns.TypeOPT },
		func(m *dns.Msg) { m.Answer = []dns.RR{&dns.TXT{Txt: []string{"unexpected"}}} },
		func(m *dns.Msg) { m.SetEdns0(1400, true); m.IsEdns0().SetVersion(1) },
	} {
		h := newSignedTestHandler(t)
		watcher := new(countingWatcher)
		release, err := h.Watchers.Register(testWatcherID, watcher)
		if err != nil {
			t.Fatal(err)
		}
		req := new(dns.Msg).SetQuestion(testWatcherID+".test.example.", dns.TypeA)
		mutation(req)
		h.ServeDNS(new(testUDPWriter), req)
		release()
		if watcher.count.Load() != 0 {
			t.Fatal("invalid request reached watcher")
		}
	}
}

func Test128BitWatcherOptions(t *testing.T) {
	for _, id := range []string{testWatcherID, strings.ToUpper(testWatcherID), "1234"} {
		opts := ParseOptions(id + "-badsig")
		if opts == nil || opts.Random != strings.ToLower(id) || !opts.BadSig {
			t.Fatalf("options rejected: %s", id)
		}
	}
	if ParseOptions(testWatcherID+"0") != nil {
		t.Fatal("accepted an oversized query ID")
	}
	for _, id := range []string{"1234", testWatcherID + "0", strings.ToUpper(testWatcherID)} {
		if validWatcherID(id) {
			t.Fatalf("accepted noncanonical watcher ID: %s", id)
		}
	}
	if !validWatcherID(testWatcherID) {
		t.Fatal("valid watcher ID rejected")
	}
}

type testWatcherWriter struct {
	mu       sync.Mutex
	deadline time.Time
	writeErr error
	writes   int
	closed   atomic.Int64
}

func (w *testWatcherWriter) SetWriteDeadline(d time.Time) error {
	w.mu.Lock()
	w.deadline = d
	w.mu.Unlock()
	return nil
}
func (w *testWatcherWriter) WriteMessage(int, []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	return w.writeErr
}
func (w *testWatcherWriter) Close() error { w.closed.Add(1); return nil }
func newTestWatcher(writer watcherWriter, full bool) *WebsocketWatcher {
	return &WebsocketWatcher{conn: writer, full: full, ch: make(chan []byte, WebsocketWatcherBufferLength), done: make(chan struct{})}
}
func testWatchQuery() *dns.Msg {
	return new(dns.Msg).SetQuestion(testWatcherID+".test.example.", dns.TypeA)
}

func TestWatcherSnapshotsExcludeLargePayloadsAndAreBounded(t *testing.T) {
	ws := newTestWatcher(new(testWatcherWriter), true)
	defer ws.Close()
	req := testWatchQuery()
	req.SetEdns0(65535, true)
	req.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: []byte(strings.Repeat("ATTACKER_PAYLOAD", 4000))}}
	for range 1000 {
		ws.Send(req, dnsutil.ProtoUDP, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil)
	}
	if len(ws.ch) != WebsocketWatcherBufferLength {
		t.Fatalf("queue has %d messages", len(ws.ch))
	}
	if ws.queuedBytes > WebsocketWatcherMaxQueueBytes {
		t.Fatalf("queue has %d bytes", ws.queuedBytes)
	}
	encoded := <-ws.ch
	ws.queuedBytes -= len(encoded)
	if len(encoded) > WebsocketWatcherMaxMessage || strings.Contains(string(encoded), "ATTACKER_PAYLOAD") {
		t.Fatal("unbounded EDNS payload entered watcher queue")
	}
	var msg WebsocketWatcherMessage
	if err := json.Unmarshal(encoded, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.QueryName != req.Question[0].Name || msg.UDPSize != 65535 || !strings.Contains(msg.MsgText, "payloads omitted") {
		t.Fatalf("missing bounded diagnostic data: %s", encoded)
	}
}

func TestWatcherWriteFailureClosesConnection(t *testing.T) {
	writer := &testWatcherWriter{writeErr: errors.New("broken connection")}
	ws := newTestWatcher(writer, false)
	ws.Send(testWatchQuery(), dnsutil.ProtoUDP, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil)
	ws.WriteLoop(context.Background())
	if writer.closed.Load() != 1 || writer.deadline.IsZero() {
		t.Fatal("write failure did not close a deadline-bounded connection")
	}
	if time.Until(writer.deadline) > WebsocketWriteWait {
		t.Fatal("write deadline is too distant")
	}
	ws.Send(testWatchQuery(), dnsutil.ProtoUDP, &net.UDPAddr{}, nil)
	if len(ws.ch) != 0 || ws.queuedBytes != 0 {
		t.Fatal("closed watcher retained queued messages")
	}
}

func TestWatcherSendAndShutdownAreRaceFree(t *testing.T) {
	for range 20 {
		ws := newTestWatcher(new(testWatcherWriter), false)
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Go(func() { ws.WriteLoop(ctx) })
		for range 4 {
			wg.Go(func() {
				for range 100 {
					ws.Send(testWatchQuery(), dnsutil.ProtoUDP, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil)
				}
			})
		}
		cancel()
		ws.Close()
		wg.Wait()
		if len(ws.ch) != 0 || ws.queuedBytes != 0 {
			t.Fatal("shutdown left messages queued")
		}
	}
}

func TestWatcherOriginsAndClientIdentity(t *testing.T) {
	h := NewWebsocketHandler(&SimpleWatcherHub{MaxSize: 100})
	for _, tc := range []struct {
		origin  string
		allowed bool
	}{
		{"", true}, {"https://watch.example", true}, {"https://evil.example", false}, {"null", false}, {"https://watch.example@evil.example", false},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://watch.example/watch/"+testWatcherID, nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if h.checkOrigin(req) != tc.allowed {
			t.Errorf("origin=%s", tc.origin)
		}
	}
	h.AllowedOrigins = []string{"https://frontend.example"}
	req := httptest.NewRequest(http.MethodGet, "https://watch.example/watch/"+testWatcherID, nil)
	req.Header.Set("Origin", "https://frontend.example")
	if !h.checkOrigin(req) {
		t.Fatal("explicit browser origin rejected")
	}
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Addr-Client-IP", "203.0.113.4")
	if key, _ := h.clientKey(req); key != "192.0.2.1" {
		t.Fatal("unconfigured proxy header trusted")
	}
	h.TrustedClientIPHeader = "X-Addr-Client-IP"
	if key, _ := h.clientKey(req); key != "203.0.113.4" {
		t.Fatal("configured proxy address not used")
	}
	req.Header.Set("X-Addr-Client-IP", "2001:db8::1234")
	if key, _ := h.clientKey(req); key != "2001:db8::/64" {
		t.Fatal("IPv6 clients not grouped by prefix")
	}
	req.Header.Set("X-Addr-Client-IP", "192.0.2.1, 203.0.113.4")
	if _, err := h.clientKey(req); err == nil {
		t.Fatal("ambiguous proxy address accepted")
	}
}

func TestWatcherAdmissionLimitsReleaseCapacity(t *testing.T) {
	h := NewWebsocketHandler(&SimpleWatcherHub{MaxSize: 100})
	h.MaxPerClient, h.MaxConnections = 1, 2
	first, ok := h.acquireClient("a")
	if !ok {
		t.Fatal("initial client rejected")
	}
	if _, ok := h.acquireClient("a"); ok {
		t.Fatal("per-client limit bypassed")
	}
	second, ok := h.acquireClient("b")
	if !ok {
		t.Fatal("second client rejected")
	}
	if _, ok := h.acquireClient("c"); ok {
		t.Fatal("global limit bypassed")
	}
	first()
	first()
	third, ok := h.acquireClient("c")
	if !ok {
		t.Fatal("released capacity not reusable")
	}
	second()
	third()
	if h.active != 0 || len(h.clients) != 0 {
		t.Fatal("admission records leaked")
	}
}

func TestWebsocketDuplicateCannotReplaceOwner(t *testing.T) {
	hub := &SimpleWatcherHub{MaxSize: 10}
	h := NewWebsocketHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/watch/{watcher}", h)
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/watch/" + testWatcherID
	first, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// The HTTP upgrade can finish before registration, so wait for its owner.
	deadline := time.Now().Add(time.Second)
	for hub.Get(testWatcherID) == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	owner := hub.Get(testWatcherID)
	if owner == nil {
		t.Fatal("watcher was not registered")
	}
	second, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = second.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != 4000 {
		t.Fatalf("duplicate close: %v", err)
	}
	if hub.Get(testWatcherID) != owner {
		t.Fatal("duplicate replaced the owner")
	}
	owner.Send(testWatchQuery(), dnsutil.ProtoUDP, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil)
	first.SetReadDeadline(time.Now().Add(time.Second))
	_, data, err := first.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), testWatcherID) {
		t.Fatalf("unexpected message %s", data)
	}
}

func TestWebsocketRejectsInvalidIDsBeforeUpgrade(t *testing.T) {
	h := NewWebsocketHandler(&SimpleWatcherHub{MaxSize: 10})
	for _, id := range []string{"1234", strings.Repeat("a", 4096)} {
		req := httptest.NewRequest(http.MethodGet, "http://example/watch/"+id, nil)
		req.SetPathValue("watcher", id)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatal(fmt.Sprintf("invalid ID status %d", w.Code))
		}
	}
}

func TestWatcherShutdownClosesHijackedConnectionsAndStopsAdmission(t *testing.T) {
	hub := &SimpleWatcherHub{MaxSize: 10}
	h := NewWebsocketHandler(hub)
	mux := http.NewServeMux()
	mux.Handle("/watch/{watcher}", h)
	server := httptest.NewServer(mux)
	defer server.Close()
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http") + "/watch/" + testWatcherID
	conn, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.Size() != 0 {
		t.Fatal("shutdown retained registered watchers")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("shutdown left a hijacked WebSocket open")
	}
	if _, response, err := websocket.DefaultDialer.Dial(endpoint, nil); err == nil || response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("new admission after shutdown: response=%v err=%v", response, err)
	}
	if err := h.Shutdown(ctx); err != nil {
		t.Fatalf("repeated shutdown: %v", err)
	}
}

func TestWatcherShutdownRespectsDeadlineDuringPendingAdmission(t *testing.T) {
	h := NewWebsocketHandler(&SimpleWatcherHub{MaxSize: 10})
	release, ok := h.acquireClient("pending-upgrade")
	if !ok {
		t.Fatal("initial admission rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := h.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pending shutdown: %v", err)
	}
	release()
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
