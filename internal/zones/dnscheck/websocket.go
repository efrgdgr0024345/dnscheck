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
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
)

const (
	WebsocketWatcherBufferLength  = 64
	WebsocketWatcherMaxQueueBytes = 256 * 1024
	WebsocketWatcherMaxMessage    = 8 * 1024
	WebsocketWatcherMaxLife       = 2 * time.Minute
	WebsocketWriteWait            = time.Second
	DefaultMaxWatchersPerClient   = 4
	DefaultMaxWatcherConnections  = 100
)

// WebsocketWatcherMessage is a bounded snapshot of a validated query. It does
// not retain the original DNS message, arbitrary EDNS payloads, or TLS state.
// A public query ID correlates observations; it does not authenticate the
// resolver or the client-subnet value supplied by that resolver.
type WebsocketWatcherMessage struct {
	Time                  uint32 `json:"time"`
	Proto                 string `json:"proto"`
	RemoteIP              string `json:"remoteIp"`
	RemotePort            int    `json:"remotePort"`
	QueryName             string `json:"qname"`
	QueryType             string `json:"qtype"`
	MsgText               string `json:"msgText,omitempty"`
	IsEdns0               bool   `json:"isEdns0,omitempty"`
	UDPSize               uint16 `json:"udpSize,omitempty"`
	ClientSubnet          string `json:"clientSubnet,omitempty"`
	TLSVersion            string `json:"tlsVersion,omitempty"`
	TLSCipherSuite        string `json:"tlsCipherSuite,omitempty"`
	TLSNamedGroup         string `json:"tlsNamedGroup,omitempty"`
	TLSServerName         string `json:"tlsServerName,omitempty"`
	TLSNegotiatedProtocol string `json:"tlsNegotiatedProtocol,omitempty"`
	TLSDidResume          bool   `json:"tlsDidResume,omitempty"`
	QUICVersion           string `json:"quicVersion,omitempty"`
	Used0RTT              bool   `json:"used0RTT,omitempty"`
}

func snapshotQuery(req *dns.Msg, proto string, remoteAddr net.Addr, connState *tls.ConnectionState, full bool) *WebsocketWatcherMessage {
	if req == nil || req.Response || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 ||
		len(req.Answer) != 0 || len(req.Ns) != 0 || len(req.Extra) > 2 {
		return nil
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET || len(q.Name) > 1024 {
		return nil
	}
	if _, ok := dns.IsDomainName(q.Name); !ok {
		return nil
	}
	msg := &WebsocketWatcherMessage{
		Time: uint32(time.Now().Unix()), Proto: proto,
		QueryName: q.Name, QueryType: dns.Type(q.Qtype).String(),
	}
	switch addr := remoteAddr.(type) {
	case *net.UDPAddr:
		msg.RemoteIP, msg.RemotePort = addr.IP.String(), addr.Port
	case *net.TCPAddr:
		msg.RemoteIP, msg.RemotePort = addr.IP.String(), addr.Port
	default:
		return nil
	}
	// The full watcher displays a sanitized DNS representation. Unknown EDNS
	// payloads (including potentially 64 KiB of padding) never enter its queue.
	sanitized := &dns.Msg{MsgHdr: req.MsgHdr, Question: []dns.Question{q}}
	if opt := req.IsEdns0(); opt != nil {
		if opt.Version() != 0 {
			return nil
		}
		msg.IsEdns0, msg.UDPSize = true, opt.UDPSize()
		sanitized.SetEdns0(opt.UDPSize(), opt.Do())
		if opt.Co() {
			sanitized.IsEdns0().SetCo()
		}
		for _, option := range opt.Option {
			subnet, ok := option.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			address := subnet.Address
			if subnet.Family == 1 && address.To4() != nil && subnet.SourceNetmask <= 32 && subnet.SourceScope <= 32 {
				address = address.To4()
			} else if subnet.Family == 2 && address.To16() != nil && address.To4() == nil && subnet.SourceNetmask <= 128 && subnet.SourceScope <= 128 {
				address = address.To16()
			} else {
				return nil
			}
			msg.ClientSubnet = fmt.Sprintf("%s/%d", address, subnet.SourceNetmask)
			sanitized.IsEdns0().Option = append(sanitized.IsEdns0().Option, &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: subnet.Family,
				SourceNetmask: subnet.SourceNetmask, SourceScope: subnet.SourceScope,
				Address: append(net.IP(nil), address...),
			})
			break
		}
	}
	if full {
		msg.MsgText = sanitized.String() + "\n;; Observation only: arbitrary EDNS payloads omitted; query ID and ECS are not authenticated."
	}
	if connState != nil {
		msg.TLSVersion = tls.VersionName(connState.Version)
		msg.TLSCipherSuite = tls.CipherSuiteName(connState.CipherSuite)
		// Protocol-bounded fields are copied; no connection state is retained.
		if len(connState.ServerName) <= 255 {
			msg.TLSServerName = connState.ServerName
		}
		if len(connState.NegotiatedProtocol) <= 255 {
			msg.TLSNegotiatedProtocol = connState.NegotiatedProtocol
		}
		msg.TLSDidResume = connState.DidResume
		if connState.CurveID != 0 {
			msg.TLSNamedGroup = connState.CurveID.String()
		}
		if proto == dnsutil.ProtoQUIC {
			// QUICStreamListener carries these diagnostic values in otherwise
			// unused TLS 1.3 fields for the DNS library's ConnectionStater API.
			if len(connState.TLSUnique) <= 32 {
				msg.QUICVersion = string(connState.TLSUnique)
			}
			msg.Used0RTT = connState.NegotiatedProtocolIsMutual
		}
	}
	return msg
}

type watcherWriter interface {
	SetWriteDeadline(time.Time) error
	WriteMessage(int, []byte) error
	Close() error
}

type WebsocketWatcher struct {
	conn        watcherWriter
	full        bool
	ch          chan []byte
	done        chan struct{}
	mu          sync.Mutex
	closed      bool
	queuedBytes int
}

func NewWebsocketWatcher(conn *websocket.Conn) *WebsocketWatcher {
	ws := newWebsocketWatcher(conn.Subprotocol() == "full")
	ws.conn = conn
	return ws
}

func newWebsocketWatcher(full bool) *WebsocketWatcher {
	return &WebsocketWatcher{
		full: full,
		ch:   make(chan []byte, WebsocketWatcherBufferLength), done: make(chan struct{}),
	}
}

func (ws *WebsocketWatcher) Send(req *dns.Msg, proto string, remoteAddr net.Addr, connState *tls.ConnectionState) {
	select {
	case <-ws.done:
		return
	default:
	}
	msg := snapshotQuery(req, proto, remoteAddr, connState, ws.full)
	if msg == nil {
		return
	}
	encoded, err := json.Marshal(msg)
	if err != nil || len(encoded) > WebsocketWatcherMaxMessage {
		return
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.closed || ws.queuedBytes+len(encoded) > WebsocketWatcherMaxQueueBytes {
		return
	}
	select {
	case ws.ch <- encoded:
		ws.queuedBytes += len(encoded)
	default:
		// Drop excess observations. DNS responses never block on a slow UI.
	}
}

func (ws *WebsocketWatcher) Close() {
	ws.mu.Lock()
	if ws.closed {
		ws.mu.Unlock()
		return
	}
	ws.closed = true
	close(ws.done)
	for {
		select {
		case msg := <-ws.ch:
			ws.queuedBytes -= len(msg)
		default:
			ws.mu.Unlock()
			if ws.conn != nil {
				ws.conn.Close()
			}
			return
		}
	}
}

func (ws *WebsocketWatcher) WriteLoop(ctx context.Context) {
	defer ws.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ws.done:
			return
		default:
		}
		select {
		case msg := <-ws.ch:
			ws.mu.Lock()
			ws.queuedBytes -= len(msg)
			ws.mu.Unlock()
			if err := ws.conn.SetWriteDeadline(time.Now().Add(WebsocketWriteWait)); err != nil {
				return
			}
			if err := ws.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ctx.Done():
			return
		case <-ws.done:
			return
		}
	}
}

type WebsocketHandler struct {
	*websocket.Upgrader
	WatcherHub
	AllowedOrigins []string
	// Trust only on a private listener behind a proxy that overwrites this
	// header. An empty value uses RemoteAddr and never trusts forwarded headers.
	TrustedClientIPHeader string
	MaxPerClient          int
	MaxConnections        int
	mu                    sync.Mutex
	clients               map[string]int
	active                int
	closing               bool
	sessions              sync.WaitGroup
	shutdownContext       context.Context
	cancelShutdown        context.CancelFunc
}

func NewWebsocketHandler(watcherHub WatcherHub) *WebsocketHandler {
	shutdownContext, cancelShutdown := context.WithCancel(context.Background())
	h := &WebsocketHandler{
		WatcherHub:   watcherHub,
		MaxPerClient: DefaultMaxWatchersPerClient, MaxConnections: DefaultMaxWatcherConnections,
		shutdownContext: shutdownContext, cancelShutdown: cancelShutdown,
	}
	h.Upgrader = &websocket.Upgrader{
		ReadBufferSize: 1024, WriteBufferSize: 1024,
		Subprotocols: []string{"full"}, HandshakeTimeout: 5 * time.Second,
		CheckOrigin: h.checkOrigin,
	}
	return h
}

func (h *WebsocketHandler) checkOrigin(req *http.Request) bool {
	origins := req.Header.Values("Origin")
	if len(origins) == 0 {
		return true // Non-browser clients still have the same admission limits.
	}
	if len(origins) != 1 {
		return false
	}
	origin, err := url.Parse(origins[0])
	if err != nil || (origin.Scheme != "https" && origin.Scheme != "http") || origin.Host == "" ||
		origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	if len(h.AllowedOrigins) == 0 {
		return strings.EqualFold(origin.Host, req.Host)
	}
	for _, allowed := range h.AllowedOrigins {
		if strings.EqualFold(origins[0], allowed) {
			return true
		}
	}
	return false
}

func (h *WebsocketHandler) clientKey(req *http.Request) (string, error) {
	var host string
	if h.TrustedClientIPHeader != "" {
		values := req.Header.Values(h.TrustedClientIPHeader)
		if len(values) != 1 {
			return "", errors.New("missing proxy client address")
		}
		host = values[0]
	} else {
		var err error
		host, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			// Local/Unix clients share a quota unless a trusted proxy supplies
			// their verified address explicitly.
			return "local", nil
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return "", errors.New("invalid client address")
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String(), nil
	}
	return addr.String(), nil
}

func (h *WebsocketHandler) acquireClient(client string) (func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	maxPerClient, maxConnections := h.MaxPerClient, h.MaxConnections
	if maxPerClient <= 0 {
		maxPerClient = DefaultMaxWatchersPerClient
	}
	if maxConnections <= 0 {
		maxConnections = DefaultMaxWatcherConnections
	}
	if h.closing || h.active >= maxConnections || h.clients[client] >= maxPerClient {
		return nil, false
	}
	if h.clients == nil {
		h.clients = make(map[string]int)
	}
	h.clients[client]++
	h.active++
	h.sessions.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.clients[client]--
			if h.clients[client] == 0 {
				delete(h.clients, client)
			}
			h.active--
			h.mu.Unlock()
			h.sessions.Done()
		})
	}, true
}

// Shutdown also closes hijacked WebSockets, which net/http.Server.Shutdown
// deliberately does not wait for. Admission and WaitGroup.Add share the same
// lock so no new session can appear after shutdown starts waiting.
func (h *WebsocketHandler) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	h.cancelShutdown()
	h.mu.Unlock()
	done := make(chan struct{})
	go func() {
		h.sessions.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validWatcherID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (h *WebsocketHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	watcherID := req.PathValue("watcher")
	if !validWatcherID(watcherID) || !websocket.IsWebSocketUpgrade(req) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !h.checkOrigin(req) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	client, err := h.clientKey(req)
	if err != nil {
		http.Error(w, "invalid client address", http.StatusBadRequest)
		return
	}
	releaseClient, ok := h.acquireClient(client)
	if !ok {
		http.Error(w, "watcher capacity reached; retry later", http.StatusTooManyRequests)
		return
	}
	defer releaseClient()
	// Reserve the ID before completing the upgrade. The browser may start its
	// first DNS probe as soon as it observes the upgrade response.
	full := slices.Contains(h.Subprotocols, "full") && slices.Contains(websocket.Subprotocols(req), "full")
	watcher := newWebsocketWatcher(full)
	releaseWatcher, registrationErr := h.Register(watcherID, watcher)
	if registrationErr == nil {
		defer releaseWatcher()
		defer watcher.Close()
	}
	conn, err := h.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	if registrationErr != nil {
		code, reason := websocket.CloseTryAgainLater, "watcher capacity reached"
		if errors.Is(registrationErr, ErrWatcherExists) {
			code, reason = 4000, "watcher already exists"
		}
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(WebsocketWriteWait))
		return
	}
	// Send only queues immutable metadata; no reader uses conn until the
	// following write loop starts, so early probes are buffered safely.
	watcher.conn = conn
	conn.SetReadLimit(512)
	ctx, cancel := context.WithTimeout(req.Context(), WebsocketWatcherMaxLife)
	defer cancel()
	stopShutdown := context.AfterFunc(h.shutdownContext, cancel)
	defer stopShutdown()
	stopClose := context.AfterFunc(ctx, func() {
		conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(WebsocketWriteWait))
		watcher.Close()
	})
	defer stopClose()
	go watcher.WriteLoop(ctx)
	for {
		if _, _, err := conn.NextReader(); err != nil {
			return
		}
	}
}
