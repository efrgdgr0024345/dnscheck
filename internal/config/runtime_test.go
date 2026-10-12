// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/dnscheck"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestDNSRuntimeWaitsForReadinessAndReportsFailure(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime := newServiceRuntime(context.Background())
	if err := runtime.startDNS("test DNS", &dns.Server{PacketConn: packet}, nil); err != nil {
		t.Fatal(err)
	}
	packet.Close() // Simulate a listener failing while the service is running.
	select {
	case err := <-runtime.errors:
		if !strings.Contains(err.Error(), "test DNS service") {
			t.Fatalf("missing listener context: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener error was not reported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRuntimeFailedStartupStillCleansUp(t *testing.T) {
	runtime := newServiceRuntime(context.Background())
	if err := runtime.startDNS("missing listener", new(dns.Server), nil); err == nil {
		t.Fatal("missing listener accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRunContextBindFailureReturnsAndReleasesEarlierListener(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	address := blocker.Addr().String()
	probe, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Skip("chosen TCP test port is already used for UDP")
	}
	probe.Close()
	c := &Config{DNSListenAddress: address, DatabasePath: filepath.Join(t.TempDir(), "state.json")}
	if err := c.RunContext(context.Background()); err == nil || !strings.Contains(err.Error(), "bind DNS TCP") {
		t.Fatalf("expected a returned startup error: %v", err)
	}
	probe, err = net.ListenPacket("udp", address)
	if err != nil {
		t.Fatalf("earlier UDP listener leaked after TCP bind failure: %v", err)
	}
	probe.Close()
	if _, err := os.Stat(c.DatabasePath); err != nil {
		t.Fatalf("startup error skipped state finalization: %v", err)
	}
}

func testTLSFiles(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func dualProtocolTestAddress(t *testing.T) string {
	t.Helper()
	for range 10 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		packet, err := net.ListenPacket("udp", address)
		listener.Close()
		if err == nil {
			packet.Close()
			return address
		}
	}
	t.Fatal("could not select a free loopback TCP/UDP test port")
	return ""
}

func TestRunContextClosesQUICTransportAndPersists(t *testing.T) {
	dir := t.TempDir()
	var c Config
	if err := json.Unmarshal([]byte(`{"DnscheckZones":[{"Zone":"test.example.","Ns":["ns.example."]}]}`), &c); err != nil {
		t.Fatal(err)
	}
	// Exercise cancellation of both kinds of SOA refresh worker as part of the
	// complete runtime shutdown, in addition to the protocol listeners.
	for _, zone := range []string{"test.example.", "dyn.example."} {
		provider, err := dnsutil.GenerateDnssecProvider(zone, dns.ED25519, 1800)
		if err != nil {
			t.Fatal(err)
		}
		private, err := provider.PrivKeyBytes()
		if err != nil {
			t.Fatal(err)
		}
		if zone == "test.example." {
			c.DnscheckZones[0].DnssecProvider = provider
			c.DnscheckZones[0].PrivateKey = base64.StdEncoding.EncodeToString(private)
		} else {
			c.DynZone.SimpleHandler = &dnsutil.SimpleHandler{Zone: zone, Ns: []string{"ns.example."}, DnssecProvider: provider}
			c.DynZone.PrivateKey = base64.StdEncoding.EncodeToString(private)
		}
	}
	c.DNSListenAddress = "127.0.0.1:0"
	c.TLSListenAddress = dualProtocolTestAddress(t)
	c.DatabasePath = filepath.Join(dir, "state.json")
	c.TLSCertPath, c.TLSKeyPath = testTLSFiles(t)
	c.TLSTicketKeysPath = filepath.Join(dir, "tickets.json")
	certPEM, err := os.ReadFile(c.TLSCertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("test certificate was not loaded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var runErr error
	done := make(chan struct{})
	go func() { runErr = c.RunContext(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("service cleanup did not finish")
		}
	})
	var client *quic.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		attempt, stopAttempt := context.WithTimeout(context.Background(), 100*time.Millisecond)
		client, err = quic.DialAddr(attempt, c.TLSListenAddress, &tls.Config{
			MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"}, ServerName: "localhost", RootCAs: roots,
		}, nil)
		stopAttempt()
		if err == nil {
			break
		}
		select {
		case <-done:
			t.Fatalf("service stopped before readiness: %v", runErr)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	if client == nil {
		t.Fatalf("DoQ endpoint did not become ready: %v", err)
	}
	defer client.CloseWithError(0, "test complete")
	stream, err := client.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(time.Second))
	query := new(dns.Msg).SetQuestion("status.", dns.TypeSOA)
	query.Id = 0
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(stream)
	if err != nil || len(response) < 14 {
		t.Fatalf("DoQ response: %v", err)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(response[2:]); err != nil || answer.Id != 0 || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) == 0 {
		t.Fatalf("DoQ request did not reach the configured DNS server: %v", err)
	}
	cancel()
	select {
	case <-done:
		if runErr != nil {
			t.Fatalf("graceful stop: %v", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunContext did not stop")
	}
	packet, err := net.ListenPacket("udp", c.TLSListenAddress)
	if err != nil {
		t.Fatalf("QUIC transport retained its supplied UDP socket: %v", err)
	}
	packet.Close()
	listener, err := net.Listen("tcp", c.TLSListenAddress)
	if err != nil {
		t.Fatalf("TLS listener survived shutdown: %v", err)
	}
	listener.Close()
	if _, err := os.Stat(c.DatabasePath); err != nil {
		t.Fatalf("final state snapshot missing: %v", err)
	}
}

func TestRuntimeDrainsHijackedWatchers(t *testing.T) {
	runtime := newServiceRuntime(context.Background())
	hub := &dnscheck.SimpleWatcherHub{MaxSize: 10}
	watcher := dnscheck.NewWebsocketHandler(hub)
	runtime.addStopper("watchers", watcher.Shutdown)
	mux := http.NewServeMux()
	mux.Handle("/watch/{watcher}", watcher)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtime.startHTTP("test HTTP", listener, newHTTPServer(mux))
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+listener.Addr().String()+"/watch/0123456789abcdef0123456789abcdef", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if hub.Size() != 0 {
		t.Fatal("runtime retained active watchers")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("runtime left a hijacked connection open")
	}
}

func TestCancelledRunContextDoesNotStartListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Config{DNSListenAddress: "127.0.0.1:0", HTTPSocketPath: filepath.Join(t.TempDir(), "absent.sock")}
	if err := c.RunContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.HTTPSocketPath); !os.IsNotExist(err) {
		t.Fatal("cancelled service created a listener")
	}
}
