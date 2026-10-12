// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package netutil

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

type oneConnListener struct{ conn net.Conn }

func (l *oneConnListener) Accept() (net.Conn, error) { return l.conn, nil }
func (l *oneConnListener) Close() error              { return l.conn.Close() }
func (l *oneConnListener) Addr() net.Addr            { return l.conn.LocalAddr() }

type testStateConn struct{ net.Conn }

func (*testStateConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{Version: tls.VersionTLS13}
}

func TestDNSWritesHaveDeadlinesWithoutInventingTLSState(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	listener := &WriteTimeoutListener{Listener: &oneConnListener{conn: left}, Timeout: 20 * time.Millisecond}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(tlsStateConn); ok {
		t.Fatal("plain TCP wrapper invented TLS metadata")
	}
	// The peer never reads. A bare net.Conn.Write would remain blocked.
	_, err = conn.Write([]byte("bounded DNS response"))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("slow writer was not bounded: %v", err)
	}
}

func TestDNSWriteWrapperPreservesTLSAndQUICMetadata(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	listener := &WriteTimeoutListener{Listener: &oneConnListener{conn: &testStateConn{Conn: left}}, Timeout: time.Second}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	state, ok := conn.(tlsStateConn)
	if !ok || state.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("encrypted-transport metadata was lost")
	}
}
