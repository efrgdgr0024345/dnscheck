// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package netutil

import (
	"crypto/tls"
	"net"
	"time"
)

// WriteTimeoutListener applies a per-write deadline without losing TLS/QUIC
// connection metadata. It bounds slow-reader DNS connections; a declared
// dns.Server.WriteTimeout alone is not applied by the pinned DNS dependency.
type WriteTimeoutListener struct {
	net.Listener
	Timeout time.Duration
}

type writeTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *writeTimeoutConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type tlsStateConn interface{ ConnectionState() tls.ConnectionState }

type writeTimeoutTLSConn struct {
	*writeTimeoutConn
	state tlsStateConn
}

func (c *writeTimeoutTLSConn) ConnectionState() tls.ConnectionState { return c.state.ConnectionState() }

func (l *WriteTimeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &writeTimeoutConn{Conn: conn, timeout: l.Timeout}
	if state, ok := conn.(tlsStateConn); ok {
		return &writeTimeoutTLSConn{writeTimeoutConn: wrapped, state: state}, nil
	}
	return wrapped, nil
}
