// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package netutil

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

var _ net.Conn = (*QUICStreamConn)(nil)

const (
	DoQNoError          quic.ApplicationErrorCode = 0
	DoQProtocolError    quic.ApplicationErrorCode = 2
	DoQRequestCancelled quic.StreamErrorCode      = 3
)

var errDoQProtocol = errors.New("invalid DNS-over-QUIC stream")

type quicStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

// QUICStreamConn adapts one RFC 9250 request/response exchange to the DNS
// server's TCP framing API. It validates the entire request and its FIN before
// exposing it to the DNS handler; further requests cannot hide on the stream.
type QUICStreamConn struct {
	stream          quicStream
	localAddr       net.Addr
	remoteAddr      net.Addr
	connectionState tls.ConnectionState
	abortConnection func()
	readMu          sync.Mutex
	writeMu         sync.Mutex
	frame           []byte
	readOffset      int
	readDone        bool
	readErr         error
	responseWritten atomic.Bool
	closed          atomic.Bool
	closeOnce       sync.Once
	closeErr        error
}

func (c *QUICStreamConn) LocalAddr() net.Addr                  { return c.localAddr }
func (c *QUICStreamConn) RemoteAddr() net.Addr                 { return c.remoteAddr }
func (c *QUICStreamConn) ConnectionState() tls.ConnectionState { return c.connectionState }
func (c *QUICStreamConn) SetDeadline(t time.Time) error        { return c.stream.SetDeadline(t) }
func (c *QUICStreamConn) SetReadDeadline(t time.Time) error    { return c.stream.SetReadDeadline(t) }
func (c *QUICStreamConn) SetWriteDeadline(t time.Time) error   { return c.stream.SetWriteDeadline(t) }

func (c *QUICStreamConn) protocolError() error {
	if c.abortConnection != nil {
		c.abortConnection()
	}
	return errDoQProtocol
}

func (c *QUICStreamConn) readFrame() error {
	var prefix [2]byte
	if _, err := io.ReadFull(c.stream, prefix[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return c.protocolError()
		}
		return err
	}
	length := int(binary.BigEndian.Uint16(prefix[:]))
	if length < 12 {
		return c.protocolError()
	}
	frame := make([]byte, length+2)
	copy(frame, prefix[:])
	if _, err := io.ReadFull(c.stream, frame[2:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return c.protocolError()
		}
		return err
	}
	if binary.BigEndian.Uint16(frame[2:4]) != 0 {
		return c.protocolError()
	}
	// RFC 9250 requires exactly one DNS message followed by FIN. The DNS
	// server's read deadline also bounds clients that withhold that FIN.
	var extra [1]byte
	if n, err := io.ReadFull(c.stream, extra[:]); n != 0 {
		return c.protocolError()
	} else if err != io.EOF {
		return err
	}
	c.frame = frame
	return nil
}

func (c *QUICStreamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !c.readDone {
		c.readDone = true
		c.readErr = c.readFrame()
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.readOffset == len(c.frame) {
		return 0, io.EOF
	}
	n := copy(p, c.frame[c.readOffset:])
	c.readOffset += n
	return n, nil
}

func (c *QUICStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	// The DNS server writes one complete length-prefixed response per call.
	if c.responseWritten.Load() || len(p) < 14 || int(binary.BigEndian.Uint16(p[:2])) != len(p)-2 || binary.BigEndian.Uint16(p[2:4]) != 0 {
		return 0, c.protocolError()
	}
	n, err := c.stream.Write(p)
	if err == nil && n == len(p) {
		c.responseWritten.Store(true)
	}
	return n, err
}

func (c *QUICStreamConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		// Close on a quic.Stream closes only its sending half. CancelRead also
		// releases receive-side resources when a client withheld FIN or failed.
		c.stream.CancelRead(DoQRequestCancelled)
		if c.responseWritten.Load() {
			c.closeErr = c.stream.Close() // Send response FIN without discarding it.
		} else {
			c.stream.CancelWrite(DoQRequestCancelled)
		}
	})
	return c.closeErr
}

var _ QUICListener = (*quic.Listener)(nil)
var _ QUICListener = (*quic.EarlyListener)(nil)

type QUICListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Addr() net.Addr
	Close() error
}

var _ net.Listener = (*QUICStreamListener)(nil)

type QUICStreamListener struct {
	ql     QUICListener
	ch     chan *QUICStreamConn
	ctx    context.Context
	cancel context.CancelCauseFunc
	closed chan struct{}
	conns  map[*quic.Conn]struct{}
	mu     sync.Mutex
}

func NewQUICStreamListener(quicListener QUICListener) *QUICStreamListener {
	ctx, cancel := context.WithCancelCause(context.Background())
	sl := &QUICStreamListener{
		ql:     quicListener,
		ch:     make(chan *QUICStreamConn),
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}, 1),
		conns:  make(map[*quic.Conn]struct{}),
	}
	go func() {
		sl.acceptConns()
		sl.closed <- struct{}{}
		close(sl.closed)
	}()
	return sl
}

func (sl *QUICStreamListener) acceptConns() {
	for {
		conn, err := sl.ql.Accept(sl.ctx)
		if err != nil {
			sl.ql.Close()
			sl.cancel(err)
			return
		}
		sl.mu.Lock()
		sl.conns[conn] = struct{}{}
		sl.mu.Unlock()
		select {
		case <-sl.ctx.Done():
			conn.CloseWithError(DoQNoError, "going away")
		default:
			go func() {
				sl.acceptStreams(conn)
				sl.mu.Lock()
				delete(sl.conns, conn)
				sl.mu.Unlock()
			}()
		}
	}
}

func (sl *QUICStreamListener) acceptStreams(conn *quic.Conn) {
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	connectionState := conn.ConnectionState()
	// hack: use TLSUnique, nil for TLS1.3, to store QUIC version
	switch connectionState.Version {
	case quic.Version1:
		connectionState.TLS.TLSUnique = []byte("QUICv1")
	case quic.Version2:
		connectionState.TLS.TLSUnique = []byte("QUICv2")
	default:
		connectionState.TLS.TLSUnique = []byte(connectionState.Version.String())
	}
	// hack: use NegotiatedProtocolIsMutual, deprecated, to store Used0RTT
	connectionState.TLS.NegotiatedProtocolIsMutual = connectionState.Used0RTT
	for {
		stream, err := conn.AcceptStream(sl.ctx)
		if err != nil {
			return
		}
		select {
		case sl.ch <- &QUICStreamConn{
			stream: stream, localAddr: localAddr, remoteAddr: remoteAddr,
			connectionState: connectionState.TLS,
			abortConnection: func() { conn.CloseWithError(DoQProtocolError, "invalid DNS-over-QUIC stream") },
		}:
		case <-sl.ctx.Done():
			stream.CancelRead(DoQRequestCancelled)
			stream.CancelWrite(DoQRequestCancelled)
			return
		}
	}
}

func (sl *QUICStreamListener) Accept() (net.Conn, error) {
	select {
	case <-sl.ctx.Done():
		return nil, context.Cause(sl.ctx)
	default:
	}
	select {
	case streamConn := <-sl.ch:
		return streamConn, nil
	case <-sl.ctx.Done():
		return nil, context.Cause(sl.ctx)
	}
}

func (sl *QUICStreamListener) Close() error {
	sl.ql.Close()
	sl.cancel(net.ErrClosed)
	_, ok := <-sl.closed
	if ok {
		var wg sync.WaitGroup
		sl.mu.Lock()
		for conn := range sl.conns {
			wg.Go(func() {
				conn.CloseWithError(0, "going away")
			})
		}
		clear(sl.conns)
		sl.mu.Unlock()
		wg.Wait()
	}
	return nil
}

func (sl *QUICStreamListener) Addr() net.Addr {
	return sl.ql.Addr()
}
