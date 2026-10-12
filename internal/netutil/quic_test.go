// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package netutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// These integration tests create only loopback QUIC connections with an
// ephemeral, explicitly trusted test certificate. No public server is queried.
func quicTestPair(t *testing.T, maxStreams int64) (*QUICStreamListener, *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, &quic.Config{MaxIncomingStreams: maxStreams, MaxIncomingUniStreams: -1})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewQUICStreamListener(listener)
	t.Cleanup(func() { adapter.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"doq"}, ServerName: "localhost", RootCAs: roots,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(DoQNoError, "test complete") })
	return adapter, client
}

func framedDNS(t *testing.T, id uint16) []byte {
	t.Helper()
	req := new(dns.Msg).SetQuestion("test.example.", dns.TypeA)
	req.Id = id
	wire, err := req.Pack()
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, len(wire)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	return frame
}

func openTestStream(t *testing.T, client *quic.Conn) *quic.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	return stream
}

func acceptTestStream(t *testing.T, listener *QUICStreamListener) net.Conn {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() { conn, err := listener.Accept(); ch <- result{conn, err} }()
	select {
	case result := <-ch:
		if result.err != nil {
			t.Fatal(result.err)
		}
		result.conn.SetDeadline(time.Now().Add(3 * time.Second))
		return result.conn
	case <-time.After(3 * time.Second):
		t.Fatal("timed out accepting test stream")
		return nil
	}
}

func TestQUICStreamDeliversResponseFINAndReleasesCapacity(t *testing.T) {
	listener, client := quicTestPair(t, 1)
	frame := framedDNS(t, 0)
	// A one-stream limit makes leaked receive/send sides visible: each next
	// OpenStreamSync must wait until both halves of the previous stream finish.
	for range 3 {
		stream := openTestStream(t, client)
		if _, err := stream.Write(frame); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		conn := acceptTestStream(t, listener)
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, frame) {
			t.Fatalf("framed request: %x, %v", got, err)
		}
		response := append([]byte(nil), frame...)
		response[4] |= 0x80 // Set the DNS QR bit; preserve its required zero ID.
		if _, err := conn.Write(response); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		got, err = io.ReadAll(stream)
		if err != nil || !bytes.Equal(got, response) {
			t.Fatalf("response and FIN: %x, %v", got, err)
		}
	}
}

func TestQUICRejectsProtocolViolationsBeforeExposingQuery(t *testing.T) {
	valid := framedDNS(t, 0)
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"nonzero message ID", framedDNS(t, 1)},
		{"second message", append(append([]byte(nil), valid...), valid...)},
		{"trailing byte", append(append([]byte(nil), valid...), 0)},
		{"short DNS message", []byte{0, 1, 0}},
		{"truncated body", valid[:len(valid)-1]},
		{"truncated length", []byte{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, client := quicTestPair(t, 1)
			stream := openTestStream(t, client)
			if _, err := stream.Write(tc.frame); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			conn := acceptTestStream(t, listener)
			defer conn.Close()
			var buf [2]byte
			n, err := conn.Read(buf[:])
			if n != 0 || !errors.Is(err, errDoQProtocol) {
				t.Fatalf("invalid data reached DNS reader: n=%d err=%v", n, err)
			}
			select {
			case <-client.Context().Done():
				var appErr *quic.ApplicationError
				if !errors.As(context.Cause(client.Context()), &appErr) || appErr.ErrorCode != DoQProtocolError {
					t.Fatalf("connection close reason: %v", context.Cause(client.Context()))
				}
			case <-time.After(time.Second):
				t.Fatal("protocol violation did not close the QUIC connection")
			}
		})
	}
}

func TestQUICWithheldFINIsBoundedAndCancelled(t *testing.T) {
	listener, client := quicTestPair(t, 1)
	stream := openTestStream(t, client)
	if _, err := stream.Write(framedDNS(t, 0)); err != nil {
		t.Fatal(err)
	}
	// Deliberately withhold Close/FIN; no DNS bytes may escape to the handler.
	conn := acceptTestStream(t, listener)
	conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var buf [2]byte
	n, err := conn.Read(buf[:])
	var netErr net.Error
	if n != 0 || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("withheld FIN: n=%d err=%v", n, err)
	}
	conn.Close()
	_, err = stream.Read(buf[:])
	var streamErr *quic.StreamError
	if !errors.As(err, &streamErr) || streamErr.ErrorCode != DoQRequestCancelled {
		t.Fatalf("unfinished stream was not reset: %v", err)
	}
	// The connection remains usable and its one stream slot is reclaimed.
	next := openTestStream(t, client)
	next.CancelRead(DoQRequestCancelled)
	next.CancelWrite(DoQRequestCancelled)
}
