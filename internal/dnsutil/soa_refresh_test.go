// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnsutil

import (
	"context"
	"crypto"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSimpleHandlerInitializationAndRefreshStop(t *testing.T) {
	provider, err := GenerateDnssecProvider("example.", dns.ED25519, 1800)
	if err != nil {
		t.Fatal(err)
	}
	private, err := provider.PrivKeyBytes()
	if err != nil {
		t.Fatal(err)
	}
	h := &SimpleHandler{DnssecProvider: provider, Zone: "EXAMPLE.", Ns: []string{"NS.EXAMPLE."}}
	if err := h.InitContext(context.Background(), private[:1]); err == nil {
		t.Fatal("malformed private key did not return an initialization error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.InitContext(ctx, private); err != nil {
		t.Fatal(err)
	}
	soa := h.SOA(nil, true)
	if len(soa) != 2 || h.Zone != "example." || h.Ns[0] != "ns.example." {
		t.Fatal("handler did not initialize its names and cached SOA signature")
	}
	if err := soa[1].(*dns.RRSIG).Verify(provider.SigningKey, soa[:1]); err != nil {
		t.Fatalf("cached SOA signature is invalid: %v", err)
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
		t.Fatal("SOA refresher did not stop when the handler context ended")
	}
	if err := h.WaitForRefresh(); err != nil {
		t.Fatalf("joining an already-stopped refresher: %v", err)
	}
	if err := (&SimpleHandler{Ns: []string{"ns.example."}}).InitContext(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled initialization was accepted")
	}
	if err := new(SimpleHandler).InitContext(context.Background(), nil); err == nil {
		t.Fatal("missing nameservers accepted")
	}
}

type failingRefreshSigner struct {
	crypto.Signer
	signs atomic.Int64
	err   error
}

func (s *failingRefreshSigner) Sign(reader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.signs.Add(1) > 1 {
		return nil, s.err
	}
	return s.Signer.Sign(reader, digest, opts)
}

func TestSOARefreshFailureIsReportedAndInvalidatesCache(t *testing.T) {
	provider, err := GenerateDnssecProvider("example.", dns.ED25519, 1)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("test signing failure")
	provider.PrivateKey = &failingRefreshSigner{Signer: provider.PrivateKey, err: wantErr}
	var cached atomic.Pointer[dns.RRSIG]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, err := StartSOASignatureRefresh(ctx, provider, &dns.SOA{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1},
		Ns:  "ns.example.", Mbox: "hostmaster.example.",
	}, cached.Store)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Load() == nil {
		t.Fatal("initial signature was not cached")
	}
	done := make(chan error, 1)
	go func() { done <- r.Wait() }()
	select {
	case err := <-done:
		if !errors.Is(err, wantErr) {
			t.Fatalf("refresh error was not preserved: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("refresh failure was not reported")
	}
	if cached.Load() != nil {
		t.Fatal("failed refresh retained a potentially stale signature")
	}
}
