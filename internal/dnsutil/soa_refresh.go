// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnsutil

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/miekg/dns"
)

// SOASignatureRefresher keeps one cached SOA signature current. Its caller owns
// the context and must cancel it, then call Wait, before discarding the zone.
type SOASignatureRefresher struct {
	done chan struct{}
	err  error // Read only after done closes.
}

func StartSOASignatureRefresh(ctx context.Context, provider *DnssecProvider, soa *dns.SOA, store func(*dns.RRSIG)) (*SOASignatureRefresher, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if provider == nil || soa == nil || soa.Hdr.Ttl == 0 || store == nil {
		return nil, fmt.Errorf("SOA signature refresh requires a provider, positive TTL, and cache")
	}
	// Keep the immutable signed record separate from responses assembled later.
	soa = dns.Copy(soa).(*dns.SOA)
	refresh := func() error {
		now := uint32(time.Now().Unix())
		sigs, err := provider.Sign([]dns.RR{soa}, now-3600, now+3600+2*soa.Hdr.Ttl)
		if err != nil {
			return err
		}
		if len(sigs) != 1 {
			return fmt.Errorf("SOA signing produced %d signatures", len(sigs))
		}
		sig, ok := sigs[0].(*dns.RRSIG)
		if !ok || sig == nil {
			return fmt.Errorf("SOA signing produced an invalid signature")
		}
		store(sig)
		return nil
	}
	if err := refresh(); err != nil {
		return nil, fmt.Errorf("initial SOA signature: %w", err)
	}
	r := &SOASignatureRefresher{done: make(chan struct{})}
	go func() {
		defer close(r.done)
		halfTTL := time.Duration(soa.Hdr.Ttl) * time.Second / 2
		for {
			// Jitter avoids refreshing every configured zone at the same instant.
			timer := time.NewTimer(halfTTL + time.Duration(rand.Int64N(int64(halfTTL))))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				return
			}
			if err := refresh(); err != nil {
				// Never retain a stale cached signature after a failed refresh.
				// The runtime receives this error through Wait and drains services.
				store(nil)
				r.err = fmt.Errorf("refresh SOA signature: %w", err)
				return
			}
		}
	}()
	return r, nil
}

// Wait joins the refresh worker. Cancellation is a normal, successful stop.
// A nil refresher denotes a zone without DNSSEC and returns immediately.
func (r *SOASignatureRefresher) Wait() error {
	if r == nil {
		return nil
	}
	<-r.done
	return r.err
}
