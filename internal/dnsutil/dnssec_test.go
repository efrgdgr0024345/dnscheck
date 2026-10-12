// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnsutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"encoding/base64"
	"math/big"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func testA(name string, class uint16, last byte) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: class, Ttl: 60}, A: net.IPv4(192, 0, 2, last)}
}

func TestDNSSECPrivateKeysValidateAndRoundTrip(t *testing.T) {
	for _, algorithm := range []uint8{dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519, dns.MLDSA44} {
		t.Run(dns.AlgorithmToString[algorithm], func(t *testing.T) {
			original, err := GenerateDnssecProvider("example.", algorithm, 60)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := original.PrivKeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			loaded := &DnssecProvider{SigningKey: dns.Copy(original.SigningKey).(*dns.DNSKEY)}
			if err := loaded.SetPrivKeyBytes(encoded); err != nil {
				t.Fatal(err)
			}
			got, err := loaded.PrivKeyBytes()
			if err != nil || !bytes.Equal(got, encoded) {
				t.Fatal("private key round trip failed")
			}
			rrset := []dns.RR{testA("www.example.", dns.ClassINET, 1)}
			sigs, err := loaded.Sign(rrset, 0, 0)
			if err != nil || len(sigs) != 1 {
				t.Fatalf("sign: %v", err)
			}
			if err := sigs[0].(*dns.RRSIG).Verify(original.SigningKey, rrset); err != nil {
				t.Fatalf("round-trip key produced invalid signature: %v", err)
			}

			other, err := GenerateDnssecProvider("example.", algorithm, 60)
			if err != nil {
				t.Fatal(err)
			}
			mismatch := &DnssecProvider{SigningKey: other.SigningKey}
			if err := mismatch.SetPrivKeyBytes(encoded); err == nil || mismatch.PrivateKey != nil {
				t.Fatal("mismatched private/public key accepted or installed")
			}
			for _, invalid := range [][]byte{nil, encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), 0)} {
				before, err := loaded.PrivKeyBytes()
				if err != nil {
					t.Fatal(err)
				}
				if err := loaded.SetPrivKeyBytes(invalid); err == nil {
					t.Fatal("malformed private key accepted")
				}
				after, err := loaded.PrivKeyBytes()
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("failed validation changed active key")
				}
			}
			loaded.SigningKey.PublicKey = "%%%"
			if err := loaded.SetPrivKeyBytes(encoded); err == nil {
				t.Fatal("malformed public key encoding accepted")
			}
		})
	}
}

func TestECDSARejectsInvalidScalarsAndPoints(t *testing.T) {
	for _, tc := range []struct {
		algorithm uint8
		curve     elliptic.Curve
	}{
		{dns.ECDSAP256SHA256, elliptic.P256()}, {dns.ECDSAP384SHA384, elliptic.P384()},
	} {
		t.Run(dns.AlgorithmToString[tc.algorithm], func(t *testing.T) {
			original, err := GenerateDnssecProvider("example.", tc.algorithm, 60)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := original.PrivKeyBytes()
			if err != nil {
				t.Fatal(err)
			}
			loaded := &DnssecProvider{SigningKey: dns.Copy(original.SigningKey).(*dns.DNSKEY)}
			for _, invalid := range [][]byte{make([]byte, len(encoded)), tc.curve.Params().N.Bytes(), new(big.Int).Add(tc.curve.Params().N, big.NewInt(1)).Bytes()} {
				if err := loaded.SetPrivKeyBytes(invalid); err == nil {
					t.Fatal("out-of-range ECDSA scalar accepted")
				}
			}
			loaded.SigningKey.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 2*len(encoded)))
			if err := loaded.SetPrivKeyBytes(encoded); err == nil {
				t.Fatal("off-curve ECDSA public point accepted")
			}
		})
	}
}

func TestECDSALegacyShortScalarEncodingRemainsSupported(t *testing.T) {
	fixed := make([]byte, 32)
	fixed[31] = 1
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), fixed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p := &DnssecProvider{SigningKey: &dns.DNSKEY{
		Algorithm: dns.ECDSAP256SHA256, PublicKey: base64.StdEncoding.EncodeToString(public[1:]),
	}}
	if err := p.SetPrivKeyBytes([]byte{1}); err != nil {
		t.Fatalf("legacy scalar rejected: %v", err)
	}
	encoded, err := p.PrivKeyBytes()
	if err != nil || !bytes.Equal(encoded, fixed) {
		t.Fatal("legacy scalar was not canonically re-encoded")
	}
}

func TestMalformedPrivateKeyExportReturnsErrors(t *testing.T) {
	for _, tc := range []struct {
		algorithm uint8
		signer    crypto.Signer
	}{
		{dns.ECDSAP256SHA256, nil}, {dns.ECDSAP256SHA256, (*ecdsa.PrivateKey)(nil)},
		{dns.ECDSAP256SHA256, new(ecdsa.PrivateKey)}, {dns.ECDSAP256SHA256, ed25519.PrivateKey(make([]byte, 64))},
		{dns.ED25519, nil}, {dns.ED25519, ed25519.PrivateKey(make([]byte, 31))},
		{dns.MLDSA44, nil}, {dns.MLDSA44, (*mldsa.PrivateKey)(nil)}, {dns.MLDSA44, new(mldsa.PrivateKey)},
	} {
		p := &DnssecProvider{SigningKey: &dns.DNSKEY{Algorithm: tc.algorithm}, PrivateKey: tc.signer}
		if _, err := p.PrivKeyBytes(); err == nil {
			t.Fatalf("algorithm %d accepted malformed signer", tc.algorithm)
		}
	}
}

func TestDNSSECSignGroupsCompleteRRsetIdentity(t *testing.T) {
	p, err := GenerateDnssecProvider("example.", dns.ED25519, 60)
	if err != nil {
		t.Fatal(err)
	}
	rrsets := [][]dns.RR{
		{testA("WWW.example.", dns.ClassINET, 1), testA("www.EXAMPLE.", dns.ClassINET, 2)},
		{testA("api.example.", dns.ClassINET, 3)},
		{testA("www.example.", dns.ClassCHAOS, 4)},
	}
	var records []dns.RR
	for _, rrset := range rrsets {
		records = append(records, rrset...)
	}
	sigs, err := p.Sign(records, 0, 0)
	if err != nil || len(sigs) != len(rrsets) {
		t.Fatalf("got %d signatures for %d RRsets: %v", len(sigs), len(rrsets), err)
	}
	for _, rr := range sigs {
		sig := rr.(*dns.RRSIG)
		var matching []dns.RR
		for _, rrset := range rrsets {
			if dns.CanonicalName(sig.Hdr.Name) == dns.CanonicalName(rrset[0].Header().Name) && sig.Hdr.Class == rrset[0].Header().Class {
				matching = rrset
				break
			}
		}
		if matching == nil {
			t.Fatal("signature has no matching RRset")
		}
		key := dns.Copy(p.SigningKey).(*dns.DNSKEY)
		key.Hdr.Class = sig.Hdr.Class
		// The DNS library's IsRRset helper compares presentation names
		// literally; normalize copies for its verifier, as DNSSEC wire
		// canonicalization does, without modifying the caller's records.
		canonical := make([]dns.RR, len(matching))
		for i, record := range matching {
			canonical[i] = dns.Copy(record)
			canonical[i].Header().Name = dns.CanonicalName(record.Header().Name)
		}
		if err := sig.Verify(key, canonical); err != nil {
			t.Fatalf("mixed RRset produced invalid signature: %v", err)
		}
	}
	// An existing signature for one A RRset must not suppress other A owners
	// or another class, while case variants of its own owner remain one set.
	signedFirst, err := p.Sign(rrsets[0], 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, signedFirst...)
	sigs, err = p.Sign(records, 0, 0)
	if err != nil || len(sigs) != len(rrsets)-1 {
		t.Fatalf("existing signature suppressed unrelated RRsets: %d, %v", len(sigs), err)
	}
	for _, rr := range sigs {
		if dns.CanonicalName(rr.Header().Name) == "www.example." && rr.Header().Class == dns.ClassINET {
			t.Fatal("already signed RRset was signed twice")
		}
	}
}
