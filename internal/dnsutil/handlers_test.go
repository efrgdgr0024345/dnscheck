// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMsgAcceptRejectsUnneededSectionsBeforeDecode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header dns.Header
		want   dns.MsgAcceptAction
	}{
		{"query with EDNS and TSIG", dns.Header{Qdcount: 1, Arcount: 2}, dns.MsgAccept},
		{"response", dns.Header{Bits: 1 << 15, Qdcount: 1}, dns.MsgIgnore},
		{"update", dns.Header{Bits: uint16(dns.OpcodeUpdate) << 11, Qdcount: 1}, dns.MsgRejectNotImplemented},
		{"multiple questions", dns.Header{Qdcount: 2}, dns.MsgReject},
		{"answer injection", dns.Header{Qdcount: 1, Ancount: 1}, dns.MsgReject},
		{"authority injection", dns.Header{Qdcount: 1, Nscount: 1}, dns.MsgReject},
		{"oversized additional section", dns.Header{Qdcount: 1, Arcount: 65535}, dns.MsgReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MsgAcceptFunc(tc.header); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}
