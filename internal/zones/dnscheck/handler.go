// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnscheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

type BadDnssecProvider struct {
	KeyTagOverride uint16
	*dnsutil.DnssecProvider
}

func (p *BadDnssecProvider) Prove(req, resp *dns.Msg, validFrom, validTo uint32) error {
	if p == nil {
		return nil
	}
	err := p.DnssecProvider.Prove(req, resp, validFrom, validTo)
	if err != nil {
		return err
	}
	ourKeyTag := p.SigningKey.KeyTag()
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			if rr.(*dns.RRSIG).KeyTag == ourKeyTag {
				rr.(*dns.RRSIG).KeyTag = p.KeyTagOverride
			}
		}
	}
	for _, rr := range resp.Ns {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			if rr.(*dns.RRSIG).KeyTag == ourKeyTag {
				rr.(*dns.RRSIG).KeyTag = p.KeyTagOverride
			}
		}
	}
	return nil
}

type DnscheckHandler struct {
	*dnsutil.DnssecProvider
	Zone                 string
	Ns                   []string
	HostMasterMbox       string
	StaticRecords        dnsutil.StaticRecords
	LargeResponseLimiter *rate.Limiter
	// MaxDiagnosticUDPSize explicitly opts in to limited oversized UDP tests.
	// Zero keeps the normal UDP limit even for "notruncate"; TCP/TLS/QUIC still
	// support larger diagnostics. Values above 4096 are clamped to 4096.
	MaxDiagnosticUDPSize int
	// SigningLimiter bounds on-demand signing work across configured zones.
	// The application config supplies a shared limiter.
	SigningLimiter    *rate.Limiter
	Watchers          WatcherHub
	IPInfoClient      *httputil.IPInfoClient
	BadDnssecProvider *BadDnssecProvider
	soaSig            atomic.Pointer[dns.RRSIG]
	soaRefresh        *dnsutil.SOASignatureRefresher
}

// InitContext initializes a handler before it serves requests. The caller must
// cancel ctx and call WaitForRefresh when stopping the handler.
func (h *DnscheckHandler) InitContext(ctx context.Context, privKeyBytes []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if h == nil || len(h.Ns) == 0 {
		return fmt.Errorf("DNS handler requires at least one nameserver")
	}
	h.Zone = dns.CanonicalName(h.Zone)
	for i, ns := range h.Ns {
		h.Ns[i] = dns.CanonicalName(ns)
	}
	if len(h.HostMasterMbox) == 0 {
		h.HostMasterMbox = "hostmaster." + h.Zone
	} else {
		h.HostMasterMbox = dns.CanonicalName(h.HostMasterMbox)
	}
	if h.DnssecProvider != nil {
		if h.DnssecProvider.SigningKey == nil {
			return fmt.Errorf("missing signing key")
		}
		h.DnssecProvider.SigningKey.Hdr.Name = h.Zone
		h.DnssecProvider.SigningKey.Hdr.Rrtype = dns.TypeDNSKEY
		h.DnssecProvider.SigningKey.Hdr.Class = dns.ClassINET
		h.DnssecProvider.SigningKey.Hdr.Ttl = 1800
		h.DnssecProvider.SigningKey.Flags = 257  // Secure Entry Point
		h.DnssecProvider.SigningKey.Protocol = 3 // DNSSEC
		err := h.DnssecProvider.SetPrivKeyBytes(privKeyBytes)
		if err != nil {
			return err
		}
		h.BadDnssecProvider = &BadDnssecProvider{KeyTagOverride: h.DnssecProvider.SigningKey.KeyTag()}
		h.BadDnssecProvider.DnssecProvider, err = dnsutil.GenerateDnssecProvider(
			h.Zone,
			h.DnssecProvider.SigningKey.Algorithm,
			h.DnssecProvider.SigningKey.Hdr.Ttl,
		)
		if err != nil {
			return err
		}
		h.soaRefresh, err = dnsutil.StartSOASignatureRefresh(ctx, h.DnssecProvider, h.SOA(nil, false)[0].(*dns.SOA), h.soaSig.Store)
		if err != nil {
			return err
		}
	}
	return nil
}

func (h *DnscheckHandler) WaitForRefresh() error {
	return h.soaRefresh.Wait()
}

func (h *DnscheckHandler) SOA(q *dns.Question, includeSig bool) (rrs []dns.RR) {
	var name string
	if q == nil {
		name = h.Zone
	} else {
		name = q.Name[len(q.Name)-len(h.Zone):]
	}
	if includeSig {
		rrs = make([]dns.RR, 1, 2)
	} else {
		rrs = make([]dns.RR, 1)
	}
	rrs[0] = &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    1800,
		},
		Ns:      h.Ns[0],
		Mbox:    h.HostMasterMbox,
		Serial:  1,
		Refresh: 1800,
		Retry:   1800,
		Expire:  3600,
		Minttl:  1800,
	}
	if !includeSig {
		return
	}
	if sig := h.soaSig.Load(); sig != nil {
		rrs = append(rrs, dns.Copy(sig))
		rrs[1].Header().Name = name
	}
	return
}

func (h *DnscheckHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || req.Response || len(req.Question) != 1 {
		return
	}
	q := &req.Question[0]
	if len(q.Name) < len(h.Zone) || !dns.IsSubDomain(h.Zone, q.Name) {
		w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeNotAuth))
		return
	}
	sub := q.Name[:len(q.Name)-len(h.Zone)]
	opts := ParseOptions(sub)
	proto := dnsutil.GetProtocol(w)
	// queries only
	if req.Opcode != dns.OpcodeQuery {
		w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented))
		return
	}
	// prepare response, defer send
	resp := new(dns.Msg).SetReply(req)
	resp.Authoritative = true
	defer func() {
		if resp != nil {
			w.WriteMsg(resp)
		}
	}()
	if len(req.Answer) != 0 || len(req.Ns) != 0 || len(req.Extra) > 2 {
		resp.Rcode = dns.RcodeFormatError
		return
	}
	// edns
	err := dnsutil.CheckAndSetEdns(req, resp)
	if err != nil {
		// Rcode already set by CheckAndSetEdns
		return
	}
	// class IN only
	if q.Qclass != dns.ClassINET {
		resp.Rcode = dns.RcodeNotImplemented
		return
	}
	// allowed types only
	switch q.Qtype {
	case dns.TypeOPT, dns.TypeNXNAME:
		resp.Rcode = dns.RcodeFormatError
		return
	case dns.TypeRRSIG, dns.TypeNSEC:
		resp.Rcode = dns.RcodeRefused
		return
	case dns.TypeANY:
		// meta type handled later
	default:
		// unhandled meta types
		if q.Qtype&128 != 0 {
			resp.Rcode = dns.RcodeNotImplemented
			return
		}
	}
	// Only validated query metadata reaches a watcher, after opcode, section,
	// EDNS, class and query-type checks. The public ID is correlation data, not
	// proof that the query came from this browser's resolver.
	if opts != nil && len(opts.Random) > 0 && h.Watchers != nil {
		if watcher := h.Watchers.Get(opts.Random); watcher != nil {
			watcher.Send(req, proto, w.RemoteAddr(), w.(dns.ConnectionStater).ConnectionState())
		}
	}
	// Charge diagnostic work before constructing or signing its response. A
	// missing limiter fails closed for expensive opt-in features.
	diagnosticTokens := 0
	if opts != nil && (opts.NoTruncate || opts.TxtFill != 0) {
		if h.LargeResponseLimiter == nil || !h.LargeResponseLimiter.Allow() {
			resp.Rcode = dns.RcodeRefused
			return
		}
		diagnosticTokens = 1
	}
	// defer compress, truncate, padding
	defer func() {
		if opts != nil && opts.Compress {
			resp.Compress = true
		}
		switch proto {
		case dnsutil.ProtoUDP:
			if opts != nil && opts.Truncate {
				resp.Truncated = true
				resp.Answer = nil
				resp.Ns = nil
				break
			}
			maxSize := dnsutil.GetMaxUdpSize(req)
			if opts != nil && opts.NoTruncate && h.MaxDiagnosticUDPSize > maxSize {
				if opt := req.IsEdns0(); opt != nil {
					maxSize = min(h.MaxDiagnosticUDPSize, max(dns.MinMsgSize, int(opt.UDPSize())), 4096)
				}
			}
			resp.Truncate(maxSize)
			if opts != nil && opts.Compress {
				resp.Compress = true
			}
			// All oversized answer paths share the same byte-weighted budget;
			// this includes DNSKEY and signed negative answers, not only TXT.
			if size := resp.Len(); size > dnsutil.MaxUdpMsgSize {
				tokens := (size + dnsutil.MaxUdpMsgSize - 1) / dnsutil.MaxUdpMsgSize
				if h.LargeResponseLimiter == nil || !h.LargeResponseLimiter.AllowN(time.Now(), tokens-diagnosticTokens) {
					resp = new(dns.Msg).SetRcode(req, dns.RcodeRefused)
				}
			}
		case dnsutil.ProtoTLS, dnsutil.ProtoQUIC:
			if dnsutil.HasPadding(req) {
				dnsutil.AddPadding(resp, dnsutil.ResponsePaddingBlockLength)
			}
		}
	}()
	// defer dnssec proof
	defer func() {
		if opts != nil && opts.NoSig {
			return
		}
		if h.DnssecProvider != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
			if opt := req.IsEdns0(); opt != nil && opt.Do() && h.SigningLimiter != nil && !h.SigningLimiter.Allow() {
				resp = new(dns.Msg).SetRcode(req, dns.RcodeRefused)
				return
			}
		}
		var validFrom, validTo uint32
		if opts != nil && opts.ExpiredSig != 0 {
			validTo = uint32(time.Now().Unix()) - uint32(opts.ExpiredSig)
			validFrom = validTo - 7200
			if len(resp.Answer) > 0 {
				validFrom -= resp.Answer[0].Header().Ttl
			} else if len(resp.Ns) > 0 {
				validFrom -= resp.Ns[0].Header().Ttl
			}
		}
		var err error
		if opts != nil && opts.BadSig {
			err = h.BadDnssecProvider.Prove(req, resp, validFrom, validTo)
		} else {
			err = h.DnssecProvider.Prove(req, resp, validFrom, validTo)
		}
		if err != nil {
			log.Printf("[error] DnssecProvider.Prove: %v", err)
			resp = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		}
	}()
	// provide dnssec keys
	if h.ProvideKeys(req, resp) {
		return // no further answers
	}
	// defer adding SOA if no answers
	defer func() {
		if (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) || resp.Rcode == dns.RcodeNameError {
			opt := req.IsEdns0()
			resp.Ns = append(resp.Ns, h.SOA(q, opt != nil && opt.Do())...)
		}
	}()
	// assume domain does not exist until validated below
	resp.Rcode = dns.RcodeNameError
	// apex records
	if len(q.Name) == len(h.Zone) {
		resp.Rcode = dns.RcodeSuccess
		switch q.Qtype {
		case dns.TypeSOA:
			opt := req.IsEdns0()
			resp.Answer = append(resp.Answer, h.SOA(q, opt != nil && opt.Do())...)
		case dns.TypeNS:
			for _, ns := range h.Ns {
				resp.Answer = append(resp.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    1800,
					},
					Ns: ns,
				})
			}
		}
	}
	// static records
	if h.StaticRecords != nil {
		rrs, validName := h.StaticRecords.Get(q)
		if len(rrs) > 0 {
			resp.Answer = append(resp.Answer, rrs...)
		}
		if validName {
			resp.Rcode = dns.RcodeSuccess
		}
	}
	// validate options
	if opts == nil {
		if resp.Rcode == dns.RcodeNameError {
			if opt := resp.IsEdns0(); opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeOther,
					ExtraText: "invalid subdomain options",
				})
			}
		}
		return
	}
	resp.Rcode = dns.RcodeSuccess
	// error response requested
	if opts.Rcode != 0 {
		resp.Rcode = opts.Rcode
		return
	}
	// handle ANY queries
	if q.Qtype == dns.TypeANY && len(resp.Answer) == 0 {
		resp.Answer = append(resp.Answer, &dns.HINFO{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeHINFO,
				Class:  dns.ClassINET,
				Ttl:    1800,
			},
			Cpu: "RFC8482",
			Os:  "",
		})
		return
	}
	// other records
	switch q.Qtype {
	case dns.TypeA:
		if opts.NullIP {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				A: net.IPv4zero,
			})
		} else if len(q.Name) > len(h.Zone) && h.StaticRecords != nil {
			rrs, _ := h.StaticRecords.Get(&dns.Question{Name: h.Zone, Qtype: q.Qtype, Qclass: q.Qclass})
			for _, rr := range rrs {
				if rr.Header().Rrtype != dns.TypeA {
					continue
				}
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					A: rr.(*dns.A).A,
				})
			}
		}
	case dns.TypeAAAA:
		if opts.NullIP {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				AAAA: net.IPv6zero,
			})
		} else if len(q.Name) > len(h.Zone) && h.StaticRecords != nil {
			rrs, _ := h.StaticRecords.Get(&dns.Question{Name: h.Zone, Qtype: q.Qtype, Qclass: q.Qclass})
			for _, rr := range rrs {
				if rr.Header().Rrtype != dns.TypeAAAA {
					continue
				}
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    1,
					},
					AAAA: rr.(*dns.AAAA).AAAA,
				})
			}
		}
	case dns.TypeHTTPS:
		if opts.NullIP {
			break
		}
		if len(q.Name) > len(h.Zone) && h.StaticRecords != nil {
			rrs, _ := h.StaticRecords.Get(&dns.Question{Name: h.Zone, Qtype: q.Qtype, Qclass: q.Qclass})
			for _, rr := range rrs {
				if rr.Header().Rrtype == dns.TypeHTTPS {
					https := rr.(*dns.HTTPS)
					resp.Answer = append(resp.Answer, &dns.HTTPS{SVCB: dns.SVCB{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeHTTPS,
							Class:  dns.ClassINET,
							Ttl:    1,
						},
						Priority: https.Priority,
						Target:   https.Target,
						Value:    https.Value,
					}})
					break
				}
			}
		}
	case dns.TypeTXT:
		if opts.TxtFill != 0 {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				Txt: dnsutil.SplitForTxt(strings.Repeat("0", opts.TxtFill)),
			})
			break // no more txts
		}
		var ip string
		var port int
		switch a := w.RemoteAddr().(type) {
		case *net.UDPAddr:
			ip = a.IP.String()
			port = a.Port
		case *net.TCPAddr:
			ip = a.IP.String()
			port = a.Port
		}
		txts := make([]string, 2, 5)
		txts[0] = fmt.Sprintf("FROM: %s#%d (%s)", ip, port, proto)
		if h.IPInfoClient != nil {
			info, err := h.IPInfoClient.GetIPInfo(ip)
			if err != nil {
				log.Printf("[error] DnscheckHandler.ServeDNS: IPInfoClient.GetIPInfo: %v", err)
			}
			if info != nil {
				if len(info.Org) > 0 {
					txts[0] += fmt.Sprintf(" - %s", dnsutil.ToPrintableAscii(info.Org))
				}
				if geo := info.GeoString(); len(geo) > 0 {
					txts[0] += fmt.Sprintf(" - %s", dnsutil.ToPrintableAscii(geo))
				}
			}
		}
		txts[1] = fmt.Sprintf("ID: %d", req.Id)
		if opt := req.IsEdns0(); opt != nil {
			var flags string
			if opt.Do() {
				flags += " do"
			}
			if opt.Co() {
				flags += " co"
			}
			// txts[2]
			txts = append(txts, fmt.Sprintf("EDNS: version: %d; flags:%s; udp: %d", opt.Version(), flags, opt.UDPSize()))
			for _, o := range opt.Option {
				if o.Option() == dns.EDNS0SUBNET {
					subnet := o.(*dns.EDNS0_SUBNET)
					// txts[3]
					txts = append(txts, fmt.Sprintf("ECS: %s/%d", subnet.Address, subnet.SourceNetmask))
					if h.IPInfoClient != nil {
						info, err := h.IPInfoClient.GetIPInfo(subnet.Address.String())
						if err != nil {
							log.Printf("[error] DnscheckHandler.ServeDNS: IPInfoClient.GetIPInfo: %v", err)
						}
						if info != nil {
							if len(info.Org) > 0 {
								txts[3] += fmt.Sprintf(" - %s", dnsutil.ToPrintableAscii(info.Org))
							}
							if geo := info.GeoString(); len(geo) > 0 {
								txts[3] += fmt.Sprintf(" - %s", dnsutil.ToPrintableAscii(geo))
							}
						}
					}
					break
				}
			}
		}
		if cs := w.(dns.ConnectionStater).ConnectionState(); cs != nil {
			tlsVersion := strings.ReplaceAll(tls.VersionName(cs.Version), " ", "")
			var used0RTT bool
			if proto == dnsutil.ProtoQUIC {
				// hack: QUIC version stored in TLSUnique by QUICStreamListener
				txts = append(txts, fmt.Sprintf("QUIC: (%s)-(%s)-(%s)-(%s)", cs.TLSUnique, tlsVersion, cs.CurveID, tls.CipherSuiteName(cs.CipherSuite)))
				// hack: Used0RTT stored in NegotiatedProtocolIsMutual by QUICStreamListener
				used0RTT = cs.NegotiatedProtocolIsMutual
			} else {
				txts = append(txts, fmt.Sprintf("TLS: (%s)-(%s)-(%s)", tlsVersion, cs.CurveID, tls.CipherSuiteName(cs.CipherSuite)))
			}
			if cs.DidResume {
				txts[len(txts)-1] += " resumed"
			}
			if used0RTT {
				txts[len(txts)-1] += " 0-rtt"
			}
		}
		for _, txt := range txts {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				Txt: dnsutil.SplitForTxt(txt),
			})
		}
	case dns.TypeMX:
		resp.Answer = append(resp.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			Preference: 0,
			Mx:         ".",
		})
	}
}
