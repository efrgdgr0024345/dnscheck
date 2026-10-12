// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"

	"github.com/efrgdgr0024345/dnscheck/internal/dns2json"
	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/miekg/dns"
)

func validateZone(zone string, nameservers []string, provider *dnsutil.DnssecProvider, private string) error {
	if _, ok := dns.IsDomainName(zone); !ok || zone == "" || zone == "." {
		return errors.New("a non-root zone name is required")
	}
	if len(nameservers) == 0 {
		return fmt.Errorf("%s: at least one nameserver is required", zone)
	}
	for _, name := range nameservers {
		if _, ok := dns.IsDomainName(name); !ok || name == "" {
			return fmt.Errorf("%s: invalid nameserver", zone)
		}
	}
	if provider == nil {
		if private != "" {
			return fmt.Errorf("%s: private key has no signing-key configuration", zone)
		}
		return nil
	}
	if provider.SigningKey == nil {
		return fmt.Errorf("%s: missing DNSSEC signing key", zone)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(private)
	if err != nil {
		return fmt.Errorf("%s: malformed DNSSEC private key", zone)
	}
	if err := provider.SetPrivKeyBytes(key); err != nil {
		return fmt.Errorf("%s: invalid DNSSEC key material: %w", zone, err)
	}
	return nil
}

func (config *Config) Validate() error {
	if (config.AdminSocketPath == "") != (config.AdminTokenFile == "") {
		return errors.New("AdminSocketPath and AdminTokenFile must be configured together")
	}
	if config.AdminSocketPath != "" && config.AdminSocketPath == config.HTTPSocketPath {
		return errors.New("administrative and public sockets must differ")
	}
	if (config.TLSCertPath == "") != (config.TLSKeyPath == "") {
		return errors.New("TLSCertPath and TLSKeyPath must be configured together")
	}
	for _, address := range []string{config.DNSListenAddress, config.TLSListenAddress} {
		if address != "" {
			if _, _, err := net.SplitHostPort(address); err != nil {
				return fmt.Errorf("invalid listener address: %w", err)
			}
		}
	}
	for _, h := range config.DnscheckZones {
		if h.DnscheckHandler == nil {
			return errors.New("empty DNS-check zone configuration")
		}
		if err := validateZone(h.Zone, h.Ns, h.DnssecProvider, h.PrivateKey); err != nil {
			return err
		}
	}
	for _, h := range config.MyaddrZones {
		if h.SimpleHandler == nil {
			return errors.New("empty registered-name zone configuration")
		}
		if err := validateZone(h.Zone, h.Ns, h.DnssecProvider, h.PrivateKey); err != nil {
			return err
		}
	}
	if h := config.ChallengesZone; h.SimpleHandler != nil {
		if err := validateZone(h.Zone, h.Ns, h.DnssecProvider, h.PrivateKey); err != nil {
			return err
		}
	}
	if h := config.DynZone; h.SimpleHandler != nil {
		if err := validateZone(h.Zone, h.Ns, h.DnssecProvider, h.PrivateKey); err != nil {
			return err
		}
	}
	if config.LookupUpstream != "" {
		return (&dns2json.LookupHandler{Upstream: config.LookupUpstream, Network: config.LookupNetwork, TLSName: config.LookupTLSName, AllowInsecure: config.AllowInsecureLookup}).Validate()
	}
	return nil
}
