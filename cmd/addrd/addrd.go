// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/efrgdgr0024345/dnscheck/internal/config"
	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/miekg/dns"
)

var revision = "development"

func keygen(zone string, alg uint8) {
	dnssecProvider, err := dnsutil.GenerateDnssecProvider(dns.CanonicalName(zone), alg, 1800)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ds, _ := dnssecProvider.DS()
	privKey, _ := dnssecProvider.PrivKeyBytes()
	fmt.Printf("%s\n%s ;privKey: %s\n", ds, dnssecProvider.SigningKey, base64.StdEncoding.EncodeToString(privKey))
	os.Exit(0)
}

func main() {
	var showVersion bool
	var checkConfig bool
	var keygenAlg uint
	var configPath, keygenZone string
	flag.BoolVar(&showVersion, "version", false, "show revision and source attribution, then exit")
	flag.BoolVar(&checkConfig, "check-config", false, "validate configuration without opening listeners")
	flag.StringVar(&configPath, "c", "", "configuration `file`")
	flag.StringVar(&keygenZone, "k", "", "generate DNSSEC keys for the specified `zone` and exit")
	flag.UintVar(&keygenAlg, "a", uint(dns.ECDSAP256SHA256), "use `algorithm` when generating DNSSEC keys")
	flag.Parse()
	if showVersion {
		fmt.Printf("dnscheck addrd %s\nSource: https://github.com/efrgdgr0024345/dnscheck\nOriginal: Brian Shea / addr.tools; AGPL-3.0-or-later\n", revision)
		return
	}
	if len(configPath) == 0 && len(keygenZone) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if len(keygenZone) > 0 {
		keygen(keygenZone, uint8(keygenAlg))
	}
	// load config, go!
	c := config.ParseConfig(configPath)
	if checkConfig {
		fmt.Println("Configuration structure and DNSSEC keys are valid; deployment reachability has not been tested.")
		return
	}
	if err := c.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
