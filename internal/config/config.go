// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/efrgdgr0024345/dnscheck/internal/dns2json"
	"github.com/efrgdgr0024345/dnscheck/internal/dnsutil"
	"github.com/efrgdgr0024345/dnscheck/internal/httputil"
	"github.com/efrgdgr0024345/dnscheck/internal/netutil"
	"github.com/efrgdgr0024345/dnscheck/internal/status"
	"github.com/efrgdgr0024345/dnscheck/internal/ttlstore"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/challenges"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/dnscheck"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/dyn"
	"github.com/efrgdgr0024345/dnscheck/internal/zones/myaddr"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"
)

const (
	MaxDnscheckWatchers          = 100
	MaxDnscheckLargeResponseRate = 10 // per second
)

type Config struct {
	HTTPSocketPath               string
	AdminSocketPath              string
	AdminTokenFile               string
	DNSListenAddress             string
	TLSListenAddress             string
	WatcherAllowedOrigins        []string
	WatcherTrustedClientIPHeader string
	WatcherMaxPerClient          int
	LookupNetwork                string
	LookupTLSName                string
	AllowInsecureLookup          bool
	MyaddrTurnstileHostname      string
	MyaddrTurnstileAction        string
	RequestLogPath               string
	DatabasePath                 string
	ValkeyURL                    string
	TLSCertPath                  string
	TLSKeyPath                   string
	TLSTicketKeysPath            string
	QUICMasterSecret             string
	LookupUpstream               string
	IPInfoBaseURL                string
	MyaddrTurnstileSecret        string
	DnscheckZones                []struct {
		*dnscheck.DnscheckHandler
		PrivateKey string
	}
	ChallengesZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	DynZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	MyaddrZones []struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
}

func ParseConfig(path string) *Config {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	config, err := decodeConfiguration(f)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

// Run serves until SIGINT/SIGTERM or a listener failure, then drains services
// and persists state before returning an error to the command-line caller.
func (config *Config) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return config.RunContext(ctx)
}

// RunContext provides the same lifecycle with an explicit cancellation source.
func (config *Config) RunContext(ctx context.Context) (runErr error) {
	if err := config.Validate(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil
	}
	services := newServiceRuntime(ctx)
	backgroundCtx, cancelBackground := context.WithCancel(context.Background())
	defer cancelBackground()
	var backgroundWaitGroup sync.WaitGroup
	var finalizers []func() error
	publicMux := http.NewServeMux()
	adminMux := http.NewServeMux()
	dnsMux := dns.NewServeMux()
	var adminToken string
	if (config.AdminSocketPath == "") != (config.AdminTokenFile == "") {
		return errors.New("AdminSocketPath and AdminTokenFile must be configured together")
	}
	if config.AdminSocketPath != "" {
		if config.AdminSocketPath == config.HTTPSocketPath {
			return errors.New("administrative and public sockets must be different")
		}
		var err error
		adminToken, err = loadAdminToken(config.AdminTokenFile)
		if err != nil {
			return err
		}
	}
	if config.DNSListenAddress == "" {
		config.DNSListenAddress = ":53"
	}
	if config.TLSListenAddress == "" {
		config.TLSListenAddress = ":853"
	}
	periodic := func(interval time.Duration, task func()) {
		backgroundWaitGroup.Go(func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-backgroundCtx.Done():
					return
				case <-ticker.C:
					task()
				}
			}
		})
	}
	defer func() {
		// Cancellation during startup is a normal stop, not a listener error.
		if ctx.Err() != nil && errors.Is(runErr, ctx.Err()) {
			runErr = nil
		}
		cancelBackground()
		backgroundWaitGroup.Wait()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if err := services.shutdown(shutdownCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("graceful shutdown: %w", err))
		}
		// State snapshots and database/log closes follow the request drain.
		for _, finalize := range finalizers {
			if err := finalize(); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("finalize service state: %w", err))
			}
		}
	}()
	initZone := func(zone string, handler interface {
		InitContext(context.Context, []byte) error
		WaitForRefresh() error
	}, encodedKey string) error {
		key, err := base64.StdEncoding.Strict().DecodeString(encodedKey)
		if err != nil {
			return fmt.Errorf("decode private key for %s: %w", zone, err)
		}
		if err := handler.InitContext(backgroundCtx, key); err != nil {
			return fmt.Errorf("initialize DNS zone %s: %w", zone, err)
		}
		backgroundWaitGroup.Go(func() {
			if err := handler.WaitForRefresh(); err != nil {
				services.report("DNSSEC refresh for "+zone, err)
			}
		})
		return nil
	}

	// init status handler, uptime
	statusHandler := new(status.StatusHandler)
	statusHandler.Add(status.NewUptimeProvider())
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{
			{Title: "source", Value: "https://github.com/efrgdgr0024345/dnscheck"},
			{Title: "upstream", Value: "https://github.com/brianshea2/addr.tools"},
			{Title: "license", Value: "AGPL-3.0-or-later"},
		}
	}))
	statusZone := &dnsutil.SimpleHandler{
		Zone:            "status.",
		Ns:              []string{"invalid."}, // not delegated
		RecordGenerator: statusHandler,
	}
	if err := initZone(statusZone.Zone, statusZone, ""); err != nil {
		return err
	}
	dnsMux.Handle(statusZone.Zone, statusZone)

	// init dns request logger
	var requestLogger *log.Logger
	if len(config.RequestLogPath) > 0 {
		requestLogFile, err := os.OpenFile(config.RequestLogPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
		buffer := bufio.NewWriter(requestLogFile)
		finalizers = append(finalizers, func() error { return errors.Join(buffer.Flush(), requestLogFile.Close()) })
		requestLogger = log.New(buffer, "", log.LstdFlags)
	}
	dnsHandler := &dnsutil.LoggingHandler{
		Logger: requestLogger,
		Next:   dnsMux,
	}
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{
			{Title: "net.ipv4", Value: strconv.FormatUint(dnsHandler.IP4Count(), 10)},
			{Title: "net.ipv6", Value: strconv.FormatUint(dnsHandler.IP6Count(), 10)},
			{Title: "proto.udp", Value: strconv.FormatUint(dnsHandler.UDPCount(), 10)},
			{Title: "proto.tcp", Value: strconv.FormatUint(dnsHandler.TCPCount(), 10)},
			{Title: "proto.tls", Value: strconv.FormatUint(dnsHandler.TLSCount(), 10)},
			{Title: "proto.quic", Value: strconv.FormatUint(dnsHandler.QUICCount(), 10)},
		}
	}))

	// init valkey client
	var valkeyClient valkey.Client
	if len(config.ValkeyURL) > 0 {
		opt, err := valkey.ParseURL(config.ValkeyURL)
		if err != nil {
			return errors.New("invalid ValkeyURL; check scheme, address, database and options (value suppressed)")
		}
		valkeyClient, err = valkey.NewClient(opt)
		if err != nil {
			return err
		}
		finalizers = append(finalizers, func() error { valkeyClient.Close(); return nil })
		log.Print("[info] connected to configured Valkey database")
	}

	// init persistent data store
	var persistentStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		periodic(time.Hour, simpleStore.Prune)
		if len(config.DatabasePath) > 0 {
			if err := simpleStore.LoadFile(config.DatabasePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			finalizers = append(finalizers, func() error {
				return simpleStore.WriteFile(config.DatabasePath)
			})
			periodic(time.Minute, func() {
				if err := simpleStore.WriteFile(config.DatabasePath); err != nil {
					log.Printf("[error] database snapshot failed; will retry: %v", err)
				}
			})
			log.Printf("[info] loaded database, size %v", simpleStore.Size())
		}
		persistentStore = simpleStore
	} else {
		client := &ttlstore.ValkeyClient{Client: valkeyClient}
		if err := client.CheckConfiguration(); err != nil {
			return err
		}
		persistentStore = client
		periodic(time.Minute, func() {
			if err := client.Prune(); err != nil {
				log.Printf("[error] database quota pruning: %v", err)
			}
		})
	}

	// init temporary challenge record store
	var challengeStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		periodic(time.Minute, simpleStore.Prune)
		challengeStore = simpleStore
	} else {
		challengeStore = &ttlstore.Prefixed{
			Store:  &ttlstore.ValkeyClient{Client: valkeyClient},
			Prefix: "challenge:",
		}
	}

	// init and set dnscheck handlers
	if len(config.DnscheckZones) > 0 {
		var ipinfoClient *httputil.IPInfoClient
		if len(config.IPInfoBaseURL) > 0 {
			ipinfoClient = &httputil.IPInfoClient{
				BaseURL:    config.IPInfoBaseURL,
				HttpClient: http.Client{Timeout: time.Second},
			}
		}
		largeResponseLimiter := rate.NewLimiter(rate.Limit(MaxDnscheckLargeResponseRate), MaxDnscheckLargeResponseRate)
		signingLimiter := rate.NewLimiter(200, 200)
		watcherHub := &dnscheck.SimpleWatcherHub{MaxSize: MaxDnscheckWatchers}
		for _, h := range config.DnscheckZones {
			h.DnscheckHandler.IPInfoClient = ipinfoClient
			h.DnscheckHandler.LargeResponseLimiter = largeResponseLimiter
			h.DnscheckHandler.SigningLimiter = signingLimiter
			h.DnscheckHandler.Watchers = watcherHub
			if err := initZone(h.DnscheckHandler.Zone, h.DnscheckHandler, h.PrivateKey); err != nil {
				return err
			}
			dnsMux.Handle(h.DnscheckHandler.Zone, h.DnscheckHandler)
		}
		watchHandler := dnscheck.NewWebsocketHandler(watcherHub)
		watchHandler.AllowedOrigins = config.WatcherAllowedOrigins
		watchHandler.TrustedClientIPHeader = config.WatcherTrustedClientIPHeader
		if config.WatcherMaxPerClient > 0 {
			watchHandler.MaxPerClient = config.WatcherMaxPerClient
		}
		publicMux.Handle("/watch/{watcher}", watchHandler)
		services.addStopper("DNS watchers", watchHandler.Shutdown)
		statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
			return []status.Status{{Title: "watchers", Value: strconv.Itoa(watcherHub.Size())}}
		}))
	}

	// init and set challenges handler
	if config.ChallengesZone.SimpleHandler != nil {
		config.ChallengesZone.SimpleHandler.RecordGenerator = &challenges.RecordGenerator{
			ChallengeStore: challengeStore,
		}
		if err := initZone(config.ChallengesZone.SimpleHandler.Zone, config.ChallengesZone.SimpleHandler, config.ChallengesZone.PrivateKey); err != nil {
			return err
		}
		dnsMux.Handle(config.ChallengesZone.SimpleHandler.Zone, config.ChallengesZone.SimpleHandler)
		publicMux.Handle("/challenges", &challenges.HTTPHandler{
			ChallengeStore: challengeStore,
			Zone:           config.ChallengesZone.SimpleHandler.Zone,
		})
	}

	// init and set dyn handler
	if config.DynZone.SimpleHandler != nil {
		config.DynZone.SimpleHandler.RecordGenerator = &dyn.RecordGenerator{
			DataStore: persistentStore,
		}
		if err := initZone(config.DynZone.SimpleHandler.Zone, config.DynZone.SimpleHandler, config.DynZone.PrivateKey); err != nil {
			return err
		}
		dnsMux.Handle(config.DynZone.SimpleHandler.Zone, config.DynZone.SimpleHandler)
		publicMux.Handle("/dyn", &dyn.HTTPHandler{
			DataStore: persistentStore,
			Zone:      config.DynZone.SimpleHandler.Zone,
		})
	}

	// init and set myaddr handlers
	if len(config.MyaddrZones) > 0 {
		myaddrDataStore := &ttlstore.Prefixed{Store: persistentStore, Prefix: "myaddr:"}
		for _, h := range config.MyaddrZones {
			h.SimpleHandler.RecordGenerator = &myaddr.RecordGenerator{
				DataStore: myaddrDataStore,
			}
			if err := initZone(h.SimpleHandler.Zone, h.SimpleHandler, h.PrivateKey); err != nil {
				return err
			}
			dnsMux.Handle(h.SimpleHandler.Zone, h.SimpleHandler)
		}
		if adminToken != "" {
			adminMux.Handle("/admin/myaddr", requireAdminToken(adminToken, &myaddr.AdminHandler{DataStore: myaddrDataStore}))
		}
		publicMux.Handle("/myaddr-reg", &myaddr.RegistrationHandler{
			DataStore: myaddrDataStore,
			TurnstileClient: &httputil.TurnstileClient{
				Secret:           config.MyaddrTurnstileSecret,
				ExpectedHostname: config.MyaddrTurnstileHostname,
				ExpectedAction:   config.MyaddrTurnstileAction,
				HttpClient:       http.Client{Timeout: 5 * time.Second},
			},
		})
		publicMux.Handle("/myaddr-update", &myaddr.UpdateHandler{
			DataStore: myaddrDataStore,
		})
	}

	// set dns lookup handler
	if len(config.LookupUpstream) > 0 {
		lookup := &dns2json.LookupHandler{Upstream: config.LookupUpstream, Network: config.LookupNetwork, TLSName: config.LookupTLSName, AllowInsecure: config.AllowInsecureLookup}
		if err := lookup.Validate(); err != nil {
			return err
		}
		publicMux.Handle("/dns/{name}/{type}", lookup)
	}

	// Bind synchronously, then wait for each DNS server's readiness notification
	// before startup continues. A bind failure cannot leave an orphan listener.
	var listenConfig net.ListenConfig
	udpConn, err := listenConfig.ListenPacket(ctx, "udp", config.DNSListenAddress)
	if err != nil {
		return fmt.Errorf("bind DNS UDP listener: %w", err)
	}
	if err := services.startDNS("DNS UDP", &dns.Server{
		PacketConn: udpConn, MsgAcceptFunc: dnsutil.MsgAcceptFunc, Handler: dnsHandler,
	}, nil); err != nil {
		return err
	}
	tcpListener, err := listenConfig.Listen(ctx, "tcp", config.DNSListenAddress)
	if err != nil {
		return fmt.Errorf("bind DNS TCP listener: %w", err)
	}
	if err := services.startDNS("DNS TCP", &dns.Server{
		Listener:      &netutil.WriteTimeoutListener{Listener: tcpListener, Timeout: 2 * time.Second},
		MsgAcceptFunc: dnsutil.MsgAcceptFunc, Handler: dnsHandler,
	}, nil); err != nil {
		return err
	}
	if config.TLSCertPath != "" {
		cert, err := tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		var ticketKeyMgr *SessionTicketKeyManager
		if config.TLSTicketKeysPath != "" {
			ticketKeyMgr, err = NewSessionTicketKeyManager(config.TLSTicketKeysPath)
			if err != nil {
				return fmt.Errorf("load TLS ticket keys: %w", err)
			}
			finalizers = append(finalizers, ticketKeyMgr.Close)
		}
		dotTLS := &tls.Config{
			NextProtos: []string{"dot"}, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024,
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
		if ticketKeyMgr != nil {
			ticketKeyMgr.AddConfig(dotTLS, "dot")
		}
		dotListener, err := listenConfig.Listen(ctx, "tcp", config.TLSListenAddress)
		if err != nil {
			return fmt.Errorf("bind DNS-over-TLS listener: %w", err)
		}
		if err := services.startDNS("DNS over TLS", &dns.Server{
			Listener:      &netutil.WriteTimeoutListener{Listener: tls.NewListener(dotListener, dotTLS), Timeout: 2 * time.Second},
			MsgAcceptFunc: dnsutil.MsgAcceptFunc, Handler: dnsHandler,
		}, nil); err != nil {
			return err
		}

		doqTLS := &tls.Config{
			NextProtos: []string{"doq"}, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024,
				tls.X25519, tls.CurveP256, tls.CurveP384,
			},
		}
		if ticketKeyMgr != nil {
			ticketKeyMgr.AddConfig(doqTLS, "doq")
		}
		quicConfig := &quic.Config{
			MaxIncomingStreams: 128, MaxIncomingUniStreams: -1,
			Allow0RTT: false, // Replayable early data is not needed by the checker.
		}
		var statelessResetKey *quic.StatelessResetKey
		var tokenGeneratorKey *quic.TokenGeneratorKey
		if config.QUICMasterSecret != "" {
			secret, err := base64.StdEncoding.Strict().DecodeString(config.QUICMasterSecret)
			if err != nil || len(secret) != 32 {
				return errors.New("QUICMasterSecret must contain 32 random bytes encoded as base64")
			}
			key1, err := hkdf.Key(sha256.New, secret, nil, "stateless-reset-key", 32)
			if err != nil {
				return err
			}
			key2, err := hkdf.Key(sha256.New, secret, nil, "token-generator-key", 32)
			if err != nil {
				return err
			}
			statelessResetKey = (*quic.StatelessResetKey)(key1)
			tokenGeneratorKey = (*quic.TokenGeneratorKey)(key2)
		}
		quicUDP, err := listenConfig.ListenPacket(ctx, "udp", config.TLSListenAddress)
		if err != nil {
			return fmt.Errorf("bind DNS-over-QUIC listener: %w", err)
		}
		retryLimiter := rate.NewLimiter(100, 100)
		quicTransport := &quic.Transport{
			Conn: quicUDP, StatelessResetKey: statelessResetKey, TokenGeneratorKey: tokenGeneratorKey,
			VerifySourceAddress: func(net.Addr) bool { return !retryLimiter.Allow() },
		}
		closeTransport := func() error {
			err := quicTransport.Close()
			if closeErr := quicUDP.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				err = errors.Join(err, closeErr)
			}
			return err
		}
		quicListener, err := quicTransport.Listen(doqTLS, quicConfig)
		if err != nil {
			closeTransport()
			return fmt.Errorf("start DNS-over-QUIC transport: %w", err)
		}
		if err := services.startDNS("DNS over QUIC", &dns.Server{
			Listener:      &netutil.WriteTimeoutListener{Listener: netutil.NewQUICStreamListener(quicListener), Timeout: 2 * time.Second},
			MaxTCPQueries: 1, MsgAcceptFunc: dnsutil.MsgAcceptFunc, Handler: dnsHandler,
		}, closeTransport); err != nil {
			return err
		}
	}

	// Public and administrative handlers never share a listener or route map.
	for _, endpoint := range []struct {
		name, path string
		mode       os.FileMode
		handler    http.Handler
	}{
		{"public HTTP", config.HTTPSocketPath, 0660, publicMux},
		{"administrative HTTP", config.AdminSocketPath, 0600, adminMux},
	} {
		if endpoint.path == "" {
			continue
		}
		listener, err := listenUnixSocket(endpoint.path, endpoint.mode)
		if err != nil {
			return fmt.Errorf("bind %s listener: %w", endpoint.name, err)
		}
		services.startHTTP(endpoint.name, listener, newHTTPServer(endpoint.handler))
	}
	log.Print("[info] configured DNS and HTTP listeners are ready")
	select {
	case <-ctx.Done():
		return nil
	case err := <-services.errors:
		return err
	}
}
