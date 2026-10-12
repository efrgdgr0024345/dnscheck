# Deployment guide

This guide is for the modified [efrgdgr0024345/dnscheck](https://github.com/efrgdgr0024345/dnscheck) repository, based on Brian Shea’s addr.tools. It explains how to make a deployment concrete without directing modified clients at the original operator’s services. No public service, domain ownership, certificate, delegation or provider account is created by cloning this repository.

## 1. Start with the local backend

Build with `make build`, then run `make check-config`. The local example is `configs/local-addrd.json`:

| Setting | Local example |
|---|---|
| `DNSListenAddress` | `127.0.0.1:1053` for UDP and TCP |
| `HTTPSocketPath` | `./run/addrd.sock` |
| `DatabasePath` | `./run/db.json` |
| Diagnostic zone | Unsigned `test.example.invalid.` |
| Administration, encrypted listeners and upstream lookup | Disabled unless explicitly configured |

Create the private runtime directory and run from the repository root:

```sh
mkdir -p run
chmod 700 run
./bin/addrd -c configs/local-addrd.json
```

A separate terminal can query `dig @127.0.0.1 -p 1053 test.example.invalid SOA`. An answer proves the local authoritative listener is functioning. It does not verify recursive DNSSEC validation, Internet delegation, browser CORS, certificate coverage or a VPN path.

`./bin/addrd -version` prints the build revision and source attribution. `./bin/addrd -check-config -c PATH` checks JSON structure, supported configuration and DNSSEC key material without opening listeners. It is not a deployment reachability test and does not prove that all runtime files, credentials or services will be available.

## 2. Choose domains and endpoints you control

`configs/sample-addrd.json` and `configs/nginx-http.conf` are production templates. Replace every upstream hostname, filesystem location, certificate path and origin with your deployment’s values. Reserved example domains in documentation are placeholders. The original public suffix/preload registrations, cloud accounts and service promises do not transfer with the source code.

A full browser diagnostic deployment needs these relationships to agree:

| Component | Required agreement |
|---|---|
| Authoritative DNS zones | Public delegation reaches your UDP/TCP listener; NS names and any required glue refer to your addresses. |
| Signed test zones | Each algorithm’s zone has matching public/private key material and the intended parent DS chain. Invalid-signature fixtures are deliberate test zones. |
| Probe HTTPS | Certificates cover the actual generated probe names. The HTTP endpoint returns a response with the configured page origin permitted by CORS. |
| WebSocket | Your `wss://.../watch/` endpoint reaches the backend; the page origin is allowed and client identity headers are overwritten by your proxy. |
| Browser configuration | URL prefixes, test-zone parent and optional enrichment endpoints refer to those same deployed services. |

Open the configured UDP/TCP DNS ports and the HTTPS/WebSocket port required by the deployment. If enabling authoritative DNS-over-TLS and DNS-over-QUIC, provide their TCP/UDP port and certificates as well. This is an authoritative toolkit; do not advertise it as a general recursive DNS/DoH resolver.

## 3. Backend configuration

The decoder rejects unknown JSON fields and extra trailing JSON. Key settings are:

| Field | Behavior |
|---|---|
| `DNSListenAddress` | UDP/TCP authoritative listener. Empty defaults to `:53`; the local example deliberately overrides it. |
| `TLSListenAddress` | TCP DoT and UDP DoQ address when a certificate/key pair is supplied. Empty defaults to `:853`. |
| `HTTPSocketPath` | Public backend Unix socket, created with mode `0660`. Parent directories must restrict access. |
| `AdminSocketPath`, `AdminTokenFile` | Both required to enable a separate administrative listener. It must differ from the public socket. Empty values keep administration disabled. |
| `DatabasePath` | Version-2 file snapshot for the in-memory persistent store. Empty means no disk persistence. |
| `ValkeyURL` | Selects Valkey-backed state instead of the file store. Keep credentials in a private config file, not shell history or the repository. |
| `RequestLogPath` | Optional DNS query logging. Empty disables that log; proxy and other operational logging remain separate concerns. |
| `TLSCertPath`, `TLSKeyPath` | Both are needed for DoT/DoQ. Mount only the certificate/key this process needs. |
| `TLSTicketKeysPath` | Optional private persisted session-ticket key file. |
| `QUICMasterSecret` | Optional standard-base64 encoding of exactly 32 random bytes for QUIC key derivation; this is a different encoding from API bearer tokens. |
| `WatcherAllowedOrigins` | Exact browser origins, such as `https://dns.your-domain.tld`. An empty list uses a same-host origin check; cross-host page/WebSocket deployments need explicit origins. |
| `WatcherTrustedClientIPHeader` | Only set behind a private trusted proxy that overwrites the named header. Otherwise leave empty. |
| `WatcherMaxPerClient` | Defaults to 4 active watchers per IPv4 address or IPv6 /64. Unix clients without a trusted forwarded identity share a local quota. |
| `LookupUpstream`, `LookupNetwork`, `LookupTLSName` | Optional DNS-to-JSON resolver and its transport. See the next section. |
| `MyaddrTurnstileSecret`, `MyaddrTurnstileHostname`, `MyaddrTurnstileAction` | Server-side CAPTCHA secret and expected context for registration. The default action is `claim`. |

Finite limits are enforced in code even when store limit fields are zero. The current logical storage defaults are 100,000 values, 32 MiB of key/value bytes, 16 values per key and 4 KiB per value. ACME challenge names have a tighter limit of 8 values. These counts are not a full process-memory accounting model; retain process/container memory limits.

Watchers additionally have a 100-connection global limit, a 2-minute lifetime, at most 64 queued messages, a 256 KiB queued-byte limit, an 8 KiB serialized-message limit, and a 1-second write deadline. These are admission and resource controls, not a guarantee of availability under every distributed attack.

Normal UDP truncation remains in effect even when a diagnostic name requests `notruncate`. A zone may explicitly set `MaxDiagnosticUDPSize`; it is capped at 4096 bytes and subject to the shared byte-weighted budget. Prefer TCP/TLS/QUIC for larger diagnostic answers. The application supplies shared diagnostic and signing-work limiters.

## 4. Configure a trusted DNS-to-JSON upstream

Lookup is disabled when `LookupUpstream` is empty. The handler supports `udp`, `tcp` and `tcp-tls`. Plaintext upstreams must be a literal loopback address unless the operator explicitly sets `AllowInsecureLookup: true`. That override weakens the protection and is not required by the supplied defaults.

For a trusted local validating resolver, use an explicit loopback address and port. In a bridge-network container, loopback means that container’s network namespace, not the host. For a remote resolver use `tcp-tls`, the resolver’s address/port and the expected `LookupTLSName`; normal TLS certificate verification remains enabled. An encrypted connection authenticates the configured endpoint, not the truth of every answer it returns.

The JSON includes `AD`, `TC`, `UpstreamTransport` and `Validation: "not-validated-locally"`. AD is the upstream resolver’s assertion; the application does not independently validate DNSSEC. Requests share a five-second deadline, propagate cancellation, and have global rate/concurrency limits.

## 5. Reverse proxy and browser

Use the supplied Nginx templates and listener snippets as a starting point, replacing the original domain and path markers. The proxy must serve the relevant `website/` directory, map `/js/*.js` and `/man.css` to this fork’s shared assets, proxy `/dns/` where used, and support 32-hex watcher paths. Serve JavaScript with the correct content type.

The public Unix socket is a trust boundary. Restrict its directory and group to the backend and proxy accounts; do not use mode `0666`. For `ip=self` and watcher client quotas, overwrite `X-Real-IP` with the actual trusted source rather than forwarding an arbitrary client header. Review any CDN real-IP configuration against the proxy’s trusted network ranges.

HSTS and other headers must be present in effective location responses, including error responses. A location with its own `add_header` directives does not automatically inherit all parent headers under the default Nginx behavior. The supplied configuration addresses this explicitly; run `nginx -t` on the complete installed configuration and inspect representative responses. Retain intentionally required diagnostic HTTP behavior only where the service design calls for it. The sample log format avoids credential-bearing query strings and request bodies; assess other enabled logs too.

Configure `website/dnscheck.tools/config.js`:

- Keep `enabled: false` until the backend, delegation, certificates, origin policy and probe endpoints are ready.
- Set `websocketURL` and `dnsLookupURL` to HTTPS/WSS prefixes with trailing slashes. Set `probeBaseDomain` to the parent of the `test`, `test-ipv6`, `test-alg13`, `test-alg14`, `test-alg15` and `test-alg18` zones.
- Supply optional plain-IP, geolocation, IP-information, STUN and timing endpoints only if you operate them or intend to use their provider. There is no automatic fallback to the original operator.
- Publish the actual logging, retention and third-party data policy. IANA/RDAP enrichment can send observed addresses to the relevant registration-data providers.

The main checks start on a visitor click. STUN requires a separate click; no microphone/camera permission is requested. The info page uses same-origin `/dns/`; its optional geolocation function remains disabled until an operator supplies a chosen implementation.

## 6. DNSSEC key material

Each signed zone needs a valid corresponding public/private key pair. `addrd -k ZONE -a ALGORITHM` generates the DS, DNSKEY and private material. Its output contains a secret: redirect it to a new private file rather than a shared terminal log, and never commit it. Use restrictive permissions before copying the needed values into private configuration. Configure delegation and DS records for the intended parent chain, then test both valid controls and deliberately invalid fixtures.

Unsupported algorithms, missing DS delegation, unavailable HTTPS certificates, or proxy errors can make a browser probe inconclusive. ML-DSA support varies; a zone’s existence is not evidence that a client resolver validates that algorithm. These are deployment checks outside a local unsigned smoke test.

## 7. Credentials and optional name registration

Generate a new stateless-service or administrative token without printing it:

```sh
python3 scripts/create-token.py /absolute/private/path/service.token
```

The helper writes 32 random bytes encoded as 43 unpadded base64url characters, followed by a newline, using an owner-only file and refusing to overwrite an existing file. Readers strip the final newline before using or hashing the token. Keep the file outside served directories. A format check cannot prove entropy; do not replace the generated value with a padded or human-chosen password. A stateless secret’s public name is still its SHA-224 hash. Rotation changes that name and requires changing dependent CNAMEs.

Use `Authorization: Bearer TOKEN` over HTTPS. Credentials in query strings and GET mutations are rejected. A single body credential is retained for migration clients; combining it with a bearer header is rejected. Body fields are string-valued JSON or URL-encoded form data, bounded to 16 KiB with duplicate and unknown fields rejected. Use a protected curl header file or a fixed helper so credentials do not appear in a reusable shell command.

For registration, configure the server Turnstile secret, expected hostname and `claim` action. Put the corresponding **public site key** in `website/myaddr.tools/claim.html`’s `turnstile-sitekey` meta value and replace its visible zone label. Do not copy the original operator’s key. The CAPTCHA loads only after the visitor chooses to continue, but its script remains trusted on the page that displays the generated owner key. Bootstrap CSS is loaded from pinned jsDelivr content with integrity metadata.

Administration is separately opt-in. Configure a private `AdminTokenFile` and distinct `AdminSocketPath`; the token file must be a regular owner-only file, and the administrative socket is mode `0600`. Do not proxy the admin route publicly. Successful authentication still requires protecting the operator account and file permissions. The administrative handler remains `/admin/myaddr` on that private listener.

## 8. Storage, migration and durability

**Do not reuse legacy upstream state without an explicit reviewed migration.** The file store requires a version-2 snapshot; registration records contain explicit status/revision fields; Valkey uses the fixed `{dnscheck:ttl:v2}:` namespace and a quota ledger. There is no automatic transfer of old registrations, old weak stateless secrets or stale key indexes. Startup rejects foreign or legacy keys in the selected dedicated Valkey database instead of silently treating a new namespace as a successful migration.

Plan either a fresh deployment with re-registration/re-delegation, or an offline migration that preserves valid ownership, expiration, suspension/revocation state, challenge limits and every quota index. Back up the original data and rehearse restoration. Do not run old and new binaries against the same new state format.

The in-memory store snapshots once a minute and after graceful shutdown. Snapshot files are written with private permissions, fsync and atomic replacement; failure is logged and retried. **An acknowledged mutation can still be lost in a crash before the next snapshot**, including a recent revocation. Atomic file replacement does not make every API response durably committed. The store drains HTTP requests before the final save, subject to finite shutdown timeouts.

For Valkey use an isolated, access-controlled instance/database with `maxmemory-policy noeviction`. The startup check requires ACL permission for `CONFIG GET maxmemory-policy` and `SCAN`, as well as the data/script commands used by the store; it inspects the currently known nodes for the policy and foreign keys. Do not bypass that check by broadly sharing a production database. The ledger and data must not be independently evicted or edited. All clients sharing the fixed namespace must use the same quota configuration; persistent and challenge records share its accounting. Enable and test AOF/replication/backups according to the durability guarantees you need. AOF `everysec` still permits a loss window, while stronger fsync policies have a performance cost. Do not claim durable revocation solely because a mutation is atomic. Disk-full, server OOM and interrupted persistence require operational testing. The common hash tag supports atomic batches in one cluster slot, but the recorded integration run used standalone Valkey 9.0.0, not a multi-node cluster or failover exercise. Cluster deployments need a dedicated cluster, consistent node policies and their own failure testing.

Use a protected Unix socket or loopback endpoint for a local database. For a remote database, select authenticated TLS with `valkeys://` or `rediss://`, preserve certificate verification, and limit network access and database credentials. The client library also accepts insecure URL options; do not enable `skip_verify` or send passwords/registration state over an untrusted plaintext network. Quota checks and atomic scripts do not supply transport security.

## 9. Container and certificate helpers

The build uses a pinned Go 1.27.2 image digest and exact module selections. The runtime image is `scratch`, runs as UID/GID `10001:10001`, and includes the application, CA certificates, copyright and license notices. `scripts/run-addrd.sh` supplies the hardened bridge-network/container settings. It needs a prepared writable data directory with ownership that matches the container and a private read-only configuration mount. Review the script’s documented variables and mounts before use.

Set `DNSCHECK_DATA_DIR` to the prepared directory containing `config.json`. Optional variables include `DNSCHECK_IMAGE`, `DNSCHECK_CONTAINER`, `DNSCHECK_NETWORK`, `DNSCHECK_MEMORY` (default `256m`), `DNSCHECK_CPUS` (default `2`), `DNSCHECK_TLS_CERT`, `DNSCHECK_TLS_KEY`, and `DNSCHECK_VALKEY_SOCKET_DIR`. The helper does not stop or delete an existing container automatically.

The run helper drops other capabilities, adds only `NET_BIND_SERVICE` for its low DNS/TLS ports, applies a read-only root filesystem and resource limits, and avoids a host-network default. Publish only the required DNS/TLS ports, preserve client source addresses through the deployed networking path, and mount only the needed certificates. A read-only key mount prevents modification but does not prevent a compromised process from reading that key.

For certificate automation, configure `DNSCHECK_CHALLENGE_URL`, `DNSCHECK_SECRET_FILE`, `DNSCHECK_CERT_DIR` and `ACME_EMAIL`, and pass Certbot arguments for domains you control to `scripts/get-certs.sh`, for example `--cert-name YOUR_DOMAIN -d YOUR_DOMAIN`. `DNSCHECK_CERTBOT_IMAGE` has a pinned default and can be explicitly selected by the operator. The fixed Python hook reads the credential file, URL-encodes the challenge, uses bearer authentication, and rejects redirects. Auth and cleanup operations do not interpolate secrets into shell code. DNS delegation and propagation still need to be in place before a certificate authority can validate a challenge.

The Certbot container runs with the invoking user's numeric UID/GID by default. Set `DNSCHECK_CERTBOT_UID` and `DNSCHECK_CERTBOT_GID` when the private token and certificate directory belong to another service account. Its writable temporary directories use that same ownership. Keep the token at mode `0600` and the certificate storage private; do not loosen permissions to compensate for a mismatched container user. Install only the certificate/key files needed by the DNS daemon, with ownership readable by UID `10001`, and reload/restart after renewal as appropriate. `DNSCHECK_PROPAGATION_SECONDS` must be an integer from 0 to 60 (default 10); the hook validates it before publishing a challenge.

## 10. Before offering a public service

Validate the installed configuration, owned domain delegation, trusted resolver connection, TLS/SNI/CORS, proxy identity handling, quota behavior, restart/recovery, and actual logs. Check UDP/TCP and enabled encrypted transports from an authorized external client. Run the isolated tests described in [TESTING.md](TESTING.md), then perform deployment-specific tests; unit tests do not replace them.

Keep [COPYRIGHT](../COPYRIGHT), [LICENSE](../LICENSE), [CREDITS.md](../CREDITS.md), and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) with distributions. Preserve the visible modified-version and upstream credit notices. If you further modify the running software, update the source offer to make the full corresponding version available to remote users under the AGPL.
