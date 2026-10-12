# dnscheck — a security-focused community version of addr.tools

**Based on [addr.tools](https://github.com/brianshea2/addr.tools), created by Brian Shea and its contributors.** This repository preserves that original work and develops a modified version with targeted security fixes, tests, clearer diagnostic results, and deployment guidance. It is maintained separately at [efrgdgr0024345/dnscheck](https://github.com/efrgdgr0024345/dnscheck); the upstream authors have not endorsed these changes.

**Download the complete current source:** <https://github.com/efrgdgr0024345/dnscheck/archive/refs/heads/main.zip>

The imported baseline is upstream commit [`394800c14932cbb1b0f5dbeb9126c4a43d482335`](https://github.com/brianshea2/addr.tools/commit/394800c14932cbb1b0f5dbeb9126c4a43d482335), dated 8 October 2026. The original [COPYRIGHT](COPYRIGHT) and [LICENSE](LICENSE) are unchanged: **GNU AGPL version 3 or later**. [CREDITS.md](CREDITS.md) records verified contributor credit; [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) includes dependency attribution and license texts.

## What is ready

The backend builds from pinned Go modules, includes focused concurrency and security regression tests, and can run a local unsigned diagnostic zone on loopback. The browser pages use this fork’s own shared assets and include visible upstream credit and a source offer for the modified version.

**This repository does not provision or claim a live public DNS service.** The browser starts disabled until an operator configures their own delegated domains, endpoints and certificates. Original `addr.tools` hostnames in historical references and deployment templates belong to the upstream operator; copying the source does not grant control of those domains.

## Main changes

- Atomic registered-name ownership and revocation checks: concurrent claims cannot both acquire a name, and a stale update cannot restore a suspended key.
- Separate, opt-in administrative socket protected by a generated bearer token; the public backend socket uses restricted permissions.
- Strict bounded request parsing; URL credentials and GET mutations are rejected. Stateless DNS secrets use the canonical encoding of 32 random bytes.
- Bounded state, challenge sets, watcher queues and client admissions; limits apply to oversized DNS response paths and signing work.
- Browser DNSSEC results distinguish reached invalid domains from inconclusive failures. A network error never becomes a confirmed authentication PASS.
- Cryptographic 128-bit watcher IDs, owner-bound registration/cleanup, corrected QUIC stream handling, and explicit diagnostic limitations.
- No automatic WebRTC or microphone access, Google STUN fallback, or remote Google Fonts. The visitor separately opts into configured STUN checks.
- Pinned build inputs, a non-root scratch runtime image, privacy-conscious proxy examples, and tests for the changed behavior.

See [the security review and remaining limits](docs/SECURITY_REVIEW.md). These changes address identified defects; they are not a claim that every possible vulnerability has been eliminated.

## Build and run locally

Use Go **1.27.2** and a current Node.js runtime that supports `node --test` (Node 22 or later is suitable). Git and Make are used below. Running the Go race detector additionally requires a supported platform and C compiler.

```sh
git clone https://github.com/efrgdgr0024345/dnscheck.git
cd dnscheck
make build
make test
make vet
make check-config
mkdir -p run
chmod 700 run
./bin/addrd -c configs/local-addrd.json
```

In a second terminal, if `dig` is installed:

```sh
dig @127.0.0.1 -p 1053 test.example.invalid SOA
dig @127.0.0.1 -p 1053 test.example.invalid TXT
```

The local configuration listens for UDP/TCP DNS at `127.0.0.1:1053` and uses `./run/addrd.sock` and `./run/db.json`. It does not expose a recursive resolver, enable administration, obtain certificates, or demonstrate working DNSSEC delegation. Stop it with Ctrl+C so it can drain requests and save state.

For production domains, reverse proxy routing, DNSSEC, storage, and optional name registration, follow [DEPLOYMENT.md](docs/DEPLOYMENT.md). For isolated Valkey integration tests, race checks, frontend tests and meaningful validation boundaries, see [TESTING.md](docs/TESTING.md).

## Components

| Directory | Purpose |
|---|---|
| `cmd/addrd` | Authoritative DNS/backend executable, configuration validation and DNSSEC key generation |
| `internal/config` | Listener setup, administrative separation, configuration checks and persistence lifecycle |
| `internal/dnsutil`, `internal/netutil` | DNSSEC, DNS message handling and DNS-over-QUIC adapter |
| `internal/dns2json` | Bounded DNS-to-JSON lookup against an explicitly configured trusted upstream |
| `internal/ttlstore` | Versioned bounded storage with conditional atomic mutations |
| `internal/zones` | Diagnostic, dynamic DNS, ACME challenge and registered-name services |
| `website` | Modified browser UI and service documentation; operator configuration required |
| `configs`, `scripts` | Local and production templates, build/run helpers and certificate helpers |
| `tests/frontend` | Network-free browser regression tests |
| `provenance` | Verified bundle retaining the exact imported upstream commit history |

## Compatibility and state

This version intentionally changes unsafe upstream behavior. Clients must stop placing credentials in URLs or changing records with GET. A single body credential remains accepted for POST/PUT/DELETE migration clients, but bearer headers are the documented interface; supplying both is rejected. Stateless secrets must match the 32-byte token format; that check cannot prove randomness, so use the provided generator. Changing a stateless secret changes its derived DNS name.

**Storage uses a version-2 schema and does not silently migrate upstream data.** Do not point it at an existing production database and assume continuity. Plan an explicit migration or a fresh namespace and re-registration with affected users. Preserve backups and revoked/suspended state. See the deployment guide before selecting persistence guarantees.

## Credits, source availability and history

Brian Shea deserves credit for the original project, its design, code, tools and website assets. The baseline also records a terminology improvement by `0x07cc`, linked in [CREDITS.md](CREDITS.md). Fork maintenance and security modifications do not transfer that credit to this repository.

The complete 275-commit upstream history is retained in [provenance/addr-tools-394800c.bundle](provenance/addr-tools-394800c.bundle), independently of GitHub’s fork-network UI. [UPSTREAM.md](docs/UPSTREAM.md) records the exact baseline and deployment identity rules.

Keep the license, copyright and notices with distributions. If you deploy further modifications, make the complete corresponding source of the running version available to remote users as required by the AGPL; update the visible source links accordingly. The software is supplied without warranty, as stated in the license.
