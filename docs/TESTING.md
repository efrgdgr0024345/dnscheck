# Testing and validation

These checks validate the modified repository locally. They do not contact the original addr.tools production services or establish that a public deployment is configured correctly. The existing upstream scripts under `test/` may target real service domains; do not run them unchanged as a local smoke test.

## Prerequisites and normal commands

Use Go 1.27.2 and Node.js with the built-in test runner (Node 22 or later is suitable), plus Make. The Go race detector needs a supported target platform and C compiler. First-time module downloads require the configured Go module/checksum services or a populated verified cache.

```sh
make build
make test
make vet
make check-config
```

The corresponding direct checks are useful when diagnosing an individual failure:

```sh
go mod verify
go test -race -count=1 ./...
go vet ./...
node --test tests/frontend/*.test.mjs
./bin/addrd -check-config -c configs/local-addrd.json
```

The Makefile also runs Python helper tests from `tests/scripts` and checks shell syntax; these checks require Python 3 and Bash. `make build` writes `bin/addrd`, uses read-only module selection and sets the revision displayed by `-version`; a working tree with uncommitted changes is marked dirty. Inspect `go version -m bin/addrd` for embedded build/VCS metadata. The container build records the supplied source revision too. Do not run `go mod tidy` automatically as part of a release build. Review and commit intended dependency changes separately.

## Coverage that matters

| Test area | Security or correctness contract |
|---|---|
| `internal/ttlstore` | Atomic competing claims across independent clients, conditional batch behavior, quota rollback, expiry reclamation, idempotent bounded values, copied data ownership, snapshot version/permissions/limits Valkey preflight failures, startup policy/legacy-data rejection and TTL overflow handling. |
| `internal/zones/myaddr` | One owner for a contested claim; stale mapping cannot read, update or delete; suspension cannot be undone by an in-flight update; old deletion cannot erase a newly claimed owner; explicit lifecycle state. |
| `internal/httputil` | Malformed/duplicate/unknown request values fail, request sizes are bounded, credential sources are unambiguous, canonical token format is checked, and Turnstile binds success to hostname/action. |
| `internal/zones/dyn`, `internal/zones/challenges` | Mutating GET and URL credentials are rejected; valid update/delete behavior and bounded/idempotent challenge insertion are retained. |
| `internal/zones/dnscheck` | Signed negative and DNSKEY answer paths cannot bypass limits; diagnostics are byte-weighted; signing work is bounded; watcher registration/cleanup, queue limits, origins, client identity and connection admission obey their contracts. |
| `internal/netutil` | QUIC response FIN and capacity release, malformed/multiple/nonzero-ID queries rejected, and a client withholding FIN is bounded and cancelled. |
| `internal/config` | Admin bearer checks and token-file permissions, safe Unix socket creation, private reloadable session-ticket files, background-worker shutdown, configuration validation and real listener lifecycle. |
| `internal/dns2json` | External plaintext resolver policy, request cancellation, shared UDP/TCP fallback deadline and clear upstream-assertion fields. |
| `tests/frontend` | HTTP503 is connectivity rather than PASS; opaque failures are inconclusive; failed controls stop interpretation; requests wait for the watcher; no probes before Run or when unconfigured; 128-bit IDs and special RDAP labels work. |
| `tests/scripts` | Canonical private token generation, no overwrite, encoded credential-bearing requests, no redirect forwarding, malformed endpoint rejection, bounded response handling and sanitized errors. |

The frontend tests execute the browser flow against controlled DOM/WebSocket/fetch substitutes, as well as its actual pure probe functions. They perform no network requests. They do not replace a real-browser test of a deployed page, CORS policy, certificate set or provider behavior.

## Reverse-proxy regression gate

With an installed Nginx and OpenSSL, run:

```sh
DNSCHECK_NGINX=/usr/sbin/nginx python3 -m unittest discover -s tests/nginx -p 'test_*.py' -v
```

The seven proxy tests use the actual template, temporary certificates and loopback
ports. They first validate the original Unix-upstream syntax with `nginx -t`, then
use a local HTTP backend in a temporary configuration to check effective HSTS,
static/API/error headers, credential-bearing GET routing, mutation preservation,
client-IP header replacement and exact diagnostic CORS/no-store behavior. No real
service domain is contacted. See [the test isolation notes](../tests/nginx/README.md).

## Continuous integration

[The GitHub Actions workflow](../.github/workflows/security-checks.yml) repeats the
race, frontend and helper suites against a disposable pinned Valkey 9.0.0 service,
checks dependency vulnerabilities, builds the executable, and validates both
sample configurations. Separate jobs exercise Nginx and build/run the container
without network access for its version check. Actions are pinned by commit;
the runner's Nginx package follows its supported distribution updates.

The Unix socket permission/active-listener regression skips only when a local
executor explicitly denies Unix sockets with `EPERM` or lacks that address family.
CI sets `DNSCHECK_REQUIRE_UNIX_SOCKETS=1`, making that check mandatory. A local skip
does not establish that the socket test passed.

## Real Valkey integration

The storage and ownership integration checks must run against a **disposable dedicated loopback Valkey instance**. The tests issue `FLUSHDB`: storage checks clear DB15, and registered-name API checks clear DB14. Never point them at a shared development or production server, even if it listens on loopback.

With a locally installed Valkey 9 server, start a throwaway instance in a separate terminal:

```sh
valkey-server --bind 127.0.0.1 --port 16479 --protected-mode yes --save '' --appendonly no
```

Then run:

```sh
DNSCHECK_TEST_VALKEY_ADDR=127.0.0.1:16479 go test -race -count=1 ./internal/ttlstore ./internal/httputil ./internal/zones/myaddr ./internal/zones/dyn ./internal/zones/challenges
```

The address must be an explicit loopback IP and port. Different real Valkey clients are used to exercise atomicity across clients. Without `DNSCHECK_TEST_VALKEY_ADDR`, Valkey subtests are explicitly skipped; a successful ordinary test run then proves only the non-Valkey coverage, not this integration. Stop the throwaway server after the run. The test server’s disabled persistence is for isolation and speed, not a production recommendation.

During the 12 October 2026 implementation, these race-enabled storage and API integration checks passed against an isolated Valkey 9.0.0 build from official commit `5018b12b`, using DB14/15. This was a standalone instance, not a Cluster/failover test. Rerun them for your final commit and exact database build; this recorded check does not attest to a later deployment. The frontend suite also passed its nine initial regression tests at that implementation checkpoint. New tests or changes may alter counts; the current runner output is authoritative.

The complete local integration run after changing the module identity to this
repository passed **163 Go tests/subtests with the race detector**, including the
real Valkey cases. One Unix socket test was explicitly skipped because this
executor denied that socket family; CI requires it. The 9 frontend, 19 Python
helper and 7 real-Nginx tests also passed. `go mod verify`, `go vet`, the build and
both sample configuration checks passed. A smoke test of the built executable
served authoritative SOA answers over UDP and TCP, then stopped cleanly on
SIGTERM, wrote a private version-2 snapshot, and restarted from that snapshot.
Runtime tests separately exercised a certificate-verified DoQ exchange and
listener/background-worker shutdown. The final small cleanup changes were
rechecked in the affected race-test packages.

The local `govulncheck v1.9.0` run using Go 1.27.2 found no affected application
symbols or imported packages. It retained the module-level advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for the unused OpenPGP package
within `golang.org/x/crypto`; this is not a claim of zero advisory matches in the
entire dependency graph. The current CI result is authoritative for its commit.
Docker was unavailable in the local executor, so local checks do not establish
that the container image built or ran; the workflow includes that separate gate.

## Local listener smoke test

```sh
mkdir -p run
chmod 700 run
./bin/addrd -c configs/local-addrd.json
```

In a second terminal:

```sh
dig @127.0.0.1 -p 1053 test.example.invalid SOA
dig +tcp @127.0.0.1 -p 1053 test.example.invalid SOA
```

Both should receive the local authoritative SOA response. Stop the server with Ctrl+C, verify that its version-2 snapshot was written privately, and start it again. The local example is unsigned and loopback-only; it does not test public delegation, DS chains, TLS, a CAPTCHA provider, certificate issuance or an Internet-facing reverse proxy.

## Dependency and release checks

Record `go version`, `go version -m bin/addrd`, the source commit and any container image digest. Verify the module checksums. If `govulncheck` is installed, run it with the chosen Go toolchain against `./...` and distinguish reachable vulnerable symbols from advisory matches in unused module packages. The scanner fetches current advisory data; results can change without a code change.

For container releases, build through `scripts/build-addrd.sh`, inspect the recorded image revision and run configuration, and confirm that the image includes the license/credit notices. A pinned build input improves reproducibility and reviewability but is not a claim of independently reproduced byte-identical output on every platform.

The upstream history bundle can be inspected without contacting a public service:

```sh
git bundle verify provenance/addr-tools-394800c.bundle
git bundle list-heads provenance/addr-tools-394800c.bundle
```

The bundle retains all 275 commits reachable from the imported baseline. Its purpose is provenance preservation, including exact author metadata; GitHub’s fork-network UI may not show that ancestry.

## Deployment checks still required

On the actual owned domains and installed configuration, validate DNS delegation/glue and signed valid controls, deliberately invalid fixtures, certificate/SNI coverage, CORS, WebSocket origin and client identity, effective response headers, and preservation of source addresses through the selected network path. Inspect the actual logs for credential handling and retention. Exercise quotas, disk-full conditions, clean shutdown, crash recovery and restore behavior using representative data.

Do not describe unit tests, mocks or a vulnerability scan as a capacity benchmark, penetration test, or assurance that all DNS responses are authenticated. The browser is intentionally inconclusive where its observations cannot distinguish the underlying cause.
