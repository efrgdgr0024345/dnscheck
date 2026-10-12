# Security changes and remaining limits

## Scope and provenance

This document maps the source review of Brian Shea’s [addr.tools](https://github.com/brianshea2/addr.tools) at commit [`394800c14932cbb1b0f5dbeb9126c4a43d482335`](https://github.com/brianshea2/addr.tools/commit/394800c14932cbb1b0f5dbeb9126c4a43d482335) to the modifications in this community fork dated 12 October 2026. Brian Shea and the upstream contributors retain credit for the original project; the unchanged `COPYRIGHT` and `LICENSE` provide the original AGPL-3.0-or-later grant. See [CREDITS](../CREDITS.md) and [UPSTREAM](UPSTREAM.md).

The original review combined source inspection, isolated local reproductions, dependency analysis and primary documentation. Several original bugs were reproduced using real handlers, controlled concurrency and the Go race detector. No live exploitation of the original public services was performed. The fixes below are targeted engineering changes, not a certification that all possible flaws have been found or eliminated.

The running configuration, DNS delegation, resolver policies, build artifacts, host permissions, third-party scripts and persistence settings are separate trust boundaries. A repository test cannot attest to an unknown deployment.

## Findings and disposition

| ID / original issue | Implemented change in this fork | Remaining limit / operational condition |
|---|---|---|
| **F01 — Concurrent registrations retained two owner keys** | Claims create ownership and reverse indexes in a conditional atomic batch. Mutations check the current registration, owner hash, status and revision. Memory and Valkey clients share the same conditional interface. | Users must migrate existing state explicitly. Authentication cannot protect a stolen current key or an operator-controlled database. |
| **F02 — In-flight update undid suspension** | Explicit pending/active/suspended state and revision checks prevent a stale commit from restoring revoked ownership. Ordinary updates do not replace owner hashes. | A storage rollback can restore an earlier state. Durable revocation still depends on the selected persistence policy. |
| **F03 — DNSSEC false-positive green result** | Any HTTP status establishes that a response was reached. Opaque fetch failures and failed valid controls are inconclusive. The UI no longer turns them into an authenticated PASS. | A browser cannot distinguish DNSSEC rejection from DNS/TLS/CORS/filter/network errors. A malicious resolver can special-case test names. The tool cannot certify every DNS response or prove absence of VPN leaks. |
| **F04 — Large-response limiter bypass** | Diagnostic work is charged before response construction. Normal UDP truncation applies by default, including `notruncate`; opt-in oversized replies are capped and byte-weighted across paths, including DNSKEY and signed negative responses. Shared signing-work limits apply. | Any Internet-facing DNS service can receive unwanted traffic. Operators still need traffic monitoring, capacity planning and appropriate upstream protections. The limit is not a live reflection benchmark. |
| **F05 — Unauthenticated administration on a world-writable socket** | Public and administrative route maps/listeners are separate. Public socket mode is `0660`; admin is disabled by default, uses `0600`, and requires a generated token from a private file. Socket creation refuses to overwrite a regular file or active listener. | Parent permissions, service-account membership and token protection remain essential. Access to a trusted proxy socket still permits requests within that interface’s authority. |
| **F06 — Public hashes allowed offline guessing of weak secrets** | Stateless secrets must have the canonical unpadded base64url encoding of 32 bytes; helpers generate them cryptographically. Examples no longer suggest human passwords. | **A format check cannot prove randomness.** A predictable value of the right shape can still be guessed offline. The public SHA-224 design remains; rotating the secret changes the derived DNS name and delegation. |
| **F07 — URL/GET credentials and shell-interpolated certificate hooks** | URL credentials and GET mutations are rejected. Bearer headers and bounded body data are supported; ambiguous sources fail. A fixed Python certificate hook reads a private token file and uses encoded POST/DELETE requests without redirects or shell re-parsing. | One body credential remains accepted for migration clients. Secrets can still be exposed by a misconfigured logger, compromised endpoint or unsafe caller. HTTPS does not erase endpoint logs. |
| **F08 — Public 32-bit watcher ID and observation contamination** | Browser identifiers now use 128 random bits. UI/help describe public query correlation, unauthenticated ECS and limits of resolver attribution; observations are not labeled as an exclusive verified path. | A resolver that sees the ID can send matching queries. Larger IDs reduce off-path guessing/collisions; they do not authenticate an observer who already knows the ID. This limitation is disclosed, not eliminated. |
| **F09 — Watcher races, cleanup errors and resource exhaustion** | Atomic owner-bound registration, stable queue lifecycle, synchronized close/send, per-client/global admissions, origin checks, bounded sanitized messages/bytes and write deadlines. Queries are validated before watcher delivery. | Distributed clients can still compete for bounded resources. Reverse-proxy client identification must be configured correctly. Raw arbitrary EDNS payloads are intentionally omitted from full observations. |
| **F10 — Mutable build inputs** | Go modules/checksums, DNS-fork revision and builder digest are pinned. Builds avoid implicit module edits and retain source/revision metadata. The runtime image includes dependency/license notices. | A pin is a reviewable version choice, not proof a provider or toolchain is uncompromised. Keep updating reviewed dependencies and verify the actual shipped image/binary. |
| **F11 — Unbounded state and fragile persistence** | Finite value/byte/per-key limits, idempotent challenge insertion, an 8-challenge per-name cap, conditional quota-checked writes, bounded Valkey quota pruning, private versioned snapshots and retryable save failures. | Logical quotas are not exact RAM accounting. Memory-store acknowledgements can precede a snapshot by up to a minute. Valkey eviction, durability, OOM and backup settings remain operator responsibilities. |
| **F12 — HSTS lost through location-header inheritance** | Proxy templates apply security headers at the locations that add other headers and supply shared header configuration. | Test the full installed Nginx configuration and real responses; unrelated includes or later edits can alter effective behavior. Preserve diagnostic HTTP only where intentionally required. |
| **F13 — Unprotected external DNS-to-JSON upstream** | External plaintext upstreams require an explicit insecure opt-in. Loopback or authenticated DNS-over-TLS can be configured. Requests have cancellation, deadlines, rate/concurrency controls and clear transport/validation fields. | AD is an upstream assertion; this code does not locally validate DNSSEC. A trusted resolver can still give bad answers. Container loopback is not automatically the host’s resolver. |
| **F14 — Broad container privileges and secret mounts** | Non-root scratch runtime, bridge-network default, read-only root filesystem, resource limits, dropped capabilities with only the binding capability required for low ports, and narrower certificate mounts. | A process can read every secret it legitimately needs. Read-only mounts prevent writes, not theft. Host configuration, container runtime and networking still require review. |
| **F15 — Inaccurate privacy claims and silent third-party traffic** | Replaced categorical “no data collected” claims with processing/logging explanations. Removed remote fonts and Google STUN fallback; WebRTC is opt-in without microphone/camera permission. Modified pages identify their source and operator-dependent services. | RDAP enrichment still contacts providers. The configured CAPTCHA is trusted script on the page displaying a key. Pinned Bootstrap CSS is retrieved from jsDelivr. Operators must publish actual providers, retention and logging. |

## Ownership and persistence model

A registration is now a versioned lifecycle record rather than a hash that ordinary renewal may overwrite. A claim, address mutation, challenge change, deletion or suspension uses checked conditions against the current owner/index/revision. The store commits all applicable mutations together or reports contention/capacity failure. The Valkey implementation uses server-side scripting across independent clients, with all keys in a fixed namespace/hash slot. Startup checks require a dedicated version-2 database and the noeviction policy on currently known nodes; the service account needs permission for those checks. The script validates schema, types, limits and encodings before performing writes because script isolation alone does not imply rollback after every possible script error.

The regression suite checks competing claims, stale owner mappings, suspend/update overlap, delete/reclaim overlap and quota failures preserving existing state. Real Valkey tests use separate clients; passing only an in-memory mock would not establish cross-client storage behavior. The recorded run was standalone Valkey 9.0.0 and does not establish cluster/failover behavior.

This does not make persistence synchronous. The file store snapshots periodically; atomic replacement and fsync improve snapshot integrity, but cannot save a mutation that has not yet been included. If an acknowledged revocation must survive every crash within a defined guarantee, select and test a database policy that provides that guarantee. Do not independently evict Valkey ledger/data keys or change quotas inconsistently across clients. The version-2 schema has no silent legacy migration.

Implementation: [registered-name API](../internal/zones/myaddr/api.go), [storage interface](../internal/ttlstore/ttlstore.go), [memory store](../internal/ttlstore/simple.go), [Valkey store](../internal/ttlstore/valkey.go).

## Interpreting a browser result

The browser only observes whether fetch returned an HTTP response. It does not receive a trustworthy structured DNSSEC failure reason. This fork therefore uses:

| Display | Meaning |
|---|---|
| `REACHED` | A deliberately invalid test domain produced an HTTP response, including 4xx/5xx. The tested path did not reject that probe. |
| `UNKNOWN` | No usable HTTP response was available. DNSSEC rejection is one possible cause among several. |
| `NO CTRL` | The valid control was unavailable; that algorithm’s invalid tests cannot be interpreted. |
| `REACHED*` | An invalid probe for the experimental algorithm was reached; support and policy vary. |

The overall result can identify a reached invalid probe or be inconclusive. It cannot produce a cryptographic assurance merely because requests failed. A green result in an older deployment must not be attributed to the changed source without checking what code actually runs.

Likewise, a query seen by an authoritative server identifies the observed packet source and supplied metadata, not the physical path of every user request. RDAP names and geolocation describe registration data and estimates. Public query IDs are not authorization tokens. IP/VPN behavior can vary by browser, address family, application, cache and connection state.

Implementation: [probe classification](../website/dnscheck.tools/probes.js), [browser flow](../website/dnscheck.tools/main.js), [watcher metadata](../internal/zones/dnscheck/websocket.go).

## Additional hardening

The changes also address malformed and duplicate request fields, body/query limits, server timeouts, explicit expiration state, Turnstile hostname/action binding, administrative token permissions, session-ticket file replacement, QUIC message framing and stream FIN/cancellation handling, and accidental credential logging. DoQ early data is disabled in this configuration. DNSSEC key validation fails with actionable configuration errors rather than relying on an unchecked startup assumption.

Frontend dictionaries no longer confuse inherited JavaScript property names with RDAP registrants. Shared browser code is served from the modified repository instead of executing the upstream site’s current modules. The info page preserves its visible credits when replacing its result content.

Not every request path can be made cost-free, and not every security boundary is in this repository. Remaining deployment work includes an effective browser script policy appropriate for any enabled third parties, secure DNS delegation and key rotation, log retention/access control, traffic admission under actual load, process memory budgets, and crash/restore exercises. The code does not provide tamper-evident audit storage, host attestation or a guarantee that the selected resolver is honest.

## Dependency interpretation

The original local scan of a freshly resolved upstream build found no known vulnerable application-reachable symbols and eight advisory matches confined to unused portions of included modules. That was not evidence of eight exploitable application vulnerabilities. This fork updates the affected Go submodules and pins its selected graph; the actual versions remain recorded in [go.mod](../go.mod) and [go.sum](../go.sum).

Run the scanner on the version and toolchain you intend to deploy, inspect reachability, and preserve the output with the release record. A clean known-vulnerability scan does not discover application logic bugs such as ownership races or misleading browser results. [TESTING.md](TESTING.md) describes repeatable local checks and their limits.

## Evidence and reporting

The tests are intended to protect the repaired contracts, including the original false-positive and race regressions. See the test commands and isolated Valkey setup in [TESTING.md](TESTING.md). Test results establish the behavior exercised under those conditions; they do not establish a production traffic capacity or the state of an independently operated service.

Report problems in the modified code through this fork’s maintainers and include the commit/build revision, affected configuration with secrets removed, and a minimal local reproduction where possible. Do not attribute this fork’s defects to Brian Shea or submit credentials, private keys, personal DNS traffic or live exploit traffic as an issue attachment.
