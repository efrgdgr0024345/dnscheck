# Modification notice — 12 October 2026

This is a modified version of **Brian Shea's addr.tools**, prepared for
[efrgdgr0024345/dnscheck](https://github.com/efrgdgr0024345/dnscheck) with OpenAI Codex
assistance. Brian Shea and the verified upstream contributors retain credit for
the original application, design and assets. The original `COPYRIGHT` and
`LICENSE` are unchanged; the project remains AGPL-3.0-or-later.

The imported baseline is upstream commit
`394800c14932cbb1b0f5dbeb9126c4a43d482335` (8 October 2026). The complete history
reachable from that baseline, including all 275 original commits and their
recorded author metadata, is retained in `provenance/addr-tools-394800c.bundle`.
The initial README of this repository remains in its original parent commit.
See [CREDITS.md](CREDITS.md) for verified contributor attribution and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency and data credits.

## Changes made in this version

- Added atomic conditional ownership and revocation checks, bounded versioned
  memory/Valkey storage, strict request parsing, canonical bearer credentials
  and safe individual ACME challenge cleanup.
- Separated authenticated administration from the public backend socket and
  added request, connection, queue, response-size and signing-work limits.
- Corrected watcher races, DNS-over-QUIC framing and shutdown, DNSSEC key and
  RRset validation, listener readiness and owned background-worker lifetimes.
- Changed browser results to preserve uncertainty, strengthened watcher IDs,
  made probes/operator endpoints explicit and removed automatic WebRTC/font
  requests described in the security notes.
- Added source/credit notices to the pages, retained existing license notices,
  and changed the Go module identity to this repository.
- Pinned reviewed build/dependency inputs; added a non-root runtime image,
  narrower private mounts, safe certificate hooks and corrected proxy headers.
- Added isolated regression tests, CI definitions and deployment/migration
  documentation. The browser starts disabled until its operator supplies a
  working deployment under domains they control.

The [security notes](docs/SECURITY_REVIEW.md) map the original findings to these
changes and their remaining limits. The [testing guide](docs/TESTING.md) records
how to verify the changed contracts. These modifications do not claim upstream
endorsement, a deployed public service, or the absence of every possible flaw.
