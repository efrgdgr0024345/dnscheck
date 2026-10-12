# Upstream provenance and deployment identity

## Baseline

- Original repository: <https://github.com/brianshea2/addr.tools>
- Original author and copyright holder: Brian Shea.
- Imported commit: `394800c14932cbb1b0f5dbeb9126c4a43d482335`.
- Commit timestamp: `2026-10-08T21:13:24Z`.
- Original commit: <https://github.com/brianshea2/addr.tools/commit/394800c14932cbb1b0f5dbeb9126c4a43d482335>.
- Modified repository: <https://github.com/efrgdgr0024345/dnscheck>.
- Original licensing: AGPL-3.0-or-later, as stated in the unchanged root `COPYRIGHT`; the unchanged root `LICENSE` supplies the GNU AGPL v3 text.
- Full-history bundle: `provenance/addr-tools-394800c.bundle`, SHA-256 `77c9f45880ac3f6fdb2f631abcf763d6b373095a73cd967a6f7fc708b0ebd94c`.

The imported tree is the upstream application, not a newly invented replacement. The upstream `COPYRIGHT`, `LICENSE`, contributor records, and source links retain their original meaning. [CREDITS.md](../CREDITS.md) identifies the additional contributor verified in the baseline history. A GitHub fork-network relationship is not claimed merely because source and history have been imported.

## What this version changes

The 12 October 2026 changes address ownership/revocation atomicity, credential parsing and API methods, bounded state and watcher resources, DNS response limits, browser result accuracy, privacy defaults, deployment isolation, and reproducible dependency inputs. Changed application source files carry modification notices; [MODIFICATIONS.md](../MODIFICATIONS.md) supplies the dated project-wide notice. The security documents and regression tests describe what was checked and what still needs deployment validation. These are changes by this fork, not claims about fixes made by Brian Shea.

The original service names (`addr.tools`, `dnscheck.tools`, `myaddr.tools`, related domains) remain in historical references, directory names, and operator-specific sample configuration. They belong to the upstream deployment. They do not establish that this repository controls those domains, offers their registrations, appears in a public suffix/preload list, or operates a running equivalent service.

## Configure the browser before enabling a service

`website/dnscheck.tools/config.js` starts with `enabled: false` and empty operator endpoints. The page shows a setup notice and sends no diagnostic requests. Supply your own delegated test zones and matching backend before enabling it. The WebSocket path remains `/watch/ID`, where ID is 32 lowercase hexadecimal characters generated from 16 cryptographically random bytes.

Configure the same operator domains consistently in the backend zones, DNS delegation, certificates, reverse proxy, CORS/origin checks, and browser config. `probeBaseDomain` is the parent of `test`, `test-ipv6`, `test-alg13`, `test-alg14`, `test-alg15`, and `test-alg18`. The WebSocket and DNS lookup URL prefixes include their trailing slash. Shared JavaScript and manual-page CSS are served from this fork at `/js/*.js` and `/man.css`, using the supplied proxy aliases. The info page uses a same-origin `/dns/` API.

Optional IP, geolocation, STUN and timing endpoints must be configured by the operator. WebRTC requires a separate visitor click; microphone/camera access is not requested, and there is no Google STUN fallback. The info page’s optional geolocation function is disabled until an operator implements a chosen endpoint. IP registrant enrichment still accesses IANA and RDAP providers and is disclosed in the help page.

For name registration, set your own `turnstile-sitekey` meta value in `website/myaddr.tools/claim.html`, configure the corresponding private server key and expected hostname, and retain the `claim` action on both sides. The page will not load Turnstile or submit claims while its site key is empty. The provider is loaded only after the visitor chooses to continue, but remains trusted script on the page displaying a new key; this version does not claim to isolate it. Replace the visible `operator-configured-zone` label with the domain(s) that you actually serve.

## Source availability and attribution when deploying

Every user-facing HTML page includes a visible notice that this is a modified version, credit to Brian Shea and contributors, a link to the modified source, the license, and credits. Keep this notice available in your deployment. If you make further changes or distribute a different version, update the source link so recipients and remote users can obtain the complete corresponding source for what is actually running. Include `COPYRIGHT`, `LICENSE`, `CREDITS.md`, and `THIRD_PARTY_NOTICES.md` with distributions.

The attribution notice does not promise a live deployment. Configure the reserved example domains before running examples, and do not send tests or update credentials to the original operator by accident. See [the deployment guide](DEPLOYMENT.md) for the backend and proxy requirements.
