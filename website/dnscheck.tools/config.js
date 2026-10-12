// Modified for https://github.com/efrgdgr0024345/dnscheck on 2026-10-12; original project by Brian Shea and contributors. See docs/UPSTREAM.md.
// Operator configuration for this modified fork. No upstream production service
// is contacted while enabled is false. See docs/DEPLOYMENT.md and docs/UPSTREAM.md.
// Configure and test your own delegated zones, TLS certificates, CORS policy, and
// WebSocket endpoint before enabling this page. Example names are not services.
export const config = Object.freeze({
  enabled: false,
  websocketURL: '',       // e.g. 'wss://ws.dns.example.com/watch/'
  probeBaseDomain: '',    // e.g. 'dns.example.com'; contains test, test-alg13, etc.
  dnsLookupURL: '',       // e.g. 'https://tools.example.com/dns/'
  ipv4URL: '',            // optional: own HTTPS endpoint returning a plain IPv4
  ipv6URL: '',            // optional: own HTTPS endpoint returning a plain IPv6
  ipInfoURL: '',          // optional: own HTTPS IP information page prefix
  geolocationURL: '',     // optional: own HTTPS geolocation API prefix
  knownRangesURL: '/known-ipranges.json',
  // STUN runs only after the visitor clicks its separate opt-in button. List
  // only servers you operate or have permission to use. No Google fallback.
  stunServers: [],        // e.g. ['stun:stun.example.com:3478']
  // Optional operator-controlled zones whose test-* names resolve to no usable
  // address. Fetch duration is an estimate, not pure DNS latency.
  rttZones: [],
})

export function configurationError(settings = config) {
  if (!settings.enabled) return 'This fork is not configured for a deployed service.'
  try {
    const example = hostname => /(^|\.)(example(?:\.com|\.net|\.org)?)$/i.test(hostname)
    const endpoint = (value, protocol, prefix = false) => {
      const url = new URL(value)
      if (url.protocol !== protocol || url.username || url.password || url.search || url.hash || example(url.hostname)) throw new Error()
      if (prefix && !url.pathname.endsWith('/')) throw new Error()
    }
    endpoint(settings.websocketURL, 'wss:', true)
    endpoint(settings.dnsLookupURL, 'https:', true)
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i.test(settings.probeBaseDomain)) throw new Error()
    if (example(settings.probeBaseDomain)) throw new Error()
    for (const value of [settings.ipv4URL, settings.ipv6URL, settings.ipInfoURL, settings.geolocationURL]) {
      if (value) endpoint(value, 'https:')
    }
    if (!Array.isArray(settings.stunServers) || !Array.isArray(settings.rttZones)) throw new Error()
  } catch {
    return 'The operator must finish the HTTPS, WebSocket, and test-zone configuration.'
  }
  return ''
}
