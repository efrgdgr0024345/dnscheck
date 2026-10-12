// Security regression tests for the modified fork. No network access is used.
// Run with: node --test tests/frontend/*.test.mjs
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

const root = new URL('../../', import.meta.url)
const read = path => fs.readFileSync(new URL(path, root), 'utf8')
const importSource = path => import('data:text/javascript;base64,' + Buffer.from(read(path)).toString('base64'))
const { makeQuery, dnssecCell, dnssecSummary } = await importSource('website/dnscheck.tools/probes.js')
const { config: defaults, configurationError } = await importSource('website/dnscheck.tools/config.js')

test('all HTTP statuses establish connectivity, including the old 503 false-positive case', async () => {
  for (const status of [200, 204, 400, 404, 500, 503]) {
    let sentOptions
    const result = await makeQuery('invalid.example', 1000, new AbortController().signal, async (_, options) => {
      sentOptions = options
      return { ok: status < 400, status, headers: { get: () => null } }
    })
    assert.equal(result.connected, true)
    assert.equal(result.httpStatus, status)
    assert.equal(dnssecCell(true, result.connected).label, 'REACHED')
    assert.equal(sentOptions.credentials, 'omit')
    assert.equal(sentOptions.cache, 'no-store')
    assert.equal(sentOptions.referrerPolicy, 'no-referrer')
  }
})

test('network, timeout and caller abort never become a DNSSEC PASS', async () => {
  const failure = await makeQuery('invalid.example', 1000, new AbortController().signal, async () => {
    throw new TypeError('Simulated DNS/TLS/CORS/network failure')
  })
  assert.equal(failure.connected, null)
  assert.equal(dnssecCell(true, failure.connected).label, 'UNKNOWN')

  const timeout = await makeQuery('invalid.example', 1, new AbortController().signal, (_, { signal }) =>
    new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('Timed out')))))
  assert.equal(timeout.connected, null)
  assert.equal(timeout.outcome, 'unavailable')

  const controller = new AbortController()
  controller.abort()
  const aborted = await makeQuery('invalid.example', 1000, controller.signal, async () => assert.fail('must not fetch after abort'))
  assert.equal(aborted.connected, null)
  assert.equal(aborted.outcome, 'aborted')

  const summary = dnssecSummary([...Array(4).fill(true), ...Array(12).fill(null)])
  assert.equal(summary.className, 'yellow')
  assert.match(summary.text, /Inconclusive/)
  assert.doesNotMatch(summary.text, /responses are authenticated/)
})

test('missing controls remain inconclusive; a known invalid response is not hidden by another failed control', () => {
  assert.equal(dnssecCell(null, null).label, 'NO CTRL')
  const failedControls = Array(16).fill(null)
  assert.equal(dnssecSummary(failedControls).className, 'yellow')
  failedControls[0] = true
  failedControls[4] = true
  assert.equal(dnssecSummary(failedControls).className, 'red')
  assert.equal(dnssecCell(true, true, true).label, 'REACHED*')
})

test('watcher IDs use all 16 Web Crypto bytes with leading zeroes preserved', () => {
  let calls = 0
  const sandbox = vm.createContext({
    Uint8Array,
    crypto: { getRandomValues(bytes) {
      calls++
      assert.equal(bytes.byteLength, 16)
      bytes.forEach((_, i) => { bytes[i] = i })
      return bytes
    } },
  })
  vm.runInContext(read('website/addr.tools/js/util.js').replace(/^export /gm, ''), sandbox)
  assert.equal(vm.runInContext('randomId()', sandbox), '000102030405060708090a0b0c0d0e0f')
  assert.equal(calls, 1)
})

test('unconfigured deployments are disabled and insecure endpoints are rejected', () => {
  assert.equal(defaults.enabled, false)
  assert.match(configurationError(), /not configured/)
  const valid = { ...defaults, enabled: true, websocketURL: 'wss://ws.operator.test/watch/', dnsLookupURL: 'https://tools.operator.test/dns/', probeBaseDomain: 'dns.operator.test' }
  assert.equal(configurationError(valid), '')
  assert.ok(configurationError({ ...valid, websocketURL: 'ws://ws.operator.test/watch/' }))
  assert.ok(configurationError({ ...valid, dnsLookupURL: 'http://tools.operator.test/dns/' }))
  assert.ok(configurationError({ ...valid, ipv4URL: 'http://ip.operator.test/' }))
})

function createPage(mode, enabled = true) {
  const elements = Object.fromEntries([...read('website/dnscheck.tools/index.html').matchAll(/\bid="([^"]+)"/g)]
    .map(([, id]) => [id, {
      id, innerHTML: '', textContent: '', disabled: false, listeners: {},
      firstElementChild: { outerHTML: '<div>Section</div>', innerHTML: '' },
      classList: { add() {}, remove() {}, contains() { return true } },
      addEventListener(name, fn) { this.listeners[name] = fn },
    }]))
  const columns = Array.from({ length: 12 }, () => ({}))
  elements['dnssec-results'].getElementsByTagName = tag => { assert.equal(tag, 'td'); return columns }
  let socketOpened = false
  const requests = []
  const sockets = []
  const fetchStub = async url => {
    assert.equal(socketOpened, true, 'probes must wait for the watcher handshake')
    requests.push(url)
    const invalid = /-(badsig|expiredsig|nosig)\./.test(url)
    if (mode === 'all-errors' || (mode === 'invalid-errors' && invalid)) throw new TypeError('Synthetic failure')
    const status = mode === 'invalid-503' && invalid ? 503 : 200
    return { ok: status === 200, status, headers: { get: () => null } }
  }
  const settings = { ...defaults, enabled, websocketURL: 'wss://ws.operator.test/watch/', dnsLookupURL: 'https://tools.operator.test/dns/', probeBaseDomain: 'dns.operator.test' }
  const sandbox = vm.createContext({
    IPAddr: class {}, IPRange: class {}, RDAPClient: class {},
    config: settings, configurationError: () => configurationError(settings),
    randomId: () => '0123456789abcdef0123456789abcdef',
    encode: str => str.replace(/["&<>]/g, match => `&#${match.charCodeAt(0)};`),
    fetchOk: () => assert.fail('no enrichment should run without an observed IP'),
    makeQuery: (host, timeout, signal) => makeQuery(host, timeout, signal, fetchStub),
    dnssecCell, dnssecSummary,
    AbortController,
    setTimeout: () => 1, clearTimeout() {},
    requestAnimationFrame: fn => fn(), ResizeObserver: class { observe() {} },
    document: {
      documentElement: { style: { setProperty() {} } },
      getElementById(id) { assert.ok(elements[id], `missing element ${id}`); return elements[id] },
    },
    window: { location: { reload() {} }, RTCPeerConnection: class { constructor() { assert.fail('WebRTC must be opt-in') } } },
    WebSocket: class {
      constructor(url) { this.url = url; this.listeners = {}; this.readyState = 1; sockets.push(this); queueMicrotask(() => { socketOpened = true; this.listeners.open() }) }
      addEventListener(name, fn) { this.listeners[name] = fn }
      close() { this.readyState = 3; this.listeners.close?.({ code: 1000 }) }
    },
    console: { log() {} },
  })
  vm.runInContext(read('website/dnscheck.tools/main.js').replace(/^import .*$/gm, ''), sandbox)
  return { elements, columns, requests, sockets }
}

test('the full browser flow stays inactive until Run and never probes an upstream operator', async () => {
  const page = createPage('invalid-errors')
  assert.equal(page.requests.length, 0)
  assert.equal(page.sockets.length, 0)
  await page.elements['run-button'].listeners.click()
  assert.equal(page.sockets.length, 1)
  assert.match(page.sockets[0].url, /\/watch\/[a-f0-9]{32}$/)
  assert.ok(page.requests.length > 0)
  assert.ok(page.requests.every(url => new URL(url).hostname.endsWith('.dns.operator.test')))
  assert.ok(page.columns.every(column => column.textContent === 'UNKNOWN'))
  assert.match(page.elements['dnssec-summary'].textContent, /Inconclusive/)
  assert.doesNotMatch(page.elements['dnssec-status'].innerHTML, /green/)
})

test('full browser flow reports invalid HTTP503 responses as reached, and failed controls as inconclusive', async () => {
  const reached = createPage('invalid-503')
  await reached.elements['run-button'].listeners.click()
  assert.ok(reached.columns.every(column => column.textContent.startsWith('REACHED')))
  assert.match(reached.elements['dnssec-status'].innerHTML, /class="red"/)
  const failed = createPage('all-errors')
  await failed.elements['run-button'].listeners.click()
  assert.ok(failed.columns.every(column => column.textContent === 'NO CTRL'))
  assert.match(failed.elements['dnssec-summary'].textContent, /valid control was unavailable/)
  assert.equal(failed.requests.filter(url => /-(badsig|expiredsig|nosig)\./.test(url)).length, 0)
})

test('the disabled default cannot open a watcher or submit a test', () => {
  const page = createPage('invalid-errors', false)
  assert.equal(page.elements['run-button'].disabled, true)
  assert.equal(page.elements['run-button'].listeners.click, undefined)
  assert.equal(page.sockets.length, 0)
  assert.equal(page.requests.length, 0)
})

test('RDAP names matching inherited object properties are rendered as ordinary labels', () => {
  const source = read('website/dnscheck.tools/main.js')
  const start = source.indexOf('const ipList =')
  const end = source.indexOf('// updates style vars', start)
  const objects = ['__proto__', 'constructor', 'toString', '<script>'].map(reg => ({ reg, ipOrRange: { compareTo: () => 0 } }))
  objects.push({ ...objects[0] })
  const sandbox = vm.createContext({ objects, encode: value => value.replace(/</g, '&lt;').replace(/>/g, '&gt;'), ipItem: () => '<li>IP</li>' })
  vm.runInContext(source.slice(start, end), sandbox)
  const html = vm.runInContext('ipList(objects)', sandbox)
  for (const label of ['__proto__', 'constructor', 'toString', '&lt;script&gt;']) assert.ok(html.includes(label))
  assert.equal((html.match(/<li>IP<\/li>/g) ?? []).length, objects.length)
  assert.doesNotMatch(html, /<script>/)
})
