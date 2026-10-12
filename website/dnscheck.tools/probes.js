// Modified for https://github.com/efrgdgr0024345/dnscheck on 2026-10-12; original project by Brian Shea and contributors. See docs/UPSTREAM.md.
// Browser observations do not expose the DNS error that caused a fetch failure.
// Never turn a network/TLS/CORS/HTTP failure into proof of DNSSEC validation.
export async function makeQuery(fqdn, timeout, abortSignal, fetchFn = fetch) {
  if (abortSignal.aborted) {
    return { connected: null, outcome: 'aborted' }
  }
  const controller = new AbortController()
  const abortFn = () => controller.abort()
  const timeoutID = setTimeout(abortFn, timeout)
  abortSignal.addEventListener('abort', abortFn, { once: true })
  try {
    const response = await fetchFn(`https://${fqdn}/`, {
      signal: controller.signal,
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
    })
    // Any HTTP status, including 4xx/5xx, proves that a response was received.
    return {
      connected: true,
      outcome: 'http-response',
      httpStatus: response.status,
      ech: response.headers.get('X-ECH-Status'),
    }
  } catch (error) {
    return { connected: null, outcome: abortSignal.aborted ? 'aborted' : 'unavailable' }
  } finally {
    clearTimeout(timeoutID)
    abortSignal.removeEventListener('abort', abortFn)
  }
}

export function dnssecCell(control, probe, experimental = false) {
  if (control !== undefined && control !== true) {
    return { label: 'NO CTRL', className: 'yellow', title: 'The valid control was unavailable. This algorithm could not be tested.' }
  }
  if (probe === undefined) {
    return { label: '…', className: 'pending', title: 'Waiting for this test.' }
  }
  if (probe === true) {
    return {
      label: experimental ? 'REACHED*' : 'REACHED',
      className: experimental ? 'yellow' : 'red',
      title: 'An HTTP response was received for this deliberately invalid DNSSEC domain. The tested path did not reject it.' +
        (experimental ? ' Support for this experimental algorithm varies.' : ''),
    }
  }
  return {
    label: 'UNKNOWN',
    className: 'yellow',
    title: 'No HTTP response was available. DNSSEC rejection, DNS or TLS failure, filtering, CORS, and other network errors cannot be distinguished here.',
  }
}

export function dnssecSummary(tests) {
  if (tests.slice(4).some((result, index) => result === true && index % 4 !== 3)) {
    return { className: 'red', text: 'An invalid DNSSEC test domain was reachable. This test path did not reject it.' }
  }
  if (tests.slice(0, 4).some(result => result !== undefined && result !== true)) {
    return { className: 'yellow', text: 'Inconclusive: at least one valid control was unavailable.' }
  }
  if (tests.every(result => result !== undefined)) {
    return {
      className: 'yellow',
      text: 'Inconclusive: unavailable invalid domains may be consistent with DNSSEC rejection, but browser failures cannot prove validation.',
    }
  }
  return { className: 'light', text: 'DNSSEC probes are pending. This browser test cannot certify all DNS responses.' }
}
