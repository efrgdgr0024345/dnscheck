// Modified for https://github.com/efrgdgr0024345/dnscheck on 2026-10-12; original project by Brian Shea and contributors. See docs/UPSTREAM.md.
export class HTTPError extends Error {
  constructor(code) {
    super(`Received HTTP status code ${code}`)
    this.code = code
    this.name = 'HTTPError'
  }
}
export class Mutex {
  #queue = []
  #locked = false
  async lock() {
    return new Promise(resolve => {
      if (this.#locked) {
        this.#queue.push({ resolve })
      } else {
        this.#locked = true
        resolve()
      }
    })
  }
  unlock() {
    const next = this.#queue.shift()
    if (next) {
      next.resolve()
    } else {
      this.#locked = false
    }
  }
}
export function encode(str) {
  return str?.replace(/["&<>]/g, match => `&#${match.charCodeAt(0)};`)
}
export async function fetchOk(resource, opts) {
  return fetch(resource, Object.assign({ referrerPolicy: 'no-referrer' }, opts))
    .then(response => response.ok ? response : (() => { throw new HTTPError(response.status) })())
}

// A public correlation ID, not an authentication credential. Never fall back to
// Math.random: the diagnostic requires a secure context and Web Crypto.
export function randomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}
