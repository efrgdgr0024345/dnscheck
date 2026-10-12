// Modified for https://github.com/efrgdgr0024345/dnscheck on 2026-10-12; original project by Brian Shea and contributors. See docs/UPSTREAM.md.
import { IPAddr, IPRange }      from '/js/ipaddr.js'
import { Client as RDAPClient } from '/js/rdap.js'
import { encode, fetchOk, randomId } from '/js/util.js'
import { makeQuery, dnssecCell, dnssecSummary } from './probes.js'
import { config, configurationError } from './config.js'

// state
const clientId       = randomId()
const rdapClient     = new RDAPClient()
const geoLookups     = {}               // geolocation lookup promises by IP string
const ipData         = {}               // combined IP data promises
const clientIPs      = {}               // detected HTTP request source and WebRTC ICE candidate IPs
const clientSubnets  = {}               // EDNS advertised client subnets
const resolvers      = {}               // detected DNS resolvers
const dnssecTests    = [ ...Array(16) ] // DNSSEC test results
const echTests       = []               // ECH test results
const rtts           = []               // DNS round trip times
const udpSizes       = []               // EDNS advertised UDP buffer sizes
let count            = 0                // number of DNS requests received
let ipLongestLength  = 0                // longest IP length (used for css var --ip-min-width)
let ptrLongestLength = 0                // longest PTR/NS length (used for css var --ptr-min-width)
let geoLongestLength = 0                // longest geo length (used for css var --geo-min-width)
let seenIPv6         = false            // whether any DNS requests have been seen over IPv6

// commonly used elements
const rootEl           = document.documentElement
const contentDiv       = document.getElementById('content')
const connectionDiv    = document.getElementById('connection-results')
const clientSubnetsDiv = document.getElementById('ecs-results')
const resolversDiv     = document.getElementById('resolver-results')
const dnssecDiv        = document.getElementById('dnssec-results')
const doneMsgDiv       = document.getElementById('done-msg')
const rttStatusSpan    = document.getElementById('rtt-status')
const ednsStatusSpan   = document.getElementById('edns-status')
const dnssecStatusSpan = document.getElementById('dnssec-status')
const echStatusSpan    = document.getElementById('ech-status')
const ipv6StatusSpan   = document.getElementById('ipv6-status')
const adoxStatusSpan   = document.getElementById('adox-status')
const countSpan        = document.getElementById('count')

// reserved IP ranges
// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
const reservedRanges = [
  new IPRange('0.0.0.0/8'),             // current network
  new IPRange('10.0.0.0/8'),            // private
  new IPRange('100.64.0.0/10'),         // cgnat
  new IPRange('127.0.0.0/8'),           // loopback
  new IPRange('169.254.0.0/16'),        // link-local
  new IPRange('172.16.0.0/12'),         // private
  new IPRange('192.0.0.0/24'),          // protocol assignments
  new IPRange('192.0.2.0/24'),          // documentation
  new IPRange('192.168.0.0/16'),        // private
  new IPRange('198.18.0.0/15'),         // benchmarking
  new IPRange('198.51.100.0/24'),       // documentation
  new IPRange('203.0.113.0/24'),        // documentation
  new IPRange('224.0.0.0/4'),           // multicast
  new IPRange('240.0.0.0/4'),           // future use, limited broadcast
  new IPRange('::/127'),                // unspecified, loopback
  new IPRange('64:ff9b:1::/48'),        // local-use ipv4/ipv6 translation
  new IPRange('100::/64'),              // discard
  new IPRange('100:0:0:1::/64'),        // dummy prefix
  new IPRange('2001::/23'),             // protocol assignments
  new IPRange('2001:db8::/32'),         // documentation
  new IPRange('2002::/16'),             // 6to4
  new IPRange('3fff::/20'),             // documentation
  new IPRange('5f00::/16'),             // segment routing
  new IPRange('fc00::/7'),              // private
  new IPRange('fe80::/10'),             // link-local
  new IPRange('ff00::/8'),              // multicast
]

// tests if the given IPAddr or entire IPRange is contained within a reserved IP range
const isReserved = ipOrRange => reservedRanges.some(r => r.contains(ipOrRange))

// Load enrichment data lazily, after a visitor has started a check.
let knownRangesPromise
const getKnownRanges = () => knownRangesPromise ??= fetchOk(config.knownRangesURL)
  .then(r => r.json())
  .then(objs => objs.flatMap(({ desc, ranges }) => ranges.map(cidr => ({ desc, range: new IPRange(cidr) }))))
  .catch(() => [])

// returns promise of RDAP registrant name or other identifier for given IPAddr or IPRange
const getReg = async ipOrRange => {
  const known = (await getKnownRanges()).find(({ range }) => range.contains(ipOrRange))
  if (known && !known.desc.includes('{}')) {
    return known.desc
  }
  const rdap = await rdapClient.lookupIP(ipOrRange)
  const reg = rdap.registrantName?.replace(/,?\s+(?:l\.?l\.?c\.?|ltd\.?|inc\.?)$/i, '') || rdap.data.name || rdap.data.handle
  if (known) {
    return known.desc.replace('{}', reg)
  }
  return reg
}

// returns cached promise of geolocation for given IPAddr or IPRange
const getGeo = ipOrRange => {
  const ip = ipOrRange instanceof IPRange ? ipOrRange.start : ipOrRange
  const str = `${ip.toRange(ip.is4() ? 24 : 56).start}`
  if (geoLookups[str] === undefined) {
    geoLookups[str] = (config.geolocationURL ? fetchOk(`${config.geolocationURL}${str}`) : Promise.reject(new Error('Geolocation disabled')))
      .then(r => r.json())
      .then(o => [ o.city, o.region, o.country ].filter(Boolean).join(', '))
  }
  return geoLookups[str]
}

// returns promise of PTR name or SOA NS for given IPAddr
const getPtr = ip => fetchOk(`${config.dnsLookupURL}${ip.reverseZone()}/ptr`)
  .then(r => r.json())
  .then(o => {
    const ptr = o.Answer?.find(({ type }) => type === 12)?.data?.slice(0, -1)
    if (ptr) {
      return fetchOk(`${config.dnsLookupURL}${ptr}/${ip.is4() ? 'a' : 'aaaa'}`)
        .then(r => r.json())
        .then(o => {
          const ptrFwdOk = o.Answer?.some(({ type, data }) => [ 1, 28 ].includes(type) && ip.equals(new IPAddr(data)))
          return { ptr, ptrFwdOk }
        })
    }
    const ns = o.Authority?.find(({ type }) => type === 6)?.data?.split(' ')[0].slice(0, -1)
    return { ns }
  })

// returns cached promise of combined geo, ptr, and rdap reg data for given IP or CIDR string
const getIPData = str => {
  if (ipData[str] === undefined) {
    const ipOrRange = str.includes('/') ? new IPRange(str) : new IPAddr(str)
    if (isReserved(ipOrRange)) {
      ipData[str] = Promise.resolve({ str, ipOrRange, reserved: true })
    } else {
      const gets = [
        getReg(ipOrRange).then(reg => ({ reg }), () => ({})),
        getGeo(ipOrRange).then(geo => ({ geo }), () => ({})),
      ]
      if (ipOrRange instanceof IPAddr) {
        gets.push(getPtr(ipOrRange).catch(() => ({})))
      }
      ipData[str] = Promise.all(gets).then(data => Object.assign({ str, ipOrRange }, ...data))
    }
  }
  return ipData[str]
}

// generates HTML for an IP list item
const ipItem = ({ str, reserved, ptr, ptrFwdOk, ns, geo }) => {
  let html = '<li>'
  if (reserved || !config.ipInfoURL) {
    html += `<span>${encode(str)}</span>`
  } else {
    html += `<span><a class="no-ul" href="${encode(config.ipInfoURL + str)}" target="_blank" rel="noopener noreferrer">${str}</a></span>`
  }
  if (ptr) {
    html += ' <span class="blue" title="PTR record (reverse DNS) for this IP'
    if (!ptrFwdOk) {
      html += '\n\nWarning: The claimed hostname does not resolve to this IP'
    }
    html += '">ptr: '
    if (!ptrFwdOk) {
      html += '<span class="unverified-ptr">'
    }
    html += encode(ptr)
    if (!ptrFwdOk) {
      html += '</span>'
    }
    html += '</span>'
  } else if (ns) {
    html += ` <span class="violet" title="Authoritative nameserver for this IP's reverse DNS">ns: ${encode(ns)}</span>`
  } else {
    html += '<span></span>'
  }
  if (geo) {
    html += ` <span class="indigo">${encode(geo)}</span>`
  } else {
    html += '<span></span>'
  }
  html += '</li>'
  return html
}

// generates HTML for an IP list given an array of IP data objects
const ipList = objs => {
  let html = ''
  const byReg = Object.create(null)
  objs.filter(({ pending, reserved }) => !pending && !reserved).forEach(obj => {
    if (byReg[obj.reg || ''] === undefined) {
      byReg[obj.reg || ''] = [ obj ]
    } else {
      byReg[obj.reg || ''].push(obj)
    }
  })
  Object.keys(byReg).sort((a, b) => a ? b ? a.localeCompare(b) : -1 : 1).forEach(reg => {
    html += `<div class="subtitle">${reg ? encode(reg) : '<i>Unknown</i>'}</div>` +
      `<ul class="ip-list">${byReg[reg].sort((a, b) => a.ipOrRange.compareTo(b.ipOrRange)).map(ipItem).join('')}</ul>`
  })
  const pending = objs.filter(({ pending }) => pending)
  if (pending.length) {
    html += '<div class="subtitle"><i>Pending</i></div>' +
      `<ul class="ip-list">${pending.map(ipItem).join('')}</ul>`
  }
  const reserved = objs.filter(({ reserved }) => reserved)
  if (reserved.length) {
    html += '<div class="subtitle"><i>Reserved</i></div>' +
      `<ul class="ip-list">${reserved.sort((a, b) => a.ipOrRange.compareTo(b.ipOrRange)).map(ipItem).join('')}</ul>`
  }
  return html
}

// updates style vars --ip-min-width, --ptr-min-width, --geo-min-width given an array of IP data objects
const updateMinWidths = objs => {
  const thisLongestIP = Math.max(...objs.map(({ str }) => str.length))
  if (thisLongestIP > ipLongestLength) {
    ipLongestLength = thisLongestIP
    rootEl.style.setProperty('--ip-min-width', `${ipLongestLength}ch`)
  }
  const thisLongestPTR = Math.max(...objs.map(({ ptr, ns }) => ptr ? ptr.length + 5 : ns ? ns.length + 4 : 0))
  if (thisLongestPTR > ptrLongestLength) {
    ptrLongestLength = thisLongestPTR
    rootEl.style.setProperty('--ptr-min-width', `${ptrLongestLength}ch`)
  }
  const thisLongestGEO = Math.max(...objs.map(({ geo }) => geo ? geo.length : 0))
  if (thisLongestGEO > geoLongestLength) {
    geoLongestLength = thisLongestGEO
    rootEl.style.setProperty('--geo-min-width', `${geoLongestLength}ch`)
  }
}

// draws the client IPs section
const drawIPs = () => {
  const objs = Object.values(clientIPs)
  connectionDiv.innerHTML = connectionDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// draws the EDNS Client Subnets section
const drawClientSubnets = () => {
  const objs = Object.values(clientSubnets)
  clientSubnetsDiv.classList.remove('hidden')
  clientSubnetsDiv.innerHTML = clientSubnetsDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// draws the DNS resolvers section
const drawResolvers = () => {
  const objs = Object.values(resolvers)
  resolversDiv.innerHTML = resolversDiv.firstElementChild.outerHTML + ipList(objs)
  updateMinWidths(objs)
}

// Display only observations the browser can establish. Network errors are unknown.
const drawDNSSEC = (() => {
  let columns
  return () => {
    if (!columns) {
      dnssecDiv.innerHTML = dnssecDiv.firstElementChild.outerHTML +
        '<div><table class="dnssec"><caption>DNSSEC probe observations</caption>' +
        '<thead><tr><th>Signature</th><th>ECDSA P-256</th><th>ECDSA P-384</th><th>Ed25519</th><th>ML-DSA-44*</th></tr></thead>' +
        '<tbody>' + ['Invalid', 'Expired', 'Missing'].map(label =>
          `<tr><th>${label}</th>${'<td class="pending">…</td>'.repeat(4)}</tr>`).join('') +
        '</tbody></table></div>' +
        '<p class="padleft-1">REACHED = the invalid test domain returned an HTTP response. ' +
        'UNKNOWN = DNSSEC rejection and other connection failures cannot be distinguished. ' +
        'NO CTRL = the valid control could not be reached. *Algorithm support varies.</p>' +
        '<p class="padleft-1">A browser test cannot certify that all your DNS responses are authenticated.</p>'
      columns = dnssecDiv.getElementsByTagName('td')
    }
    Array.from(columns).forEach((column, index) => {
      const cell = dnssecCell(dnssecTests[index % 4], dnssecTests[index + 4], index % 4 === 3)
      column.className = cell.className
      column.textContent = cell.label
      column.title = cell.title
    })
    const result = dnssecSummary(dnssecTests)
    dnssecStatusSpan.innerHTML = `<span class="${result.className}" title="${encode(result.text)}">DNSSEC</span>`
    document.getElementById('dnssec-summary').textContent = result.text
  }
})()

// HTTP IP checks run with the main test. WebRTC runs only on a separate click.
const handleClientIP = str => {
  let ip
  try { ip = new IPAddr(str.trim()).toString(true) } catch { return }
  if (clientIPs[ip] !== undefined) return
  clientIPs[ip] = { str: ip, pending: true }
  drawIPs()
  getIPData(ip).then(data => { clientIPs[ip] = data; drawIPs() })
}

const testIPs = () => {
  for (const url of [config.ipv4URL, config.ipv6URL].filter(Boolean)) {
    fetchOk(url).then(r => r.text()).then(handleClientIP).catch(() => {})
  }
  if (!config.ipv4URL && !config.ipv6URL) {
    connectionDiv.innerHTML = connectionDiv.firstElementChild.outerHTML + '<p>HTTP IP checks are not configured.</p>'
  }
}

const testWebRTC = async () => {
  const button = document.getElementById('webrtc-button')
  const status = document.getElementById('webrtc-status')
  button.disabled = true
  if (!config.stunServers.length || !window.RTCPeerConnection) {
    status.textContent = 'WebRTC or an operator-configured STUN server is unavailable.'
    return
  }
  status.textContent = 'Checking the configured STUN servers. No camera or microphone access is requested.'
  let peerConn, timer
  const finish = () => {
    clearTimeout(timer)
    peerConn?.close()
    status.textContent = 'WebRTC check finished. Your browser may hide some local addresses.'
  }
  try {
    peerConn = new RTCPeerConnection({ iceServers: config.stunServers.map(urls => ({ urls })) })
    peerConn.addEventListener('icecandidate', ({ candidate }) => {
      if (candidate?.candidate) handleClientIP(candidate.candidate.split(' ')[4])
    })
    peerConn.addEventListener('icegatheringstatechange', () => {
      if (peerConn.iceGatheringState === 'complete') finish()
    })
    timer = setTimeout(finish, 15000)
    peerConn.createDataChannel('ip-check')
    await peerConn.setLocalDescription(await peerConn.createOffer())
  } catch {
    finish()
    status.textContent = 'The WebRTC check could not complete.'
  }
}

// detects DNS resolvers and DNSSEC validation
const testDNS = () => new Promise(done => {
  // listen for DNS requests via WebSocket
  const socket = new WebSocket(`${config.websocketURL}${clientId}`)

  // abort all requests on close
  const abortController = new AbortController()
  const connectTimeout = setTimeout(() => {
    abortController.abort()
    socket.close()
    for (let i = 0; i < dnssecTests.length; i++) dnssecTests[i] = null
    drawDNSSEC()
    done()
  }, 15000)

  // on open
  socket.addEventListener('open', async () => {
    clearTimeout(connectTimeout)
    console.log('WebSocket opened')
    // generate some DNS requests
    for (let i = 0; i < 4; i++) {
      await makeQuery(`${String.fromCharCode(97 + i)}.${clientId}-nullip.test.${config.probeBaseDomain}`, 10000, abortController.signal)
    }
    // test IPv6 support
    if (!seenIPv6) {
      await makeQuery(`${clientId}-nullip.test-ipv6.${config.probeBaseDomain}`, 10000, abortController.signal)
    }
    if (!seenIPv6) {
      ipv6StatusSpan.innerHTML = '<span class="yellow" title="No IPv6 authoritative DNS request was observed during these probes">IPv6?</span>'
    }
    // test DNSSEC validation, ECH
    drawDNSSEC()
    await Promise.all([ 'alg13', 'alg14', 'alg15', 'alg18' ].map(async (alg, algIndex) => {
      const fqdn = `${clientId}.test-${alg}.${config.probeBaseDomain}`
      const { connected, ech } = await makeQuery(fqdn, 10000, abortController.signal)
      dnssecTests[algIndex] = connected
      drawDNSSEC()
      if (connected !== true) {
        // No control response: mark this algorithm's remaining probes inconclusive.
        for (let sigIndex = 0; sigIndex < 3; sigIndex++) dnssecTests[4 + 4 * sigIndex + algIndex] = null
        drawDNSSEC()
        return
      }
      console.log(`ECH: ${fqdn} ${ech}`)
      echTests.push(ech)
      await Promise.all([ 'badsig', 'expiredsig', 'nosig' ].map((sigOpt, sigIndex) =>
        makeQuery(`${clientId}-${sigOpt}.test-${alg}.${config.probeBaseDomain}`, 30000, abortController.signal)
          .then(({ connected }) => {
            dnssecTests[4 + 4 * sigIndex + algIndex] = connected
            drawDNSSEC()
          })
      ))
    }))
    // update ECH status
    if (echTests.length) {
      let className, msg
      if (echTests.every(v => v === 'SUCCESS')) {
        className = 'green'
        msg = 'ECH related DNS records were retrieved, and the HTTPS server name was encrypted'
      } else if (echTests.some(v => v === 'GREASE')) {
        className = 'yellow'
        msg = 'ECH is supported, but the HTTPS server name was not encrypted (GREASE)\n\n' +
          'Possible reasons:\n' +
          '- filtering of ECH related DNS records\n' +
          '- insecure DNS transport\n' +
          '- something else'
      } else {
        className = 'yellow'
        msg = 'Your browser does not support ECH, or an error occurred'
      }
      echStatusSpan.innerHTML = `<span class="${className}" title="Encrypted Client Hello\n\n${msg}">ECH</span>`
    }
    // finished
    countSpan.classList.remove('light')
    doneMsgDiv.classList.remove('hidden')
    setTimeout(
      () => {
        if (socket.readyState === 1) {
          socket.close(1000)
        }
      },
      10000
    )
    done()
  })

  // on message
  socket.addEventListener('message', ({ data }) => {
    // parse data
    const request = JSON.parse(data)
    console.log(`DNS (${request.proto}): ${request.qname} IN ${request.qtype}`, request)
    // increment count
    countSpan.innerHTML = ++count
    // add resolver if new
    if (resolvers[request.remoteIp] === undefined) {
      resolvers[request.remoteIp] = {
        str: request.remoteIp,
        pending: true,
        requests: [],
      }
      drawResolvers()
      getIPData(request.remoteIp).then(data => {
        const { requests } = resolvers[request.remoteIp]
        resolvers[request.remoteIp] = { ...data, requests }
        drawResolvers()
      })
    }
    // add request
    resolvers[request.remoteIp].requests.push(request)
    // discover EDNS support, add UDP buffer size
    if (request.isEdns0 && !udpSizes.includes(request.udpSize)) {
      udpSizes.push(request.udpSize)
      udpSizes.sort((a, b) => a - b)
      ednsStatusSpan.innerHTML = `<span class="${udpSizes[0] < 1200 ? 'yellow' : 'green'}" ` +
        `title="Extension Mechanisms for DNS\n\nAdvertised UDP buffer sizes: ${udpSizes.join(', ')}">EDNS</span>`
    }
    // discover ECS
    if (request.clientSubnet && !request.clientSubnet.endsWith('/0') && clientSubnets[request.clientSubnet] === undefined) {
      clientSubnets[request.clientSubnet] = {
        str: request.clientSubnet,
        pending: true,
      }
      drawClientSubnets()
      getIPData(request.clientSubnet).then(data => {
        clientSubnets[request.clientSubnet] = data
        drawClientSubnets()
      })
    }
    // discover IPv6 support
    if (!seenIPv6 && request.remoteIp.includes(':')) {
      seenIPv6 = true
      ipv6StatusSpan.innerHTML = '<span class="green" title="An authoritative DNS request associated with this test was observed over IPv6">IPv6</span>'
    }
    // discover ADoX support
    if (request.proto === 'TLS' || request.proto === 'QUIC') {
      adoxStatusSpan.innerHTML = '<span class="blue" title="Authoritative DoT/DoQ\n\n' +
        'One or more queries associated with this public test ID reached the authoritative server over an encrypted transport">ADoX</span>'
    }
  })

  // on close
  socket.addEventListener('close', e => {
    clearTimeout(connectTimeout)
    console.log(`WebSocket closed (${e.code})`)
    abortController.abort()
    for (let i = 0; i < dnssecTests.length; i++) {
      if (dnssecTests[i] === undefined) dnssecTests[i] = null
    }
    drawDNSSEC()
    done()
    if (count === 0) {
      resolversDiv.innerHTML = resolversDiv.firstElementChild.outerHTML +
        '<p><span class="red">an error occurred.</span> ' +
        '<span class="link" onclick="window.location.reload()">reload</span> to try again.'
    }
  })
})

// detects DNS average round trip time
const testRTT = async () => {
  let name, start, rtt, avg
  for (let i = 0; i < 5; i++) {
    for (const zone of config.rttZones) {
      name = `test-${randomId()}.${zone}`
      start = Date.now()
      await makeQuery(name, 5000, new AbortController().signal)
      rtt = Date.now() - start
      console.log(`RTT: ${name}\t${rtt}ms`)
      rtts.push(rtt)
      avg = Math.round(rtts.reduce((sum, x) => sum + x) / rtts.length)
      rttStatusSpan.innerHTML = `<span class="${avg <= 150 ? 'green' : avg <= 500 ? 'yellow' : 'red'}">${avg}ms</span>`
    }
  }
  rttStatusSpan.classList.remove('light')
}

// monitors resizes to toggle IP list tabular mode
const monitorResizes = () => {
  let minWidth
  const obsvr = new ResizeObserver(() => {
    requestAnimationFrame(() => {
      if (contentDiv.classList.contains('ip-list-tabular')) {
        if (contentDiv.scrollWidth > contentDiv.clientWidth) {
          minWidth = contentDiv.scrollWidth
          contentDiv.classList.remove('ip-list-tabular')
        }
        return
      }
      if (contentDiv.clientWidth >= minWidth) {
        contentDiv.classList.add('ip-list-tabular')
      }
    })
  })
  obsvr.observe(contentDiv)
  obsvr.observe(contentDiv.firstElementChild)
}

// No probe, enrichment lookup, or WebRTC connection runs before a visitor starts.
monitorResizes()
const runButton = document.getElementById('run-button')
const setupMessage = document.getElementById('setup-message')
const setupError = configurationError()
if (setupError) {
  runButton.disabled = true
  setupMessage.textContent = setupError + ' See the deployment guide linked below.'
} else {
  setupMessage.textContent = 'Ready. These checks contact this operator’s test services and public registration-data providers.'
  runButton.addEventListener('click', async () => {
    runButton.disabled = true
    runButton.textContent = 'Checks running…'
    document.getElementById('webrtc-button').disabled = !config.stunServers.length
    testIPs()
    await testDNS()
    await Promise.allSettled(Object.values(ipData))
    if (config.rttZones.length) await testRTT()
    runButton.textContent = 'Checks complete — reload to run again'
  }, { once: true })
}
document.getElementById('webrtc-button').addEventListener('click', testWebRTC, { once: true })
