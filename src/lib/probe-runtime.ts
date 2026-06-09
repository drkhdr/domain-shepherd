import {
  type RedirectChainEntry,
  classifyProbeStatus,
  dedupeStrings,
  extractFramesetUrl,
  isImplicitlyRedirectedResponse,
  isProbeDomainInput,
  isExplicitRequestTimeoutError,
  MAX_REDIRECTS,
  matchesConfiguredParkedPatterns,
  normalizeDomain,
  normalizeParkedPatterns,
  normalizeProbeBatchConcurrency,
  REQUEST_TIMEOUT_MS,
  shouldProbeHttpsVariant,
  WHOIS_SERVER_OVERRIDES,
} from '@/lib/probe'
import type { ParkedPattern, ProbeDomainInput, ProbeErrorKind, ProbeResult, ProbeStatus, WhoisResult } from '@/lib/probe'

interface HttpProbeResult {
  status: ProbeStatus
  httpStatus?: number
  redirectChain: RedirectChainEntry[]
  finalUrl?: string
  framesetUrl?: string
  framesetHttpStatus?: number
  serverHeader?: string
  contentType?: string
  error?: string
  errorKind?: ProbeErrorKind
}

interface FollowUrlResult {
  finalUrl: string
  httpStatus?: number
}

interface ProbeRuntimeOptions {
  parkedPatterns?: ParkedPattern[]
}

interface DnsLookupResult {
  addresses: string[]
  cname?: string
  nameServers: string[]
  dnsError?: string
}

interface DnsAnswer {
  data?: string
  type?: number
}

interface DnsResponse {
  Status?: number
  Answer?: DnsAnswer[]
}

const APP_USER_AGENT = 'Domain Shepherd/0.1.0'
const WHOIS_TIMEOUT_MS = 7000
const WHOIS_PRIMARY_SERVER = 'whois.iana.org'
const DNS_TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  AAAA: 28,
}

function getEventDate(events: unknown, ...actions: string[]): string | undefined {
  if (!Array.isArray(events)) return undefined
  const normalizedActions = actions.map((action) => action.toLowerCase())
  for (const event of events) {
    if (!event || typeof event !== 'object') continue
    const record = event as Record<string, unknown>
    const action = typeof record.eventAction === 'string' ? record.eventAction.toLowerCase() : ''
    if (!normalizedActions.includes(action)) continue
    if (typeof record.eventDate === 'string') return record.eventDate
  }
  return undefined
}

function extractVCardText(entity: unknown, fieldName: string): string | undefined {
  if (!entity || typeof entity !== 'object') return undefined
  const card = (entity as Record<string, unknown>).vcardArray
  if (!Array.isArray(card) || !Array.isArray(card[1])) return undefined

  for (const entry of card[1]) {
    if (!Array.isArray(entry)) continue
    if (entry[0] !== fieldName) continue
    if (typeof entry[3] === 'string') return entry[3]
  }

  return undefined
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function findWhoisField(text: string, labels: string[]): string | undefined {
  for (const label of labels) {
    const match = text.match(new RegExp(`^\\s*${escapeRegex(label)}\\s*:\\s*(.+)$`, 'im'))
    if (match?.[1]) {
      return match[1].trim()
    }
  }

  return undefined
}

function findWhoisFields(text: string, labels: string[]): string[] {
  const values: string[] = []

  for (const label of labels) {
    const regex = new RegExp(`^\\s*${escapeRegex(label)}\\s*:\\s*(.+)$`, 'gim')
    let match: RegExpExecArray | null
    while ((match = regex.exec(text)) !== null) {
      const value = match[1]?.trim()
      if (value) {
        values.push(value)
      }
    }
  }

  return Array.from(new Set(values))
}

function firstWhoisValue(text: string, labels: string[]): string | undefined {
  return findWhoisField(text, labels) ?? findWhoisFields(text, labels)[0]
}

function normalizeWhoisStatuses(values: string[]): string[] {
  const statuses = values
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => value.replace(/\s+https?:\/\/\S+$/i, '').trim())
    .map((value) => value.split(/\s+/)[0])
    .filter(Boolean)

  return Array.from(new Set(statuses))
}

function normalizeWhoisNameServer(value: string): string | undefined {
  const candidate = value
    .trim()
    .replace(/\s+/g, ' ')
    .split(' ')[0]
    .replace(/\.$/, '')
    .toLowerCase()

  if (!candidate || !candidate.includes('.')) {
    return undefined
  }

  if (!/^[a-z0-9.-]+$/i.test(candidate)) {
    return undefined
  }

  return candidate
}

function findWhoisNameServers(text: string): string[] {
  const values: string[] = []
  const lines = text.split('\n')
  let inNameServerBlock = false

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r/g, '')
    const trimmed = line.trim()

    if (!trimmed) {
      inNameServerBlock = false
      continue
    }

    const singleLineMatch = line.match(/^\s*(?:Name Server|Nameserver|Name Servers|nserver)\s*:\s*(.+)$/i)
    if (singleLineMatch?.[1]) {
      const normalized = normalizeWhoisNameServer(singleLineMatch[1])
      if (normalized) {
        values.push(normalized)
      }

      inNameServerBlock = /^\s*Name Servers\s*:\s*$/i.test(line)
      continue
    }

    if (/^\s*Name Servers\s*:\s*$/i.test(line)) {
      inNameServerBlock = true
      continue
    }

    if (inNameServerBlock) {
      if (/^[A-Za-z][A-Za-z0-9 -]*\s*:/i.test(trimmed)) {
        inNameServerBlock = false
        continue
      }

      const normalized = normalizeWhoisNameServer(trimmed)
      if (normalized) {
        values.push(normalized)
        continue
      }

      inNameServerBlock = false
    }
  }

  return Array.from(new Set(values))
}

function cleanWhoisResponse(text: string): string {
  return text
    .replace(/\r\n/g, '\n')
    .split('\u0000').join('')
    .trim()
}

function getWhoisQuery(domain: string, server: string): string {
  if (server === 'whois.denic.de') {
    return `-T dn,ace ${domain}`
  }

  return domain
}

async function queryWhoisServer(server: string, query: string): Promise<string> {
  const { Socket } = await import('node:net')

  return await new Promise<string>((resolve, reject) => {
    const socket = new Socket()
    let settled = false
    let response = ''

    const finishResolve = (value: string) => {
      if (settled) {
        return
      }

      settled = true
      socket.destroy()
      resolve(value)
    }

    const finishReject = (error: Error) => {
      if (settled) {
        return
      }

      settled = true
      socket.destroy()
      reject(error)
    }

    socket.setTimeout(WHOIS_TIMEOUT_MS)

    socket.once('error', (error) => finishReject(error))
    socket.once('timeout', () => finishReject(new Error('WHOIS timeout')))
    socket.on('data', (chunk: Buffer) => {
      response += chunk.toString('utf8')
    })
    socket.once('end', () => finishResolve(response))
    socket.once('close', (hadError) => {
      if (!hadError) {
        finishResolve(response)
      }
    })

    socket.connect(43, server, () => {
      socket.write(`${query}\r\n`)
    })
  })
}

async function findWhoisServer(domain: string): Promise<string | undefined> {
  const tld = domain.split('.').pop()?.toLowerCase()
  if (!tld) {
    return undefined
  }

  if (WHOIS_SERVER_OVERRIDES[tld]) {
    return WHOIS_SERVER_OVERRIDES[tld]
  }

  const response = await queryWhoisServer(WHOIS_PRIMARY_SERVER, tld)
  return findWhoisField(response, ['refer', 'whois'])
}

async function fetchWhoisTraditional(domain: string): Promise<WhoisResult> {
  try {
    const primaryServer = await findWhoisServer(domain)
    if (!primaryServer) {
      return { error: 'WHOIS server not found' }
    }

    const primaryResponse = cleanWhoisResponse(await queryWhoisServer(primaryServer, getWhoisQuery(domain, primaryServer)))
    const registrarWhoisServer = firstWhoisValue(primaryResponse, [
      'Registrar WHOIS Server',
      'Whois Server',
      'ReferralServer',
    ])
      ?.replace(/^whois:\/\//i, '')
      .trim()

    const shouldFollowReferral = Boolean(
      registrarWhoisServer &&
      !registrarWhoisServer.includes('/') &&
      registrarWhoisServer.toLowerCase() !== primaryServer.toLowerCase()
    )

    const finalServer = shouldFollowReferral ? registrarWhoisServer! : primaryServer
    const finalResponse = shouldFollowReferral
      ? cleanWhoisResponse(await queryWhoisServer(finalServer, getWhoisQuery(domain, finalServer)))
      : primaryResponse
    const combinedResponse = shouldFollowReferral
      ? `${primaryResponse}\n\n# Registrar WHOIS\n${finalResponse}`
      : finalResponse

    const statuses = normalizeWhoisStatuses(
      findWhoisFields(combinedResponse, [
        'Domain Status',
        'Status',
        'state',
        'State',
        'Domain status',
      ])
    )

    return {
      registrar: firstWhoisValue(combinedResponse, [
        'Registrar',
        'registrar',
        'Sponsoring Registrar',
        'Registrar Name',
        'Record maintained by',
      ]),
      createdAt: firstWhoisValue(combinedResponse, [
        'Creation Date',
        'Created On',
        'Registered On',
        'Registration Time',
        'Created',
        'Domain Registration Date',
      ]),
      updatedAt: firstWhoisValue(combinedResponse, [
        'Updated Date',
        'Last Updated On',
        'Changed',
        'Modified',
        'Last Modified',
        'Changed Date',
      ]),
      expiresAt: firstWhoisValue(combinedResponse, [
        'Registry Expiry Date',
        'Registrar Registration Expiration Date',
        'Expiration Date',
        'Expire Date',
        'Paid-till',
        'Expiry Date',
        'Expires On',
        'Renewal Date',
      ]),
      abuseEmail: firstWhoisValue(combinedResponse, [
        'Registrar Abuse Contact Email',
        'abuse-mailbox',
        'OrgAbuseEmail',
        'Abuse Contact Email',
      ]),
      server: finalServer,
      nameServers: findWhoisNameServers(combinedResponse),
      statuses: statuses.length > 0 ? statuses : undefined,
      rawText: combinedResponse || undefined,
    }
  } catch (error) {
    // Fallback: return error, will try RDAP next
    return {
      error: error instanceof Error ? error.message : 'WHOIS lookup failed',
    }
  }
}

async function fetchWhois(domain: string): Promise<WhoisResult> {
  // Try traditional WHOIS first (server-side only), then RDAP as fallback.
  // Keep rawText plain text only; RDAP payload is structured JSON and not
  // equivalent to original WHOIS server text.
  const whoisResult = await fetchWhoisTraditional(domain)
  if (!whoisResult.error) {
    return whoisResult
  }

  const rdapResult = await fetchRdap(domain)
  return {
    ...rdapResult,
    rawText: undefined,
  }
}

async function fetchRdap(domain: string): Promise<WhoisResult> {
  const endpoints: string[] = [`https://rdap.org/domain/${domain}`, `https://www.rdap.net/domain/${domain}`]

  // Add TLD-specific RDAP servers
  const tld = domain.split('.').pop()?.toLowerCase()
  if (tld === 'de') {
    endpoints.push(`https://rdap.nic.de/domain/${domain}`)
  } else if (tld === 'uk') {
    endpoints.push(`https://rdap.nominet.uk/domain/${domain}`)
  } else if (tld === 'fr') {
    endpoints.push(`https://rdap.afnic.fr/domain/${domain}`)
  }

  let payload: Record<string, unknown> | null = null
  const errors: string[] = []

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint, {
        headers: {
          'user-agent': APP_USER_AGENT,
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        cache: 'no-store',
      })

      if (!response.ok) {
        errors.push(`${endpoint.split('/domain/')[0]} HTTP ${response.status}`)
        continue
      }

      payload = (await response.json()) as Record<string, unknown>
      break
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      errors.push(`${endpoint.split('/domain/')[0]} fetch: ${errorMsg}`)
    }
  }

  if (!payload) {
    return {
      error: errors.length > 0 ? `RDAP failed: ${errors.join('; ')}` : 'RDAP lookup failed',
    }
  }

  try {
    const entities = Array.isArray(payload.entities) ? payload.entities : []
    const registrarEntity = entities.find((entity) => {
      if (!entity || typeof entity !== 'object') return false
      const roles = (entity as Record<string, unknown>).roles
      return Array.isArray(roles) && roles.some((role) => typeof role === 'string' && role.toLowerCase() === 'registrar')
    })
    const abuseEntity = entities.find((entity) => {
      if (!entity || typeof entity !== 'object') return false
      const roles = (entity as Record<string, unknown>).roles
      return (
        Array.isArray(roles) &&
        roles.some(
          (role) => typeof role === 'string' && (role.toLowerCase() === 'abuse' || role.toLowerCase() === 'technical')
        )
      )
    })

    return {
      registrar:
        extractVCardText(registrarEntity, 'fn') ||
        extractVCardText(registrarEntity, 'org') ||
        (typeof payload.registrarName === 'string' ? payload.registrarName : undefined),
      createdAt: getEventDate(payload.events, 'registration'),
      updatedAt: getEventDate(payload.events, 'last changed'),
      expiresAt: getEventDate(payload.events, 'expiration', 'expiration date', 'expiry'),
      abuseEmail: extractVCardText(abuseEntity, 'email'),
      server: typeof payload.port43 === 'string' ? payload.port43 : undefined,
      nameServers: Array.isArray(payload.nameservers)
        ? dedupeStrings(
            payload.nameservers
              .map((server) =>
                server && typeof server === 'object' && typeof (server as Record<string, unknown>).ldhName === 'string'
                  ? ((server as Record<string, unknown>).ldhName as string)
                  : ''
              )
              .filter(Boolean)
          )
        : undefined,
      statuses: Array.isArray(payload.status)
        ? payload.status.filter((status): status is string => typeof status === 'string')
        : undefined,
    }
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : 'RDAP lookup failed',
    }
  }
}

async function resolveDoh(domain: string, type: number): Promise<{ values: string[]; status?: number }> {
  const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, {
    headers: {
      accept: 'application/dns-json',
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    cache: 'no-store',
  })

  if (!response.ok) {
    throw new Error(`DNS lookup failed with status ${response.status}`)
  }

  const payload = (await response.json()) as DnsResponse
  const values = Array.isArray(payload.Answer)
    ? payload.Answer
        .filter((answer) => answer?.type === type && typeof answer.data === 'string')
        .map((answer) => (answer.data as string).replace(/\.$/, ''))
    : []

  return {
    values,
    status: payload.Status,
  }
}

async function resolveDns(domain: string): Promise<DnsLookupResult> {
  const [a, aaaa, cname, ns] = await Promise.allSettled([
    resolveDoh(domain, DNS_TYPES.A),
    resolveDoh(domain, DNS_TYPES.AAAA),
    resolveDoh(domain, DNS_TYPES.CNAME),
    resolveDoh(domain, DNS_TYPES.NS),
  ])

  const addresses = dedupeStrings([
    ...(a.status === 'fulfilled' ? a.value.values : []),
    ...(aaaa.status === 'fulfilled' ? aaaa.value.values : []),
  ])
  const cnameValues = cname.status === 'fulfilled' ? cname.value.values : []
  const nameServers = ns.status === 'fulfilled' ? dedupeStrings(ns.value.values) : []

  if (addresses.length > 0 || cnameValues.length > 0) {
    return {
      addresses,
      cname: cnameValues[0],
      nameServers,
    }
  }

  const errors = [a, aaaa, cname]
    .filter((entry): entry is PromiseRejectedResult => entry.status === 'rejected')
    .map((entry) => (entry.reason instanceof Error ? entry.reason.message : String(entry.reason)))

  const statuses = [a, aaaa, cname]
    .filter((entry): entry is PromiseFulfilledResult<{ values: string[]; status?: number }> => entry.status === 'fulfilled')
    .map((entry) => entry.value.status)
    .filter((status): status is number => typeof status === 'number' && status !== 0)

  return {
    addresses,
    cname: cnameValues[0],
    nameServers,
    dnsError: errors[0] || (statuses.length > 0 ? `DNS response status ${statuses[0]}` : 'No DNS records found'),
  }
}

async function followHttp(domain: string, dnsNameServers: string[], options?: ProbeRuntimeOptions): Promise<HttpProbeResult> {
  async function followUrlRedirects(initialUrl: string): Promise<FollowUrlResult> {
    let currentUrl = initialUrl

    for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) {
      let response: Response
      try {
        response = await fetch(currentUrl, {
          redirect: 'manual',
          cache: 'no-store',
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          headers: {
            'user-agent': APP_USER_AGENT,
          },
        })
      } catch {
        return {
          finalUrl: currentUrl,
        }
      }

      if (isImplicitlyRedirectedResponse(currentUrl, response.url)) {
        currentUrl = response.url
        continue
      }

      const location = response.headers.get('location')
      if (location && response.status >= 300 && response.status < 400) {
        currentUrl = new URL(location, currentUrl).toString()
        continue
      }

      return {
        finalUrl: currentUrl,
        httpStatus: response.status,
      }
    }

    return {
      finalUrl: currentUrl,
    }
  }

  const redirectChain: RedirectChainEntry[] = []
  let currentUrl = `https://${domain}`
  let allowHttpFallback = true

  for (let attempt = 0; attempt <= MAX_REDIRECTS; attempt += 1) {
    let response: Response
    try {
      response = await fetch(currentUrl, {
        redirect: 'manual',
        cache: 'no-store',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: {
          'user-agent': APP_USER_AGENT,
        },
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Request failed'
      if (allowHttpFallback && currentUrl.startsWith('https://')) {
        currentUrl = `http://${domain}`
        allowHttpFallback = false
        continue
      }

      const timedOut = isExplicitRequestTimeoutError(error)

      return {
        status: timedOut ? 'timeout' : 'unreachable',
        redirectChain,
        finalUrl: currentUrl,
        error: message,
        errorKind: timedOut ? 'request-timeout' : 'network-error',
      }
    }

    if (isImplicitlyRedirectedResponse(currentUrl, response.url)) {
      redirectChain.push({
        url: currentUrl,
      })
      currentUrl = response.url
      allowHttpFallback = false
      continue
    }

    const location = response.headers.get('location')
    if (location && response.status >= 300 && response.status < 400) {
      const nextUrl = new URL(location, currentUrl).toString()
      redirectChain.push({
        url: currentUrl,
        responseStatus: response.status,
      })
      currentUrl = nextUrl
      allowHttpFallback = false
      continue
    }

    const finalUrl = currentUrl
    const serverHeader = response.headers.get('server') ?? undefined
    const contentType = response.headers.get('content-type') ?? undefined
    const bodyText = await response.text().catch(() => '')

    if (shouldProbeHttpsVariant(currentUrl, redirectChain, response.status)) {
      const httpsUrl = currentUrl.replace(/^http:/i, 'https:')
      if (httpsUrl !== currentUrl) {
        redirectChain.push({
          url: currentUrl,
          responseStatus: response.status,
        })
        currentUrl = httpsUrl
        allowHttpFallback = false
        continue
      }
    }

    const framesetSourceUrl = extractFramesetUrl(finalUrl, contentType, bodyText)
    const configuredParked = matchesConfiguredParkedPatterns(options?.parkedPatterns, dnsNameServers, bodyText)
    let framesetUrl = framesetSourceUrl
    let framesetHttpStatus: number | undefined

    if (framesetSourceUrl) {
      const framesetProbe = await followUrlRedirects(framesetSourceUrl)
      framesetUrl = framesetProbe.finalUrl
      framesetHttpStatus = framesetProbe.httpStatus
    }

    return {
      status: configuredParked
        ? 'parked'
        : framesetUrl
          ? 'frameset'
          : classifyProbeStatus(domain, finalUrl, redirectChain, serverHeader, contentType),
      httpStatus: response.status,
      redirectChain,
      finalUrl,
      framesetUrl,
      framesetHttpStatus,
      serverHeader,
      contentType,
      error: response.ok ? undefined : `HTTP request returned ${response.status}`,
      errorKind: response.ok ? undefined : 'network-error',
    }
  }

  return {
    status: 'unreachable',
    redirectChain,
    finalUrl: currentUrl,
    error: `Exceeded ${MAX_REDIRECTS} redirects`,
    errorKind: 'redirect-limit',
  }
}

export async function probeDomain(domainInput: ProbeDomainInput, options?: ProbeRuntimeOptions): Promise<ProbeResult> {
  const startedAt = Date.now()
  const domain = normalizeDomain(domainInput.domain)
  const whoisStartedAt = Date.now()
  const whoisPromise = fetchWhois(domain)
    .then((whois) => ({ whois, whoisMs: Date.now() - whoisStartedAt }))
    .catch(() => ({ whois: { error: 'WHOIS lookup failed' } as WhoisResult, whoisMs: Date.now() - whoisStartedAt }))

  const result: ProbeResult = {
    domainId: domainInput.id,
    domain,
    status: 'unreachable',
    redirectChain: [],
    ipAddresses: [],
    dnsNameServers: [],
    dnsMs: 0,
    httpMs: 0,
    whoisMs: 0,
    probeMs: 0,
  }

  try {
    const dnsStartedAt = Date.now()
    const dns = await resolveDns(domain)
    result.dnsMs = Date.now() - dnsStartedAt
    result.ipAddresses = dns.addresses
    result.cname = dns.cname
    result.dnsNameServers = dns.nameServers

    if (result.ipAddresses.length === 0 && !result.cname) {
      result.status = 'no-dns'
      result.dnsError = dns.dnsError || 'No DNS records found'
      const whoisResult = await whoisPromise
      result.whois = whoisResult.whois
      result.whoisMs = whoisResult.whoisMs
      result.probeMs = Date.now() - startedAt
      return result
    }

    const httpStartedAt = Date.now()
    const httpProbe = await followHttp(domain, dns.nameServers, options)
    result.httpMs = Date.now() - httpStartedAt
    result.status = httpProbe.status
    result.httpStatus = httpProbe.httpStatus
    result.redirectChain = httpProbe.redirectChain
    result.finalUrl = httpProbe.finalUrl
    result.framesetUrl = httpProbe.framesetUrl
    result.framesetHttpStatus = httpProbe.framesetHttpStatus
    result.serverHeader = httpProbe.serverHeader
    result.contentType = httpProbe.contentType
    result.error = httpProbe.error
    result.errorKind = httpProbe.errorKind
    const whoisResult = await whoisPromise
    result.whois = whoisResult.whois
    result.whoisMs = whoisResult.whoisMs
  } catch (error) {
    result.status = 'unreachable'
    result.error = error instanceof Error ? error.message : 'Probe failed'
    result.errorKind = 'probe-failed'
    const whoisResult = await whoisPromise
    result.whois = whoisResult.whois
    result.whoisMs = whoisResult.whoisMs
  }

  result.probeMs = Date.now() - startedAt
  return result
}

export async function runProbeBatch(domains: unknown, concurrency?: unknown, options?: ProbeRuntimeOptions): Promise<ProbeResult[]> {
  const entries = Array.isArray(domains) ? domains.filter(isProbeDomainInput) : []
  const results: ProbeResult[] = new Array(entries.length)
  let index = 0
  const batchConcurrency = normalizeProbeBatchConcurrency(concurrency)
  const normalizedOptions: ProbeRuntimeOptions = {
    parkedPatterns: normalizeParkedPatterns(options?.parkedPatterns),
  }

  async function worker(): Promise<void> {
    while (index < entries.length) {
      const current = index
      index += 1
      results[current] = await probeDomain(entries[current], normalizedOptions)
    }
  }

  const workerCount = Math.min(batchConcurrency, entries.length)
  await Promise.all(Array.from({ length: workerCount }, () => worker()))
  return results
}
