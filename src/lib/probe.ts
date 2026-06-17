export type ProbeStatus = 'ok' | 'redirected' | 'parked' | 'frameset' | 'unreachable' | 'no-dns' | 'timeout'
export type ProbeErrorKind = 'request-timeout' | 'network-error' | 'redirect-limit' | 'probe-failed'
export type SortKey = 'domain' | 'status' | 'code' | 'target' | 'whoisStatus' | 'nsSld'
export type SortDirection = 'asc' | 'desc'
export type WhoisStatusFamily = 'ICANN EPP' | 'DENIC' | 'Unknown'

export interface ProbeDomainInput {
  id: string
  domain: string
}

export interface WhoisResult {
  registrar?: string
  createdAt?: string
  updatedAt?: string
  expiresAt?: string
  abuseEmail?: string
  server?: string
  nameServers?: string[]
  statuses?: string[]
  rawText?: string
  error?: string
}

export interface RedirectChainEntry {
  url: string
  responseStatus?: number
  serverHeader?: string
}

export type RedirectChainItem = string | RedirectChainEntry

export interface ProbeResult {
  domainId: string
  domain: string
  status: ProbeStatus
  httpStatus?: number
  redirectChain?: RedirectChainItem[]
  finalUrl?: string
  framesetUrl?: string
  framesetHttpStatus?: number
  serverHeader?: string
  contentType?: string
  ipAddresses?: string[]
  cname?: string
  dnsNameServers?: string[]
  whois?: WhoisResult
  dnsError?: string
  error?: string
  errorKind?: ProbeErrorKind
  dnsMs: number
  httpMs: number
  whoisMs: number
  probeMs: number
}

export interface ParkedPattern {
  nsSld?: string
  responseRegex: string
}

export const DEFAULT_PARKED_PATTERNS: ReadonlyArray<ParkedPattern> = [
  { nsSld: 'udag', responseRegex: 'Diese neue Domain wurde im Kundenauftrag registriert.' },
  { nsSld: 'nic', responseRegex: '\\.tel' },
]

export const ICANN_EPP_STATUS_DEFINITIONS: Record<string, string> = {
  ok: 'Standard active EPP status with no pending operations or restrictions.',
  inactive: 'Domain exists but has no working delegation (typically no nameservers).',
  clienttransferprohibited: 'Registrar lock: transfer to another registrar is blocked by the registrar.',
  servertransferprohibited: 'Registry lock: transfer to another registrar is blocked by the registry.',
  clientupdateprohibited: 'Registrar lock: domain data cannot be updated by registrar-side command.',
  serverupdateprohibited: 'Registry lock: domain data updates are blocked by the registry.',
  clientdeleteprohibited: 'Registrar lock: deletion is blocked by registrar-side command.',
  serverdeleteprohibited: 'Registry lock: deletion is blocked by the registry.',
  clientrenewprohibited: 'Registrar-side lock that prevents renew commands.',
  serverrenewprohibited: 'Registry-side lock that prevents renew commands.',
  clienthold: 'Registrar has set hold; domain is typically removed from DNS zone publication.',
  serverhold: 'Registry has set hold; domain is typically removed from DNS zone publication.',
  pendingcreate: 'Creation request is pending completion at the registry.',
  pendingdelete: 'Deletion request is pending completion at the registry.',
  pendingrenew: 'Renew request is pending completion at the registry.',
  pendingtransfer: 'Registrar transfer is pending completion.',
  pendingupdate: 'Update request is pending completion at the registry.',
  redemptionperiod: 'Domain is in redemption grace period after deletion.',
  pendingrestore: 'Restore request has been submitted and is pending completion.',
  addperiod: 'Domain is in add grace period shortly after initial creation.',
  autorenewperiod: 'Domain is in auto-renew grace period after expiry auto-renew.',
  renewperiod: 'Domain is in renew grace period after explicit renewal.',
  transferperiod: 'Domain is in transfer grace period after successful transfer.',
}

export const DENIC_STATUS_DEFINITIONS: Record<string, string> = {
  connect: 'Domain is delegated and connected in the .de zone.',
  failed: 'Domain exists but delegation is currently not connected due to configuration issues.',
  free: 'Domain is currently available for registration.',
  invalid: 'Domain exists but is in an invalid technical state.',
  active: 'Standard active status with no restrictions.',
  'inactive-voluntary': 'Domain inactive; registrant is voluntarily inactive.',
  'inactive-payment': 'Domain inactive due to payment issues.',
  'inactive-registration': 'Domain inactive; no delegation/nameservers.',
  'inactive-public': 'Domain inactive; no delegation; public suffix.',
  reserved: 'Domain is reserved for special use.',
  deleted: 'Domain has been deleted.',
  'transfer-prohibited': 'Transfer to another registrar is prohibited.',
  'update-prohibited': 'Domain data updates are prohibited.',
  'delete-prohibited': 'Deletion is prohibited.',
  'renew-prohibited': 'Renewal is prohibited.',
  'transfer-protected': 'Domain protection is active; transfer is restricted.',
}

function normalizeWhoisStatusValue(status: string): string {
  let normalized = status.trim().toLowerCase()
  if (!normalized) return ''

  // RDAP commonly returns EPP statuses as URLs like
  // https://icann.org/epp#clientTransferProhibited.
  const hashIndex = normalized.lastIndexOf('#')
  if (hashIndex >= 0 && hashIndex < normalized.length - 1) {
    normalized = normalized.slice(hashIndex + 1)
  } else {
    const slashIndex = normalized.lastIndexOf('/')
    if (slashIndex >= 0 && slashIndex < normalized.length - 1) {
      normalized = normalized.slice(slashIndex + 1)
    }
  }

  return normalized.replace(/[^a-z0-9]/g, '')
}

const ICANN_EPP_STATUS_DEFINITIONS_NORMALIZED: Record<string, string> = Object.fromEntries(
  Object.entries(ICANN_EPP_STATUS_DEFINITIONS).map(([key, value]) => [normalizeWhoisStatusValue(key), value])
)

const DENIC_STATUS_DEFINITIONS_NORMALIZED: Record<string, string> = Object.fromEntries(
  Object.entries(DENIC_STATUS_DEFINITIONS).map(([key, value]) => [normalizeWhoisStatusValue(key), value])
)

export const MAX_REDIRECTS = 8
export const REQUEST_TIMEOUT_MS = 12_000
const PROBE_BATCH_CONCURRENCY_FALLBACK = 10
export const PROBE_BATCH_CONCURRENCY_MIN = 1
export const PROBE_BATCH_CONCURRENCY_MAX = 50
const PROBE_MAX_ATTEMPTS_FALLBACK = 2
export const PROBE_MAX_ATTEMPTS_MIN = 1
export const PROBE_MAX_ATTEMPTS_MAX = 5

const PROBE_BATCH_CONCURRENCY_ENV_VALUE =
  process.env.NEXT_PUBLIC_PROBE_BATCH_CONCURRENCY ?? process.env.PROBE_BATCH_CONCURRENCY
const PROBE_MAX_ATTEMPTS_ENV_VALUE = process.env.NEXT_PUBLIC_PROBE_MAX_ATTEMPTS ?? process.env.PROBE_MAX_ATTEMPTS

export const WHOIS_SERVER_OVERRIDES: Record<string, string> = {
  ai: 'whois.nic.ai',
  de: 'whois.denic.de',
  io: 'whois.nic.io',
  org: 'whois.pir.org',
  uk: 'whois.nominet.uk',
  fr: 'whois.afnic.fr',
}

export interface DefaultProbeSettings {
  batchConcurrency: number
  maxAttempts: number
  parkedPatterns: ParkedPattern[]
}

export function dedupeStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b))
}

export function createDefaultProbeSettings(): DefaultProbeSettings {
  return {
    batchConcurrency: PROBE_BATCH_CONCURRENCY_DEFAULT,
    maxAttempts: PROBE_MAX_ATTEMPTS_DEFAULT,
    parkedPatterns: getDefaultParkedPatterns(),
  }
}

export function normalizeDomain(domain: string): string {
  const trimmed = domain.trim().toLowerCase()
  if (!trimmed) return ''

  const parseHostname = (value: string): string | undefined => {
    try {
      return new URL(value).hostname.toLowerCase()
    } catch {
      return undefined
    }
  }

  const hostname = parseHostname(trimmed) ?? parseHostname(`http://${trimmed}`)
  const base = (hostname ?? trimmed)
    .replace(/^[^@]*@/, '')
    .split(/[/?#]/, 1)[0]
    .replace(/:\d+$/, '')

  return base.replace(/\.+$/, '')
}

export function isProbeDomainInput(value: unknown): value is ProbeDomainInput {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Record<string, unknown>
  return typeof candidate.id === 'string' && typeof candidate.domain === 'string'
}

export function normalizeRedirectChainItem(item: RedirectChainItem): RedirectChainEntry | undefined {
  if (typeof item === 'string') {
    const url = item.trim()
    return url ? { url } : undefined
  }

  if (!item || typeof item.url !== 'string') {
    return undefined
  }

  const url = item.url.trim()
  if (!url) {
    return undefined
  }

  const responseStatus =
    typeof item.responseStatus === 'number' && Number.isFinite(item.responseStatus) && item.responseStatus > 0
      ? Math.trunc(item.responseStatus)
      : undefined
  const serverHeader = typeof item.serverHeader === 'string' ? item.serverHeader.trim() : ''

  return {
    url,
    responseStatus,
    serverHeader: serverHeader || undefined,
  }
}

export function buildRedirectChainWithFinal(
  redirectChain: RedirectChainItem[] | undefined,
  finalUrl?: string,
  finalStatus?: number,
  finalServerHeader?: string
): RedirectChainEntry[] {
  const steps: RedirectChainEntry[] = []

  for (const item of redirectChain ?? []) {
    const normalized = normalizeRedirectChainItem(item)
    if (normalized) {
      steps.push(normalized)
    }
  }

  if (finalUrl) {
    const responseStatus =
      typeof finalStatus === 'number' && Number.isFinite(finalStatus) && finalStatus > 0 ? Math.trunc(finalStatus) : undefined
    const serverHeader = typeof finalServerHeader === 'string' ? finalServerHeader.trim() : ''
    steps.push({
      url: finalUrl,
      responseStatus,
      serverHeader: serverHeader || undefined,
    })
  }

  return steps
}

function normalizeComparableUrl(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }

  try {
    const parsed = new URL(trimmed)
    const pathname = parsed.pathname.replace(/\/$/, '') || '/'
    return `${parsed.protocol}//${parsed.host}${pathname}${parsed.search}`.toLowerCase()
  } catch {
    return trimmed.replace(/\/$/, '').toLowerCase()
  }
}

export function isImplicitlyRedirectedResponse(requestUrl: string, responseUrl?: string): boolean {
  if (!responseUrl) {
    return false
  }

  const request = normalizeComparableUrl(requestUrl)
  const effective = normalizeComparableUrl(responseUrl)
  if (!request || !effective) {
    return false
  }

  return request !== effective
}

export function shouldContinueToHttpsCounterpart(
  currentUrl: string,
  redirectChain: RedirectChainItem[] | undefined,
  responseStatus?: number
): boolean {
  if (!currentUrl.toLowerCase().startsWith('http://')) {
    return false
  }

  if ((redirectChain?.length ?? 0) === 0) {
    return false
  }

  return typeof responseStatus === 'number' && responseStatus >= 200 && responseStatus < 300
}

export function shouldFetchWhoisOnExpand(isExpanding: boolean, hasWhois: boolean, isWhoisLoading: boolean): boolean {
  if (!isExpanding) {
    return false
  }

  if (hasWhois) {
    return false
  }

  return !isWhoisLoading
}

export function classifyProbeStatus(
  domain: string,
  finalUrl?: string,
  redirectChain?: RedirectChainItem[],
  serverHeader?: string,
  contentType?: string
): ProbeStatus {
  if (!finalUrl) return 'unreachable'

  if ((redirectChain?.length ?? 0) > 0) {
    return 'redirected'
  }

  const parkedSignals = [finalUrl, serverHeader, contentType]
    .filter((value): value is string => Boolean(value))
    .join(' ')
    .toLowerCase()

  if (/(sedoparking|parkingcrew|bodis|afternic|dan\.com|undeveloped)/.test(parkedSignals)) {
    return 'parked'
  }

  try {
    const finalHost = new URL(finalUrl).hostname.toLowerCase()
    if (finalHost !== domain && finalHost !== `www.${domain}`) {
      return 'redirected'
    }
  } catch {
    return 'unreachable'
  }

  return 'ok'
}

export function extractFramesetUrl(finalUrl?: string, contentType?: string, bodyText?: string): string | undefined {
  if (!finalUrl || !bodyText) {
    return undefined
  }

  const lowerBody = bodyText.toLowerCase()
  const isHtml = !contentType || contentType.toLowerCase().includes('text/html')
  if (!isHtml && !lowerBody.includes('<frameset')) {
    return undefined
  }

  if (!lowerBody.includes('<frameset')) {
    return undefined
  }

  const frameTagMatch = bodyText.match(/<frame\b[^>]*>/i)
  if (!frameTagMatch) {
    return undefined
  }

  const srcMatch = frameTagMatch[0].match(/\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/i)
  const src = srcMatch?.[1] || srcMatch?.[2] || srcMatch?.[3]
  if (!src) {
    return undefined
  }

  try {
    return new URL(src, finalUrl).toString()
  } catch {
    return undefined
  }
}

export function getPrimaryWhoisStatus(whois?: WhoisResult): string {
  return whois?.statuses?.[0] || ''
}

export function getWhoisStatusFamily(status: string): WhoisStatusFamily {
  const normalized = normalizeWhoisStatusValue(status)
  if (normalized in ICANN_EPP_STATUS_DEFINITIONS_NORMALIZED) return 'ICANN EPP'
  if (normalized in DENIC_STATUS_DEFINITIONS_NORMALIZED) return 'DENIC'
  return 'Unknown'
}

export function getWhoisStatusDefinition(status: string): string | undefined {
  const normalized = normalizeWhoisStatusValue(status)
  return ICANN_EPP_STATUS_DEFINITIONS_NORMALIZED[normalized] || DENIC_STATUS_DEFINITIONS_NORMALIZED[normalized]
}

export function getNameServerSld(nameServer?: string): string {
  if (!nameServer) return ''
  const parts = nameServer.split('.').filter(Boolean)
  return parts.slice(-2).join('.')
}

function normalizeParkedPatternNsSld(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const normalized = value.trim().toLowerCase().replace(/\.+$/, '')
  return normalized || undefined
}

export function normalizeParkedPatterns(value: unknown): ParkedPattern[] {
  if (!Array.isArray(value)) {
    return []
  }

  const patterns: ParkedPattern[] = []
  for (const item of value) {
    if (!item || typeof item !== 'object') {
      continue
    }

    const candidate = item as Record<string, unknown>
    const responseRegex = typeof candidate.responseRegex === 'string' ? candidate.responseRegex.trim() : ''
    if (!responseRegex) {
      continue
    }

    patterns.push({
      nsSld: normalizeParkedPatternNsSld(candidate.nsSld),
      responseRegex,
    })
  }
  return patterns
}

export function getDefaultParkedPatterns(): ParkedPattern[] {
  return DEFAULT_PARKED_PATTERNS.map((pattern) => ({ ...pattern }))
}

export function matchesConfiguredParkedPatterns(
  patterns: ParkedPattern[] | undefined,
  dnsNameServers: string[] | undefined,
  responseBody: string | undefined
): boolean {
  if (!patterns?.length || !responseBody) {
    return false
  }

  const nsSlds = new Set<string>()
  for (const nameServer of dnsNameServers ?? []) {
    const fullSld = getNameServerSld(nameServer)
    if (!fullSld) continue
    nsSlds.add(fullSld)

    const label = fullSld.split('.', 1)[0]
    if (label) {
      nsSlds.add(label)
    }
  }

  for (const pattern of patterns) {
    if (pattern.nsSld && !nsSlds.has(pattern.nsSld)) {
      continue
    }

    try {
      const regex = new RegExp(pattern.responseRegex, 'i')
      if (regex.test(responseBody)) {
        return true
      }
    } catch {
      continue
    }
  }

  return false
}

export function normalizeProbeBatchConcurrency(value: unknown): number {
  const candidate =
    typeof value === 'number'
      ? value
      : typeof value === 'string'
        ? value.trim() === ''
          ? Number.NaN
          : Number(value.trim())
        : Number.NaN

  if (!Number.isFinite(candidate)) {
    return PROBE_BATCH_CONCURRENCY_FALLBACK
  }

  const intValue = Math.trunc(candidate)
  if (intValue < PROBE_BATCH_CONCURRENCY_MIN) {
    return PROBE_BATCH_CONCURRENCY_MIN
  }
  if (intValue > PROBE_BATCH_CONCURRENCY_MAX) {
    return PROBE_BATCH_CONCURRENCY_MAX
  }

  return intValue
}

export const PROBE_BATCH_CONCURRENCY_DEFAULT = normalizeProbeBatchConcurrency(PROBE_BATCH_CONCURRENCY_ENV_VALUE)

export function normalizeProbeMaxAttempts(value: unknown): number {
  const candidate =
    typeof value === 'number'
      ? value
      : typeof value === 'string'
        ? value.trim() === ''
          ? Number.NaN
          : Number(value.trim())
        : Number.NaN

  if (!Number.isFinite(candidate)) {
    return PROBE_MAX_ATTEMPTS_FALLBACK
  }

  const intValue = Math.trunc(candidate)
  if (intValue < PROBE_MAX_ATTEMPTS_MIN) {
    return PROBE_MAX_ATTEMPTS_MIN
  }
  if (intValue > PROBE_MAX_ATTEMPTS_MAX) {
    return PROBE_MAX_ATTEMPTS_MAX
  }

  return intValue
}

export const PROBE_MAX_ATTEMPTS_DEFAULT = normalizeProbeMaxAttempts(PROBE_MAX_ATTEMPTS_ENV_VALUE)

export function getResponseBadgeHttpStatus(status: ProbeStatus, httpStatus?: number): number | undefined {
  if (!httpStatus || httpStatus <= 0) {
    return undefined
  }

  // Redirect targets can legitimately vary by probe vantage point; keep the badge stable.
  if (status === 'redirected') {
    return undefined
  }

  return httpStatus
}

export function formatProbeProgress(completed: number, total: number): string {
  const normalizedTotal = Math.max(0, Math.trunc(total))
  const normalizedCompleted = Math.min(Math.max(0, Math.trunc(completed)), normalizedTotal)
  return `${normalizedCompleted} von ${normalizedTotal}`
}

export function createProbeFailureResult(input: ProbeDomainInput, error: string): ProbeResult {
  return {
    domainId: input.id,
    domain: input.domain,
    status: 'unreachable',
    redirectChain: [],
    ipAddresses: [],
    dnsNameServers: [],
    error,
    errorKind: 'probe-failed',
    dnsMs: 0,
    httpMs: 0,
    whoisMs: 0,
    probeMs: 0,
  }
}

export function calculateWhoisSharePercent(probeMs: number, whoisMs: number): number {
  const total = Math.max(0, Math.trunc(probeMs))
  const whois = Math.max(0, Math.trunc(whoisMs))
  if (total === 0) {
    return 0
  }

  const ratio = Math.min(1, whois / total)
  return Math.round(ratio * 100)
}

export function isExplicitRequestTimeoutError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false
  }

  const candidate = error as { name?: unknown }
  return candidate.name === 'TimeoutError'
}

export type TargetStatusFilter = 'all' | 'none' | '2xx' | '3xx' | '4xx' | '5xx'

export function matchesTargetStatusFilter(statusCode: number | undefined, filter: TargetStatusFilter): boolean {
  if (filter === 'all') {
    return true
  }

  const code = typeof statusCode === 'number' ? statusCode : 0
  if (filter === 'none') {
    return code <= 0
  }

  if (filter === '2xx') {
    return code >= 200 && code < 300
  }

  if (filter === '3xx') {
    return code >= 300 && code < 400
  }

  if (filter === '4xx') {
    return code >= 400 && code < 500
  }

  if (filter === '5xx') {
    return code >= 500 && code < 600
  }

  return true
}

export function matchesDomainTargetSearchFilter(domain: string, target: string, query: string): boolean {
  const normalizedQuery = query.trim().toLowerCase()
  if (!normalizedQuery) {
    return true
  }

  const haystack = [domain, target].join(' ').toLowerCase()
  return haystack.includes(normalizedQuery)
}
