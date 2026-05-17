'use client'

import { Fragment, useEffect, useMemo, useRef, useState } from 'react'

import {
  createProbeFailureResult,
  formatProbeProgress,
  getPrimaryWhoisStatus,
  normalizeParkedPatterns,
  normalizeDomain,
  normalizeProbeBatchConcurrency,
  PROBE_BATCH_CONCURRENCY_MAX,
  PROBE_BATCH_CONCURRENCY_MIN,
  normalizeProbeMaxAttempts,
  PROBE_BATCH_CONCURRENCY_DEFAULT,
  PROBE_MAX_ATTEMPTS_MAX,
  PROBE_MAX_ATTEMPTS_MIN,
  PROBE_MAX_ATTEMPTS_DEFAULT,
  getWhoisStatusDefinition,
  getWhoisStatusFamily,
} from '@/lib/probe'
import type { ParkedPattern, ProbeDomainInput, ProbeResult, ProbeStatus, SortDirection, SortKey } from '@/lib/probe'
import {
  APP_NAME,
  APP_VERSION_WITH_GIT,
  LOCAL_LIST_STORAGE_KEY,
  LOCAL_SETTINGS_STORAGE_KEY,
  SETTINGS_OPEN_EVENT,
} from '@/lib/app-config'
import { ExternalLink } from '@/components/ExternalLink'

type WhoisStatusFamily = 'ICANN EPP' | 'DENIC' | 'Unknown'

interface DomainItem {
  id: string
  domain: string
  displayDomain?: string
  addedAt: string
}

interface ParsedDomainEntry {
  canonicalDomain: string
  displayDomain: string
}

interface DomainListResponse {
  domains: DomainItem[]
  createdAt: string
  updatedAt: string
}

interface ProbeSettings {
  batchConcurrency: number
  maxAttempts: number
  parkedPatterns: ParkedPattern[]
}

interface TableRow {
  id: string
  domain: string
  probeDomain: string
  probe?: ProbeResult
  target: string
  framesetUrl: string
  displayTarget: string
  displayTargetHttpStatus: number
  whoisStatus: string
  whoisStatusInfo: { family: WhoisStatusFamily; definition: string }
  nsSldList: string[]
  nsSld: string
  status: ProbeStatus | 'unprobed'
  code: number
}

const STATUS_CONFIG: Record<ProbeStatus, { label: string; badge: string; dot: string }> = {
  ok: {
    label: 'OK',
    badge: 'bg-emerald-100 text-emerald-800 ring-emerald-200 hover:bg-emerald-200',
    dot: 'bg-emerald-500',
  },
  redirected: {
    label: 'Redirected',
    badge: 'bg-blue-100 text-blue-800 ring-blue-200 hover:bg-blue-200',
    dot: 'bg-blue-500',
  },
  parked: {
    label: 'Parked',
    badge: 'bg-orange-100 text-orange-800 ring-orange-200 hover:bg-orange-200',
    dot: 'bg-orange-500',
  },
  frameset: {
    label: 'Frameset',
    badge: 'bg-violet-100 text-violet-800 ring-violet-200 hover:bg-violet-200',
    dot: 'bg-violet-500',
  },
  unreachable: {
    label: 'Unreachable',
    badge: 'bg-rose-100 text-rose-800 ring-rose-200 hover:bg-rose-200',
    dot: 'bg-rose-500',
  },
  'no-dns': {
    label: 'No DNS',
    badge: 'bg-slate-100 text-slate-600 ring-slate-200 hover:bg-slate-200',
    dot: 'bg-slate-400',
  },
  timeout: {
    label: 'Timeout',
    badge: 'bg-yellow-100 text-yellow-800 ring-yellow-200 hover:bg-yellow-200',
    dot: 'bg-yellow-500',
  },
}

function normalizeDisplayDomain(domain: string): string {
  const trimmed = domain.trim().toLowerCase()
  if (!trimmed) return ''

  const base = trimmed
    .replace(/^[^@]*@/, '')
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    .split(/[/?#]/, 1)[0]
    .replace(/:\d+$/, '')

  return base.replace(/\.+$/, '')
}

function splitDomainInput(input: string): ParsedDomainEntry[] {
  return input
    .split(/[\s,;]+/)
    .map((value) => {
      const displayDomain = normalizeDisplayDomain(value)
      const canonicalDomain = normalizeDomain(displayDomain)
      return { displayDomain, canonicalDomain }
    })
    .filter((entry) => Boolean(entry.displayDomain) && Boolean(entry.canonicalDomain))
}

function createEmptyList(): DomainListResponse {
  const now = new Date().toISOString()
  return {
    domains: [],
    createdAt: now,
    updatedAt: now,
  }
}

function createDefaultSettings(): ProbeSettings {
  return {
    batchConcurrency: PROBE_BATCH_CONCURRENCY_DEFAULT,
    maxAttempts: PROBE_MAX_ATTEMPTS_DEFAULT,
    parkedPatterns: [],
  }
}

function loadLocalList(): DomainListResponse {
  try {
    const raw = localStorage.getItem(LOCAL_LIST_STORAGE_KEY)
    if (!raw) return createEmptyList()
    const parsed = JSON.parse(raw) as DomainListResponse
    if (!Array.isArray(parsed.domains)) return createEmptyList()
    return {
      domains: parsed.domains,
      createdAt: parsed.createdAt || new Date().toISOString(),
      updatedAt: parsed.updatedAt || new Date().toISOString(),
    }
  } catch {
    return createEmptyList()
  }
}

function saveLocalList(nextList: DomainListResponse) {
  localStorage.setItem(LOCAL_LIST_STORAGE_KEY, JSON.stringify(nextList))
}

function loadLocalSettings(): ProbeSettings {
  try {
    const raw = localStorage.getItem(LOCAL_SETTINGS_STORAGE_KEY)
    if (!raw) return createDefaultSettings()

    const parsed = JSON.parse(raw) as {
      batchConcurrency?: unknown
      maxAttempts?: unknown
      parkedPatterns?: unknown
    }

    return {
      batchConcurrency: normalizeProbeBatchConcurrency(parsed?.batchConcurrency),
      maxAttempts: normalizeProbeMaxAttempts(parsed?.maxAttempts),
      parkedPatterns: normalizeParkedPatterns(parsed?.parkedPatterns),
    }
  } catch {
    return createDefaultSettings()
  }
}

function saveLocalSettings(nextSettings: ProbeSettings) {
  localStorage.setItem(LOCAL_SETTINGS_STORAGE_KEY, JSON.stringify(nextSettings))
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '...' : s
}

function toCsvCell(value: string): string {
  const normalized = value.replace(/\r?\n/g, ' ')
  if (/[,"\n]/.test(normalized)) {
    return `"${normalized.replace(/"/g, '""')}"`
  }
  return normalized
}

function validateIntegerRange(value: number, min: number, max: number): string | undefined {
  if (!Number.isFinite(value)) {
    return `Please enter a number between ${min} and ${max}.`
  }

  if (!Number.isInteger(value)) {
    return 'Please enter a whole number.'
  }

  if (value < min || value > max) {
    return `Allowed range is ${min} to ${max}.`
  }

  return undefined
}

function toSecondLevelDomain(hostname: string): string {
  const labels = hostname
    .toLowerCase()
    .replace(/\.$/, '')
    .split('.')
    .filter(Boolean)

  if (labels.length < 2) {
    return ''
  }

  const knownSecondLevel = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu'])
  const tld = labels[labels.length - 1]
  const second = labels[labels.length - 2]
  const looksLikeCountryMultiLevel = tld.length === 2 && labels.length >= 3 && knownSecondLevel.has(second)

  if (looksLikeCountryMultiLevel) {
    return labels[labels.length - 3]
  }

  return second
}

function getUniqueNameServerSlds(result?: ProbeResult): string[] {
  const source = result?.dnsNameServers?.length
    ? result.dnsNameServers
    : result?.whois?.nameServers ?? []

  const slds = source
    .map((ns) => toSecondLevelDomain(ns))
    .filter(Boolean)

  return Array.from(new Set(slds))
}

function getWhoisStatusInfo(status: string): { family: WhoisStatusFamily; definition: string } {
  const family = getWhoisStatusFamily(status)
  const definition = getWhoisStatusDefinition(status)
  return {
    family,
    definition:
      definition ||
      (status
        ? 'Status not mapped to known ICANN EPP or DENIC definitions yet.'
        : 'No WHOIS status value available for this domain.'),
  }
}

function ProbeBadge({
  result,
  expanded,
  onToggle,
}: {
  result: ProbeResult
  expanded: boolean
  onToggle: () => void
}) {
  const cfg = STATUS_CONFIG[result.status]
  return (
    <button
      type="button"
      onClick={onToggle}
      title="Toggle probe details"
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-sm font-semibold ring-1 transition cursor-pointer ${cfg.badge}`}
    >
      <span className={`inline-block h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
      {result.httpStatus ? <span className="opacity-60">- {result.httpStatus}</span> : null}
      <span className="opacity-50">{expanded ? '▴' : '▾'}</span>
    </button>
  )
}

function UrlStatusPill({ code }: { code?: number }) {
  if (!code || code <= 0) {
    return null
  }

  const badgeClass = (() => {
    if (code >= 200 && code < 300) {
      return STATUS_CONFIG.ok.badge
    }

    if (code >= 300 && code < 400) {
      return STATUS_CONFIG.redirected.badge
    }

    if (code >= 400 && code < 500) {
      return STATUS_CONFIG.unreachable.badge
    }

    if (code >= 500 && code < 600) {
      return STATUS_CONFIG.timeout.badge
    }

    return STATUS_CONFIG.unreachable.badge
  })()

  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-sm font-semibold ring-1 ${badgeClass}`}>
      {code}
    </span>
  )
}

function InfoHint({ text }: { text: string }) {
  return (
    <span
      className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-200 bg-slate-100 text-[11px] font-semibold text-slate-600"
      title={text}
      aria-label={text}
    >
      i
    </span>
  )
}

function WhoisStatusChip({
  status,
  family,
  definition,
}: {
  status: string
  family: WhoisStatusFamily
  definition: string
}) {
  const buttonRef = useRef<HTMLButtonElement | null>(null)
  const [isTooltipOpen, setIsTooltipOpen] = useState(false)
  const [tooltipPosition, setTooltipPosition] = useState<{ top: number; left: number } | null>(null)

  function updateTooltipPosition() {
    const button = buttonRef.current
    if (!button || typeof window === 'undefined') {
      return
    }

    const rect = button.getBoundingClientRect()
    const tooltipWidth = Math.min(320, window.innerWidth - 16)
    const left = Math.min(Math.max(8, rect.left), window.innerWidth - tooltipWidth - 8)
    const top = rect.bottom + 8

    setTooltipPosition({ top, left })
  }

  function openTooltip() {
    updateTooltipPosition()
    setIsTooltipOpen(true)
  }

  function closeTooltip() {
    setIsTooltipOpen(false)
  }

  useEffect(() => {
    if (!isTooltipOpen) {
      return
    }

    const handleViewportChange = () => updateTooltipPosition()
    window.addEventListener('scroll', handleViewportChange, true)
    window.addEventListener('resize', handleViewportChange)

    return () => {
      window.removeEventListener('scroll', handleViewportChange, true)
      window.removeEventListener('resize', handleViewportChange)
    }
  }, [isTooltipOpen])

  return (
    <span className="relative inline-flex items-center">
      <button
        ref={buttonRef}
        type="button"
        onMouseEnter={openTooltip}
        onMouseLeave={closeTooltip}
        onFocus={openTooltip}
        onBlur={closeTooltip}
        className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-sm font-medium text-slate-700 ring-1 ring-slate-200 transition hover:bg-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"
        aria-label={`WHOIS status ${status}. ${family}. ${definition}`}
        aria-describedby={isTooltipOpen ? `whois-tooltip-${status}` : undefined}
      >
        {status}
      </button>
      {isTooltipOpen && tooltipPosition && (
        <span
          id={`whois-tooltip-${status}`}
          role="tooltip"
          className="pointer-events-none fixed z-[200] rounded-lg border border-slate-300 bg-white px-3 py-2 text-left text-xs leading-5 text-slate-700 shadow-lg"
          style={{
            top: tooltipPosition.top,
            left: tooltipPosition.left,
            width: 'min(20rem, calc(100vw - 1rem))',
          }}
        >
          <span className="block font-semibold text-slate-900">{family}</span>
          <span className="mt-1 block">{definition}</span>
        </span>
      )}
    </span>
  )
}

function ProbeDetails({
  result,
  onReprobe,
  reprobing,
}: {
  result: ProbeResult
  onReprobe: () => void
  reprobing: boolean
}) {
  const redirectFull = [...(result.redirectChain ?? []), result.finalUrl ?? ''].filter(Boolean)
  const hasWhois = Boolean(
    result.whois?.registrar ||
      result.whois?.createdAt ||
      result.whois?.updatedAt ||
      result.whois?.expiresAt ||
      result.whois?.abuseEmail ||
      result.whois?.server ||
      (result.whois?.nameServers?.length ?? 0) > 0 ||
      (result.whois?.statuses?.length ?? 0) > 0 ||
      result.whois?.rawText ||
      result.whois?.error
  )

  return (
    <div className="mx-5 mb-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-700 space-y-2">
      <div className="flex items-center justify-end">
        <button
          type="button"
          onClick={onReprobe}
          disabled={reprobing}
          className="rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {reprobing ? 'Re-probing...' : 'Re-Probe'}
        </button>
      </div>

      <div className="flex flex-wrap gap-x-6 gap-y-1">
        {result.httpStatus !== undefined && result.httpStatus > 0 && (
          <span>
            <span className="text-slate-400">HTTP </span>
            {result.httpStatus}
          </span>
        )}
        <span>
          <span className="text-slate-400">Time </span>
          {result.probeMs} ms
        </span>
        {result.serverHeader && (
          <span>
            <span className="text-slate-400">Server </span>
            {result.serverHeader}
          </span>
        )}
        {result.contentType && (
          <span>
            <span className="text-slate-400">Content-Type </span>
            {result.contentType.split(';')[0]}
          </span>
        )}
      </div>

      {(result.ipAddresses?.length ?? 0) > 0 && (
        <div>
          <span className="text-slate-400">IP </span>
          {result.ipAddresses?.join(', ')}
          {result.cname && (
            <>
              <span className="text-slate-400"> | CNAME </span>
              {result.cname}
            </>
          )}
        </div>
      )}

      {(result.dnsNameServers?.length ?? 0) > 0 && (
        <div>
          <p className="mb-1 text-slate-400">DNS NS</p>
          <div className="flex flex-wrap gap-1.5">
            {result.dnsNameServers?.map((nameServer) => (
              <span
                key={nameServer}
                className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700 ring-1 ring-slate-200"
              >
                {nameServer}
              </span>
            ))}
          </div>
        </div>
      )}

      {result.dnsError && (
        <div className="text-rose-600">
          <span className="text-slate-400">DNS error: </span>
          {result.dnsError}
        </div>
      )}
      {result.error && (
        <div className="text-rose-600">
          <span className="text-slate-400">Error: </span>
          {truncate(result.error, 120)}
        </div>
      )}

      {hasWhois && (
        <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
          <p className="mb-1 text-slate-400">WHOIS</p>
          <div className="flex flex-wrap gap-x-6 gap-y-1">
            {result.whois?.registrar && (
              <span>
                <span className="text-slate-400">Registrar </span>
                {result.whois.registrar}
              </span>
            )}
            {result.whois?.createdAt && (
              <span>
                <span className="text-slate-400">Created </span>
                {result.whois.createdAt}
              </span>
            )}
            {result.whois?.updatedAt && (
              <span>
                <span className="text-slate-400">Updated </span>
                {result.whois.updatedAt}
              </span>
            )}
            {result.whois?.expiresAt && (
              <span>
                <span className="text-slate-400">Expires </span>
                {result.whois.expiresAt}
              </span>
            )}
            {result.whois?.abuseEmail && (
              <span>
                <span className="text-slate-400">Abuse </span>
                {result.whois.abuseEmail}
              </span>
            )}
            {result.whois?.server && (
              <span>
                <span className="text-slate-400">Server </span>
                {result.whois.server}
              </span>
            )}
          </div>

          {(result.whois?.nameServers?.length ?? 0) > 0 && (
            <div className="mt-2">
              <p className="mb-1 text-slate-400">NS</p>
              <div className="flex flex-wrap gap-1.5">
                {result.whois?.nameServers?.map((nameServer) => (
                  <span
                    key={nameServer}
                    className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700 ring-1 ring-slate-200"
                  >
                    {nameServer}
                  </span>
                ))}
              </div>
            </div>
          )}

          {(result.whois?.statuses?.length ?? 0) > 0 && (
            <div className="mt-2">
              <p className="mb-1 text-slate-400">Status</p>
              <div className="space-y-1.5">
                {result.whois?.statuses?.map((status, index) => {
                  const info = getWhoisStatusInfo(status)
                  return (
                    <div key={`${status}-${index}`} className="flex flex-wrap items-start gap-2">
                      <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-700 ring-1 ring-slate-200">
                        {status}
                      </span>
                      <span className="text-[11px] leading-5 text-slate-600">
                        <span className="font-semibold text-slate-700">{info.family}:</span>{' '}
                        {info.definition}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {result.whois?.error && (
            <div className="mt-1 text-rose-600">
              <span className="text-slate-400">WHOIS error: </span>
              {truncate(result.whois.error, 120)}
            </div>
          )}
          {result.whois?.rawText && (
            <details className="mt-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2" open>
              <summary className="cursor-pointer text-slate-500">WHOIS raw data</summary>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words text-[11px] leading-5 text-slate-700">
                {result.whois.rawText}
              </pre>
            </details>
          )}
        </div>
      )}

      {redirectFull.length > 1 && (
        <div>
          <p className="text-slate-400 mb-1">Redirect chain</p>
          {redirectFull.map((url, i) => (
            <div key={i} className="flex items-start gap-1.5">
              <span className="text-slate-300 mt-px select-none">{i === redirectFull.length - 1 ? '└' : '├'}</span>
              <ExternalLink href={url} className="break-all text-blue-600 hover:underline">
                {truncate(url, 90)}
              </ExternalLink>
            </div>
          ))}
        </div>
      )}

      {result.finalUrl && redirectFull.length <= 1 && (
        <div>
          <span className="text-slate-400">Final URL </span>
          <span className="inline-flex max-w-full items-center gap-2 align-middle">
            <ExternalLink href={result.finalUrl} className="break-all text-blue-600 hover:underline">
              {truncate(result.finalUrl, 90)}
            </ExternalLink>
            <UrlStatusPill code={result.httpStatus} />
          </span>
        </div>
      )}

      {result.framesetUrl && (
        <div>
          <span className="text-slate-400">Frameset URL </span>
          <span className="inline-flex max-w-full items-center gap-2 align-middle">
            <ExternalLink href={result.framesetUrl} className="break-all text-blue-600 hover:underline">
              {truncate(result.framesetUrl, 90)}
            </ExternalLink>
            <UrlStatusPill code={result.framesetHttpStatus} />
          </span>
        </div>
      )}
    </div>
  )
}

function isTauriRuntime(): boolean {
  if (typeof window === 'undefined') return false
  return window.location.protocol === 'tauri:' || Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__)
}

async function runProbeViaTauri(
  domains: ProbeDomainInput[],
  concurrency: number,
  parkedPatterns: ParkedPattern[]
): Promise<ProbeResult[]> {
  if (!isTauriRuntime()) {
    throw new Error('Tauri runtime not available.')
  }

  const { invoke } = await import('@tauri-apps/api/core')

  const payload = await invoke('run_probe_batch', {
    domains,
    concurrency,
    parkedPatterns,
  })
  return Array.isArray(payload) ? (payload as ProbeResult[]) : []
}

async function runProbeViaServer(
  domains: ProbeDomainInput[],
  concurrency: number,
  parkedPatterns: ParkedPattern[]
): Promise<ProbeResult[]> {
  const response = await fetch('/api/probe', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      domains,
      concurrency,
      parkedPatterns,
    }),
  })

  const payload = (await response.json().catch(() => ({}))) as { error?: string; results?: unknown }
  if (!response.ok) {
    throw new Error(payload?.error || 'Probe failed')
  }

  return Array.isArray(payload.results) ? (payload.results as ProbeResult[]) : []
}

export function ListPage() {
  const [list, setList] = useState<DomainListResponse | null>(null)
  const [probeResults, setProbeResults] = useState<Record<string, ProbeResult>>({})
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [singleProbeIds, setSingleProbeIds] = useState<Record<string, true>>({})
  const [probeProgress, setProbeProgress] = useState<{ completed: number; total: number }>({ completed: 0, total: 0 })
  const [clearing, setClearing] = useState(false)
  const [copyFeedback, setCopyFeedback] = useState<string>('')
  const [sortBy, setSortBy] = useState<SortKey>('domain')
  const [sortDir, setSortDir] = useState<SortDirection>('asc')
  const [filterText, setFilterText] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'unprobed' | ProbeStatus>('all')
  const [expandedProbeId, setExpandedProbeId] = useState('')
  const [newDomainsInput, setNewDomainsInput] = useState('')
  const [settings, setSettings] = useState<ProbeSettings>(createDefaultSettings())
  const [settingsDraft, setSettingsDraft] = useState<ProbeSettings>(createDefaultSettings())
  const [settingsOpen, setSettingsOpen] = useState(false)

  const batchConcurrencyError = validateIntegerRange(
    settingsDraft.batchConcurrency,
    PROBE_BATCH_CONCURRENCY_MIN,
    PROBE_BATCH_CONCURRENCY_MAX
  )
  const maxAttemptsError = validateIntegerRange(settingsDraft.maxAttempts, PROBE_MAX_ATTEMPTS_MIN, PROBE_MAX_ATTEMPTS_MAX)
  const settingsHasValidationError = Boolean(batchConcurrencyError || maxAttemptsError)

  function showTransientFeedback(message: string) {
    setCopyFeedback(message)
    setTimeout(() => setCopyFeedback(''), 2500)
  }

  function toggleSort(nextKey: SortKey) {
    if (sortBy === nextKey) {
      setSortDir((current) => (current === 'asc' ? 'desc' : 'asc'))
      return
    }

    setSortBy(nextKey)
    setSortDir('asc')
  }

  function getSortMarker(key: SortKey): string {
    if (sortBy !== key) return ''
    return sortDir === 'asc' ? ' ^' : ' v'
  }

  useEffect(() => {
    fetchList()
  }, [])

  useEffect(() => {
    const handleOpenSettings = () => openSettings()
    window.addEventListener(SETTINGS_OPEN_EVENT, handleOpenSettings)

    return () => {
      window.removeEventListener(SETTINGS_OPEN_EVENT, handleOpenSettings)
    }
  }, [settings])

  async function fetchList() {
    try {
      setList(loadLocalList())
      setSettings(loadLocalSettings())
    } catch (error) {
      console.error('Failed to load list:', error)
    } finally {
      setLoading(false)
    }
  }

  async function addDomains() {
    if (!newDomainsInput.trim()) return
    try {
      const domains = splitDomainInput(newDomainsInput)
      if (domains.length === 0) return

      const currentList = loadLocalList()
      const existing = new Set(currentList.domains.map((d) => d.domain))
      const now = new Date().toISOString()

      const nextDomains = [...currentList.domains]
      for (const domain of domains) {
        if (existing.has(domain.canonicalDomain)) continue
        nextDomains.push({
          id: crypto.randomUUID(),
          domain: domain.canonicalDomain,
          displayDomain: domain.displayDomain,
          addedAt: now,
        })
        existing.add(domain.canonicalDomain)
      }

      const nextList: DomainListResponse = {
        ...currentList,
        domains: nextDomains,
        updatedAt: now,
      }
      saveLocalList(nextList)
      setList(nextList)
      setNewDomainsInput('')
    } catch (error) {
      console.error('Failed to add domains:', error)
    }
  }

  async function updateDomain(domainId: string, newDisplayDomain: string) {
    const nextDomain = normalizeDomain(newDisplayDomain)
    if (!nextDomain) return

    try {
      const currentList = loadLocalList()
      const now = new Date().toISOString()
      const nextDomains = currentList.domains.map((domain) =>
        domain.id === domainId ? { ...domain, domain: nextDomain, displayDomain: newDisplayDomain } : domain
      )
      const nextList: DomainListResponse = {
        ...currentList,
        domains: nextDomains,
        updatedAt: now,
      }
      saveLocalList(nextList)
      setList(nextList)
    } catch (error) {
      console.error('Failed to update domain:', error)
    }
  }

  async function deleteDomain(domainId: string) {
    if (!confirm('Delete this domain?')) return
    try {
      const currentList = loadLocalList()
      const now = new Date().toISOString()
      const nextList: DomainListResponse = {
        ...currentList,
        domains: currentList.domains.filter((domain) => domain.id !== domainId),
        updatedAt: now,
      }
      saveLocalList(nextList)
      setList(nextList)
    } catch (error) {
      console.error('Failed to delete domain:', error)
    }
  }

  async function editDomain(domainId: string, currentDomain: string) {
    const next = prompt('Edit domain', currentDomain)
    if (!next) return

    const normalizedDisplayDomain = normalizeDisplayDomain(next)
    if (!normalizedDisplayDomain || normalizedDisplayDomain === currentDomain) return

    await updateDomain(domainId, normalizedDisplayDomain)
    setProbeResults((prev) => {
      if (!(domainId in prev)) return prev
      const nextResults = { ...prev }
      delete nextResults[domainId]
      return nextResults
    })
  }

  async function probeAll() {
    if (!list || list.domains.length === 0) return

    setProbing(true)
    setExpandedProbeId('')
    setSingleProbeIds({})
    try {
      const probeInput: ProbeDomainInput[] = list.domains.map(({ id, domain }) => ({ id, domain }))
      const batchConcurrency = normalizeProbeBatchConcurrency(settings.batchConcurrency)
      const maxAttempts = normalizeProbeMaxAttempts(settings.maxAttempts)
      const parkedPatterns = normalizeParkedPatterns(settings.parkedPatterns)
      const total = probeInput.length
      let completed = 0
      const allResults: ProbeResult[] = []

      setProbeProgress({ completed: 0, total })
      setProbeResults({})

      const runBatch = async (domains: ProbeDomainInput[]): Promise<ProbeResult[]> => {
        if (isTauriRuntime()) {
          return runProbeViaTauri(domains, batchConcurrency, parkedPatterns)
        }
        return runProbeViaServer(domains, batchConcurrency, parkedPatterns)
      }

      const runSingleProbeWithRetries = async (domainInput: ProbeDomainInput): Promise<ProbeResult> => {
        let lastError = 'Probe failed.'

        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          try {
            const singleResult = await runBatch([domainInput])
            const single = singleResult.find((result) => result.domainId === domainInput.id)
            if (single) {
              return single
            }
            lastError = 'Probe returned no result for domain.'
          } catch (error) {
            lastError = error instanceof Error ? error.message : 'Probe failed.'
          }
        }

        return createProbeFailureResult(domainInput, `${lastError} (after ${maxAttempts} attempts)`)
      }

      for (let index = 0; index < probeInput.length; index += batchConcurrency) {
        const chunk = probeInput.slice(index, index + batchConcurrency)
        let chunkResults: ProbeResult[] = []

        try {
          chunkResults = await runBatch(chunk)
        } catch (chunkError) {
          console.error('Chunk probe failed, retrying per-domain:', chunkError)
        }

        const byDomainId = new Map(chunkResults.map((result) => [result.domainId, result]))
        const normalizedChunkResults: ProbeResult[] = []
        for (const domainInput of chunk) {
          const existing = byDomainId.get(domainInput.id)
          if (existing) {
            normalizedChunkResults.push(existing)
            continue
          }
          normalizedChunkResults.push(await runSingleProbeWithRetries(domainInput))
        }

        completed += chunk.length
        allResults.push(...normalizedChunkResults)

        setProbeResults((prev) => ({
          ...prev,
          ...Object.fromEntries(normalizedChunkResults.map((result) => [result.domainId, result])),
        }))
        setProbeProgress({ completed, total })
      }

      showTransientFeedback(`Probed ${allResults.length} domain${allResults.length === 1 ? '' : 's'}.`)
    } catch (error) {
      console.error('Failed to probe domains:', error)
      showTransientFeedback(error instanceof Error ? error.message : 'Probe failed.')
    } finally {
      setProbing(false)
      setProbeProgress({ completed: 0, total: 0 })
    }
  }

  async function probeSingleDomain(domainInput: ProbeDomainInput) {
    if (probing || singleProbeIds[domainInput.id]) {
      return
    }

    setSingleProbeIds((prev) => ({ ...prev, [domainInput.id]: true }))
    try {
      const batchConcurrency = normalizeProbeBatchConcurrency(settings.batchConcurrency)
      const maxAttempts = normalizeProbeMaxAttempts(settings.maxAttempts)
      const parkedPatterns = normalizeParkedPatterns(settings.parkedPatterns)
      let result: ProbeResult | null = null
      let lastError = 'Probe failed.'

      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        try {
          const singleResult = isTauriRuntime()
            ? await runProbeViaTauri([domainInput], batchConcurrency, parkedPatterns)
            : await runProbeViaServer([domainInput], batchConcurrency, parkedPatterns)
          const found = singleResult.find((entry) => entry.domainId === domainInput.id)
          if (found) {
            result = found
            break
          }
          lastError = 'Probe returned no result for domain.'
        } catch (error) {
          lastError = error instanceof Error ? error.message : 'Probe failed.'
        }
      }

      const finalResult = result ?? createProbeFailureResult(domainInput, `${lastError} (after ${maxAttempts} attempts)`)

      setProbeResults((prev) => ({
        ...prev,
        [domainInput.id]: finalResult,
      }))
    } finally {
      setSingleProbeIds((prev) => {
        const next = { ...prev }
        delete next[domainInput.id]
        return next
      })
    }
  }

  async function clearAllDomains() {
    if (!list || list.domains.length === 0) return
    if (!confirm(`Clear all ${list.domains.length} domains from the list?`)) return

    setClearing(true)
    try {
      const now = new Date().toISOString()
      const emptyList: DomainListResponse = {
        domains: [],
        createdAt: list.createdAt,
        updatedAt: now,
      }
      saveLocalList(emptyList)
      setList(emptyList)
      setProbeResults({})
      setSingleProbeIds({})
      setExpandedProbeId('')
    } catch (error) {
      console.error('Failed to clear domains:', error)
    } finally {
      setClearing(false)
    }
  }

  function buildCsv(): string {
    if (!list) return ''
    const generatedAt = new Date().toISOString()
    const metadataRow = [
      toCsvCell(`GeneratedAt=${generatedAt}`),
      toCsvCell(`App=${APP_NAME}`),
      toCsvCell(`Version=${APP_VERSION_WITH_GIT}`),
    ]
    const rows = [['Domain', 'Response', 'Target', 'Frameset URL', 'Status', 'NS SLD']]
    for (const row of tableRows) {
      const response = row.probe
        ? `${STATUS_CONFIG[row.probe.status].label}${row.code > 0 ? ` ${row.code}` : ''}`
        : 'Not probed'

      rows.push([
        toCsvCell(row.domain),
        toCsvCell(response),
        toCsvCell(row.displayTarget),
        toCsvCell(row.framesetUrl),
        toCsvCell(row.whoisStatus),
        toCsvCell(row.nsSld),
      ])
    }
    return [metadataRow, ...rows].map((r) => r.join(',')).join('\n')
  }

  async function copyCSV() {
    const csv = buildCsv()
    if (!csv) return

    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(csv)
        showTransientFeedback('Copied')
        return
      }
    } catch {
      // Fall through to legacy copy path.
    }

    try {
      const textarea = document.createElement('textarea')
      textarea.value = csv
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      textarea.style.left = '-9999px'
      document.body.appendChild(textarea)
      textarea.select()
      const copied = document.execCommand('copy')
      document.body.removeChild(textarea)

      if (copied) {
        showTransientFeedback('Copied')
      } else {
        showTransientFeedback('Copy failed. Use Export CSV instead.')
      }
    } catch {
      showTransientFeedback('Copy failed. Use Export CSV instead.')
    }
  }

  function exportCSV() {
    const csv = buildCsv()
    if (!csv) return
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `domains-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function openSettings() {
    setSettingsDraft({
      batchConcurrency: settings.batchConcurrency,
      maxAttempts: settings.maxAttempts,
      parkedPatterns: settings.parkedPatterns.map((pattern) => ({
        nsSld: pattern.nsSld,
        responseRegex: pattern.responseRegex,
      })),
    })
    setSettingsOpen(true)
  }

  function saveSettings() {
    if (settingsHasValidationError) {
      return
    }

    const normalized: ProbeSettings = {
      batchConcurrency: normalizeProbeBatchConcurrency(settingsDraft.batchConcurrency),
      maxAttempts: normalizeProbeMaxAttempts(settingsDraft.maxAttempts),
      parkedPatterns: normalizeParkedPatterns(settingsDraft.parkedPatterns),
    }

    setSettings(normalized)
    saveLocalSettings(normalized)
    setSettingsOpen(false)
    showTransientFeedback('Settings saved.')
  }

  function addParkedPatternRow() {
    setSettingsDraft((prev) => ({
      ...prev,
      parkedPatterns: [...prev.parkedPatterns, { nsSld: '', responseRegex: '' }],
    }))
  }

  function removeParkedPatternRow(index: number) {
    setSettingsDraft((prev) => ({
      ...prev,
      parkedPatterns: prev.parkedPatterns.filter((_, i) => i !== index),
    }))
  }

  function updateParkedPattern(index: number, key: keyof ParkedPattern, value: string) {
    setSettingsDraft((prev) => ({
      ...prev,
      parkedPatterns: prev.parkedPatterns.map((pattern, i) =>
        i === index
          ? {
              ...pattern,
              [key]: value,
            }
          : pattern
      ),
    }))
  }

  const tableRows = useMemo<TableRow[]>(() => {
    if (!list) return []

    const rows = list.domains.map((domain) => {
      const probe = probeResults[domain.id]
      const target = probe?.finalUrl ?? ''
      const framesetUrl = probe?.framesetUrl ?? ''
      const displayTarget = probe?.status === 'frameset' && framesetUrl ? framesetUrl : target
      const displayTargetHttpStatus = probe?.status === 'frameset' ? (probe?.framesetHttpStatus ?? 0) : (probe?.httpStatus ?? 0)
      const whoisStatus = getPrimaryWhoisStatus(probe?.whois)
      const whoisStatusInfo = getWhoisStatusInfo(whoisStatus)
      const nsSldList = getUniqueNameServerSlds(probe)
      const nsSld = nsSldList.join(', ')
      const status = probe?.status ?? 'unprobed'
      const code = probe?.httpStatus ?? 0

      return {
        id: domain.id,
        domain: domain.displayDomain ?? domain.domain,
        probeDomain: domain.domain,
        probe,
        target,
        framesetUrl,
        displayTarget,
        displayTargetHttpStatus,
        whoisStatus,
        whoisStatusInfo,
        nsSldList,
        nsSld,
        status,
        code,
      }
    })

    const query = filterText.trim().toLowerCase()
    const filteredRows = rows.filter((row) => {
      const matchesStatus = statusFilter === 'all' || row.status === statusFilter
      if (!matchesStatus) {
        return false
      }

      if (!query) {
        return true
      }

      const haystack = [
        row.domain,
        row.target,
        row.framesetUrl,
        row.displayTarget,
        row.whoisStatus,
        row.whoisStatusInfo.family,
        row.nsSld,
        row.status,
      ]
        .join(' ')
        .toLowerCase()
      return haystack.includes(query)
    })

    return [...filteredRows].sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1

      switch (sortBy) {
        case 'domain':
          return dir * a.domain.localeCompare(b.domain)
        case 'status':
          return dir * a.status.localeCompare(b.status)
        case 'code':
          return dir * (a.code - b.code)
        case 'target':
          return dir * a.displayTarget.localeCompare(b.displayTarget)
        case 'whoisStatus':
          return dir * a.whoisStatus.localeCompare(b.whoisStatus)
        case 'nsSld':
          return dir * a.nsSld.localeCompare(b.nsSld)
        default:
          return 0
      }
    })
  }, [filterText, list, probeResults, sortBy, sortDir, statusFilter])

  if (loading) {
    return <div className="min-h-screen flex items-center justify-center">Loading...</div>
  }

  return (
    <main className="min-h-screen bg-slate-50 p-4 md:p-6">
      <div className="mx-auto max-w-[var(--app-content-max-width)]">
        <div className="mb-6">
          <p className="text-slate-600">Track your domain portfolio. No account needed.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Add domains (comma or space separated)"
                value={newDomainsInput}
                onChange={(e) => setNewDomainsInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') addDomains()
                }}
                className="flex-1 rounded-xl border border-slate-200 px-4 py-2 text-sm text-slate-800 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
              />
              <button
                onClick={addDomains}
                className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-100"
              >
                Add
              </button>
              <button
                onClick={clearAllDomains}
                disabled={clearing || !list || list.domains.length === 0}
                className="rounded-xl bg-red-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-red-700 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-red-100 disabled:cursor-not-allowed disabled:bg-red-300"
              >
                {clearing ? 'Clearing...' : 'Clear'}
              </button>
            </div>
          </div>
          <div className="flex gap-2 justify-end">
            {probing && probeProgress.total > 0 ? (
              <span className="self-center text-sm font-medium text-slate-600">
                {formatProbeProgress(probeProgress.completed, probeProgress.total)}
              </span>
            ) : null}
            <button
              onClick={copyCSV}
              className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-800 transition hover:bg-slate-100 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-slate-100"
            >
              Copy CSV
            </button>
            <button
              onClick={exportCSV}
              className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-800 transition hover:bg-slate-100 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-slate-100"
            >
              Export CSV
            </button>
            <button
              onClick={probeAll}
              disabled={probing}
              className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-100 disabled:cursor-not-allowed disabled:bg-blue-400"
            >
              {probing && probeProgress.total > 0
                ? `Probing... (${formatProbeProgress(probeProgress.completed, probeProgress.total)})`
                : 'Probe All'}
            </button>
          </div>
        </div>

        <div className="overflow-visible rounded-xl border border-slate-200 bg-white">
          <div className="grid gap-3 border-b border-slate-200 bg-slate-50 p-3 md:grid-cols-[1fr,220px]">
            <input
              value={filterText}
              onChange={(event) => setFilterText(event.target.value)}
              placeholder="Filter: domain, target, status, NS SLD"
              className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-800 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
            />
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as 'all' | 'unprobed' | ProbeStatus)}
              className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-800 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
            >
              <option value="all">All statuses</option>
              <option value="unprobed">Not probed</option>
              <option value="ok">OK</option>
              <option value="redirected">Redirected</option>
              <option value="parked">Parked</option>
              <option value="frameset">Frameset</option>
              <option value="unreachable">Unreachable</option>
              <option value="no-dns">No DNS</option>
              <option value="timeout">Timeout</option>
            </select>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full border-collapse text-sm">
              <thead>
                <tr className="bg-slate-50 text-sm font-semibold text-slate-500">
                  <th className="px-4 py-3 text-left">
                    <button type="button" className="hover:text-slate-800" onClick={() => toggleSort('domain')}>
                      Domain {getSortMarker('domain')}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left">
                    <button type="button" className="hover:text-slate-800" onClick={() => toggleSort('status')}>
                      Response {getSortMarker('status')}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left">
                    <button type="button" className="hover:text-slate-800" onClick={() => toggleSort('target')}>
                      Target {getSortMarker('target')}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">
                    <button type="button" className="hover:text-slate-800" onClick={() => toggleSort('whoisStatus')}>
                      Registrar Status {getSortMarker('whoisStatus')}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left">
                    <button type="button" className="hover:text-slate-800" onClick={() => toggleSort('nsSld')}>
                      NS SLD {getSortMarker('nsSld')}
                    </button>
                  </th>
                  <th className="px-4 py-3 text-left">Edit</th>
                  <th className="px-4 py-3 text-left">Delete</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-sm text-slate-500">
                      {list?.domains.length ? 'No domains match the current filter.' : 'No domains yet. Add some to get started.'}
                    </td>
                  </tr>
                ) : (
                  tableRows.map((row) => {
                    const isExpanded = expandedProbeId === row.id

                    return (
                      <Fragment key={row.id}>
                        <tr className="border-t border-slate-100 align-top">
                          <td className="px-4 py-2.5">
                            <ExternalLink
                              href={`http://${row.domain}`}
                              className="block max-w-56 truncate font-medium text-blue-600 hover:underline"
                              title={`http://${row.domain}`}
                            >
                              {row.domain}
                            </ExternalLink>
                          </td>
                          <td className="px-4 py-2.5">
                            {row.probe ? (
                              <ProbeBadge
                                result={row.probe}
                                expanded={isExpanded}
                                onToggle={() => setExpandedProbeId((prev) => (prev === row.id ? '' : row.id))}
                              />
                            ) : (
                              <button
                                type="button"
                                onClick={() => probeSingleDomain({ id: row.id, domain: row.probeDomain })}
                                disabled={probing || Boolean(singleProbeIds[row.id])}
                                className="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-sm font-semibold text-slate-500 ring-1 ring-slate-200 transition hover:bg-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
                                title="Probe this domain"
                              >
                                {singleProbeIds[row.id] ? 'Probing...' : 'Not probed'}
                              </button>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            {row.displayTarget ? (
                              <div className="inline-flex max-w-full items-center gap-2">
                                <ExternalLink
                                  href={row.displayTarget}
                                  className="block max-w-72 truncate text-blue-600 hover:underline"
                                  title={row.displayTarget}
                                >
                                  {row.displayTarget}
                                </ExternalLink>
                              </div>
                            ) : (
                              <span className="text-sm text-slate-400">-</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            {row.probe ? <UrlStatusPill code={row.displayTargetHttpStatus} /> : <span className="text-sm text-slate-400">-</span>}
                          </td>
                          <td className="px-4 py-2.5">
                            {row.whoisStatus ? (
                              <WhoisStatusChip
                                status={row.whoisStatus}
                                family={row.whoisStatusInfo.family}
                                definition={row.whoisStatusInfo.definition}
                              />
                            ) : (
                              <span className="text-sm text-slate-400">-</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            {row.nsSldList.length > 0 ? (
                              <div className="flex max-w-52 flex-wrap gap-1">
                                {row.nsSldList.map((sld) => (
                                  <span
                                    key={`${row.id}-${sld}`}
                                    className="rounded-full bg-slate-100 px-2 py-0.5 text-sm font-medium text-slate-700 ring-1 ring-slate-200"
                                  >
                                    {sld}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-sm text-slate-400">-</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5">
                            <button
                              type="button"
                              onClick={() => editDomain(row.id, row.domain)}
                              className="rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-100 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-slate-100"
                            >
                              Edit
                            </button>
                          </td>
                          <td className="px-4 py-2.5">
                            <button
                              type="button"
                              onClick={() => deleteDomain(row.id)}
                              className="rounded-lg border border-rose-200 bg-white px-2.5 py-1.5 text-sm font-semibold text-rose-700 transition hover:bg-rose-50 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-rose-100"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>

                        {isExpanded && row.probe && (
                          <tr className="border-t border-slate-100">
                            <td colSpan={8} className="px-0 py-0">
                              <ProbeDetails
                                result={row.probe}
                                onReprobe={() => probeSingleDomain({ id: row.id, domain: row.probeDomain })}
                                reprobing={Boolean(singleProbeIds[row.id]) || probing}
                              />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {copyFeedback ? (
          <div className="pointer-events-none fixed bottom-4 right-4 z-50">
            <div className="rounded-full bg-slate-900/90 px-3 py-1.5 text-xs font-medium text-white shadow-lg backdrop-blur">
              {copyFeedback}
            </div>
          </div>
        ) : null}

        {settingsOpen ? (
          <div className="fixed inset-0 z-[120] flex items-center justify-center bg-slate-900/40 p-4">
            <div className="w-full max-w-3xl rounded-xl border border-slate-200 bg-white p-5 shadow-xl">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-slate-900">Settings</h2>
                <button
                  type="button"
                  onClick={() => setSettingsOpen(false)}
                  className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-100"
                >
                  Close
                </button>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <label className="space-y-1">
                  <span className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-700">
                    Probe batch concurrency
                    <InfoHint
                      text={`Default: ${PROBE_BATCH_CONCURRENCY_DEFAULT}. Allowed: ${PROBE_BATCH_CONCURRENCY_MIN}..${PROBE_BATCH_CONCURRENCY_MAX}. Controls how many domains are probed in parallel.`}
                    />
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={settingsDraft.batchConcurrency}
                    onChange={(event) =>
                      setSettingsDraft((prev) => ({
                        ...prev,
                        batchConcurrency: event.target.value === '' ? Number.NaN : Number(event.target.value),
                      }))
                    }
                    className={`w-full rounded-xl px-3 py-2 text-sm text-slate-800 outline-none focus:ring-4 ${
                      batchConcurrencyError
                        ? 'border border-rose-300 focus:border-rose-500 focus:ring-rose-100'
                        : 'border border-slate-200 focus:border-blue-500 focus:ring-blue-100'
                    }`}
                  />
                  {batchConcurrencyError ? (
                    <p className="text-xs text-rose-600">{batchConcurrencyError}</p>
                  ) : null}
                </label>

                <label className="space-y-1">
                  <span className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-700">
                    Probe auto-retry max attempts per domain
                    <InfoHint
                      text={`Default: ${PROBE_MAX_ATTEMPTS_DEFAULT}. Allowed: ${PROBE_MAX_ATTEMPTS_MIN}..${PROBE_MAX_ATTEMPTS_MAX}. Defines retry attempts per domain before marking it failed.`}
                    />
                  </span>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={settingsDraft.maxAttempts}
                    onChange={(event) =>
                      setSettingsDraft((prev) => ({
                        ...prev,
                        maxAttempts: event.target.value === '' ? Number.NaN : Number(event.target.value),
                      }))
                    }
                    className={`w-full rounded-xl px-3 py-2 text-sm text-slate-800 outline-none focus:ring-4 ${
                      maxAttemptsError
                        ? 'border border-rose-300 focus:border-rose-500 focus:ring-rose-100'
                        : 'border border-slate-200 focus:border-blue-500 focus:ring-blue-100'
                    }`}
                  />
                  {maxAttemptsError ? (
                    <p className="text-xs text-rose-600">{maxAttemptsError}</p>
                  ) : null}
                </label>
              </div>

              <div className="mt-5 rounded-xl border border-slate-200">
                <div className="flex items-center justify-between border-b border-slate-200 bg-slate-50 px-3 py-2">
                  <p className="text-sm font-semibold text-slate-700">Parked patterns</p>
                  <button
                    type="button"
                    onClick={addParkedPatternRow}
                    className="rounded-lg border border-slate-200 bg-white px-2.5 py-1 text-sm font-semibold text-slate-700 transition hover:bg-slate-100"
                  >
                    Add pattern
                  </button>
                </div>

                <div className="space-y-3 p-3">
                  {settingsDraft.parkedPatterns.length === 0 ? (
                    <p className="text-sm text-slate-500">No custom patterns yet. Example: NS SLD udag + regex Diese neue Domain wurde im Kundenauftrag registriert</p>
                  ) : (
                    settingsDraft.parkedPatterns.map((pattern, index) => (
                      <div key={`parked-pattern-${index}`} className="grid gap-2 md:grid-cols-[180px,1fr,auto]">
                        <input
                          type="text"
                          placeholder="NS SLD (optional)"
                          value={pattern.nsSld ?? ''}
                          onChange={(event) => updateParkedPattern(index, 'nsSld', event.target.value)}
                          className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-800 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
                        />
                        <input
                          type="text"
                          placeholder="Response regex"
                          value={pattern.responseRegex}
                          onChange={(event) => updateParkedPattern(index, 'responseRegex', event.target.value)}
                          className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-800 outline-none focus:border-blue-500 focus:ring-4 focus:ring-blue-100"
                        />
                        <button
                          type="button"
                          onClick={() => removeParkedPatternRow(index)}
                          className="rounded-lg border border-rose-200 bg-white px-2.5 py-1.5 text-sm font-semibold text-rose-700 transition hover:bg-rose-50"
                        >
                          Remove
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setSettingsOpen(false)}
                  className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition hover:bg-slate-100"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={saveSettings}
                  disabled={settingsHasValidationError}
                  className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-blue-300"
                >
                  Save settings
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </main>
  )
}
