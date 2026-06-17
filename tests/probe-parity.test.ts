import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import test from 'node:test'

import { lookupWhois, runProbeBatch } from '../src/lib/probe-runtime'
import type { ProbeDomainInput, ProbeResult, RedirectChainItem } from '../src/lib/probe'

const PARITY_DOMAINS: ProbeDomainInput[] = [
  { id: 'd1', domain: 'schufa.de' },
  { id: 'd2', domain: 'meineschufa.de' },
  { id: 'd3', domain: 'google.com' },
  { id: 'd4', domain: 'example.com' },
  { id: 'd5', domain: 'xn--alleswassieschonimmerberscoringwissenwollten-bue.de' },
]

function normalizeUrl(url?: string): string {
  if (!url) return ''
  try {
    const parsed = new URL(url)
    const normalizedPath = parsed.pathname.replace(/\/$/, '')
    return `${parsed.protocol}//${parsed.host}${normalizedPath}${parsed.search}`.toLowerCase()
  } catch {
    return url.trim().toLowerCase().replace(/\/$/, '')
  }
}

function getRedirectChainUrl(entry: RedirectChainItem): string {
  return typeof entry === 'string' ? entry : entry.url
}

function normalizeChain(chain?: RedirectChainItem[]): string[] {
  return (chain ?? []).map((entry) => normalizeUrl(getRedirectChainUrl(entry)))
}

function normalizeSet(values?: string[]): string[] {
  return Array.from(new Set((values ?? []).map((entry) => entry.toLowerCase()))).sort((a, b) => a.localeCompare(b))
}

function indexById(results: ProbeResult[]): Map<string, ProbeResult> {
  return new Map(results.map((result) => [result.domainId, result]))
}

async function runRustParityProbe(domains: ProbeDomainInput[]): Promise<ProbeResult[]> {
  const binaryPath = path.join(
    process.cwd(),
    'src-tauri',
    'target',
    'debug',
    process.platform === 'win32' ? 'parity_probe.exe' : 'parity_probe'
  )

  const stdout = execFileSync(binaryPath, [], {
    cwd: process.cwd(),
    maxBuffer: 1024 * 1024 * 8,
    encoding: 'utf8',
    input: JSON.stringify(domains),
    timeout: 120000,
  })

  const parsed = JSON.parse(stdout) as unknown
  return Array.isArray(parsed) ? (parsed as ProbeResult[]) : []
}

async function runRustWhoisParityProbe(domain: string): Promise<{ domain: string; whois: ProbeResult['whois']; whoisMs: number }> {
  const binaryPath = path.join(
    process.cwd(),
    'src-tauri',
    'target',
    'debug',
    process.platform === 'win32' ? 'parity_whois.exe' : 'parity_whois'
  )

  const stdout = execFileSync(binaryPath, [], {
    cwd: process.cwd(),
    maxBuffer: 1024 * 1024 * 8,
    encoding: 'utf8',
    input: domain,
    timeout: 120000,
  })

  const parsed = JSON.parse(stdout) as unknown
  const payload = (parsed ?? {}) as { domain?: unknown; whois?: unknown; whoisMs?: unknown }

  return {
    domain: typeof payload.domain === 'string' ? payload.domain : '',
    whois: (payload.whois ?? {}) as ProbeResult['whois'],
    whoisMs: typeof payload.whoisMs === 'number' ? payload.whoisMs : 0,
  }
}

test('REQ-PROBE-011: node and rust probe runtimes stay parity-compatible', async () => {
  const [nodeResults, rustResults] = await Promise.all([
    runProbeBatch(PARITY_DOMAINS),
    runRustParityProbe(PARITY_DOMAINS),
  ])

  const nodeById = indexById(nodeResults)
  const rustById = indexById(rustResults)

  const mismatches: string[] = []

  for (const domain of PARITY_DOMAINS) {
    const node = nodeById.get(domain.id)
    const rust = rustById.get(domain.id)

    if (!node || !rust) {
      mismatches.push(`${domain.domain}: missing result (node=${Boolean(node)}, rust=${Boolean(rust)})`)
      continue
    }

    if (node.status !== rust.status) {
      mismatches.push(`${domain.domain}: status mismatch node=${node.status} rust=${rust.status}`)
    }

    if (normalizeUrl(node.finalUrl) !== normalizeUrl(rust.finalUrl)) {
      mismatches.push(`${domain.domain}: finalUrl mismatch node=${node.finalUrl} rust=${rust.finalUrl}`)
    }

    if (normalizeUrl(node.framesetUrl) !== normalizeUrl(rust.framesetUrl)) {
      mismatches.push(`${domain.domain}: framesetUrl mismatch node=${node.framesetUrl} rust=${rust.framesetUrl}`)
    }

    if ((node.framesetHttpStatus ?? 0) !== (rust.framesetHttpStatus ?? 0)) {
      mismatches.push(
        `${domain.domain}: framesetHttpStatus mismatch node=${node.framesetHttpStatus} rust=${rust.framesetHttpStatus}`
      )
    }

    const nodeChain = normalizeChain(node.redirectChain)
    const rustChain = normalizeChain(rust.redirectChain)
    if (JSON.stringify(nodeChain) !== JSON.stringify(rustChain)) {
      mismatches.push(`${domain.domain}: redirectChain mismatch node=${nodeChain.join(' -> ')} rust=${rustChain.join(' -> ')}`)
    }

    const nodeNs = normalizeSet(node.dnsNameServers)
    const rustNs = normalizeSet(rust.dnsNameServers)
    if (JSON.stringify(nodeNs) !== JSON.stringify(rustNs)) {
      mismatches.push(`${domain.domain}: dnsNameServers mismatch node=${nodeNs.join(',')} rust=${rustNs.join(',')}`)
    }

    if (node.whois || rust.whois) {
      mismatches.push(`${domain.domain}: whois payload unexpectedly present in batch probe result`)
    }
  }

  assert.equal(
    mismatches.length,
    0,
    `Parity mismatches detected:\n${mismatches.map((entry) => `- ${entry}`).join('\n')}`
  )
})

test('REQ-PROBE-017: .info WHOIS parity avoids RDAP redirect-only errors', async () => {
  const domain = 'deineschufa.info'
  const [nodeWhois, rustWhois] = await Promise.all([lookupWhois(domain), runRustWhoisParityProbe(domain)])

  const nodeWhoisError = nodeWhois.whois?.error || ''
  const rustWhoisError = rustWhois.whois?.error || ''

  assert.equal(
    rustWhoisError,
    nodeWhoisError,
    `WHOIS error mismatch for .info domain: node=${nodeWhoisError || '<none>'} rust=${rustWhoisError || '<none>'}`
  )
  assert.equal(
    /rdap\.org http 302 found|www\.rdap\.net http 302 found/i.test(rustWhoisError),
    false,
    `Unexpected RDAP redirect-only WHOIS error for .info domain: ${rustWhoisError}`
  )
})
