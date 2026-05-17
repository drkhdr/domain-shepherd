import assert from 'node:assert/strict'
import { execFile, execFileSync } from 'node:child_process'
import path from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

import { runProbeBatch } from '../src/lib/probe-runtime'
import type { ProbeDomainInput, ProbeResult } from '../src/lib/probe'

const execFileAsync = promisify(execFile)

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

function normalizeChain(chain?: string[]): string[] {
  return (chain ?? []).map((entry) => normalizeUrl(entry))
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

    const nodeWhoisServer = (node.whois?.server || '').toLowerCase()
    const rustWhoisServer = (rust.whois?.server || '').toLowerCase()
    if (nodeWhoisServer !== rustWhoisServer) {
      mismatches.push(`${domain.domain}: whois.server mismatch node=${nodeWhoisServer} rust=${rustWhoisServer}`)
    }

    const nodeRaw = Boolean(node.whois?.rawText)
    const rustRaw = Boolean(rust.whois?.rawText)
    if (nodeRaw !== rustRaw) {
      mismatches.push(`${domain.domain}: whois.rawText presence mismatch node=${nodeRaw} rust=${rustRaw}`)
    }
  }

  assert.equal(
    mismatches.length,
    0,
    `Parity mismatches detected:\n${mismatches.map((entry) => `- ${entry}`).join('\n')}`
  )
})
