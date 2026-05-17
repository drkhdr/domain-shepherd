import assert from 'node:assert/strict'
import test from 'node:test'

import {
  classifyProbeStatus,
  createProbeFailureResult,
  extractFramesetUrl,
  formatProbeProgress,
  getNameServerSld,
  matchesConfiguredParkedPatterns,
  normalizeParkedPatterns,
  PROBE_BATCH_CONCURRENCY_DEFAULT,
  PROBE_MAX_ATTEMPTS_DEFAULT,
  getWhoisStatusDefinition,
  getWhoisStatusFamily,
  normalizeProbeBatchConcurrency,
  normalizeProbeMaxAttempts,
  normalizeDomain,
} from '../src/lib/probe'

test('REQ-PROBE-001: redirect chain forces redirected status', () => {
  const status = classifyProbeStatus('schufa.de', 'https://www.schufa.de/', ['https://schufa.de'])
  assert.equal(status, 'redirected')
})

test('REQ-PROBE-002: parking signal is classified as parked', () => {
  const status = classifyProbeStatus('example.com', 'https://example.com', [], 'server', 'text/html; dan.com parking')
  assert.equal(status, 'parked')
})

test('REQ-PROBE-003: different final host is redirected', () => {
  const status = classifyProbeStatus('example.com', 'https://target.example.net/')
  assert.equal(status, 'redirected')
})

test('REQ-PROBE-004: same host is ok without redirects', () => {
  const statusApex = classifyProbeStatus('example.com', 'https://example.com/')
  const statusWww = classifyProbeStatus('example.com', 'https://www.example.com/')
  assert.equal(statusApex, 'ok')
  assert.equal(statusWww, 'ok')
})

test('REQ-PROBE-005: missing final URL is unreachable', () => {
  const status = classifyProbeStatus('example.com', undefined)
  assert.equal(status, 'unreachable')
})

test('REQ-PROBE-006: normalizeDomain trims, lowercases, and strips trailing dots', () => {
  const normalized = normalizeDomain('  EXAMPLE.COM...  ')
  assert.equal(normalized, 'example.com')

  const normalizedUrl = normalizeDomain('http://2425-euro-kreditvermittlung-ohne-schufa.eu/schufa-frei/?x=1#top')
  assert.equal(normalizedUrl, '2425-euro-kreditvermittlung-ohne-schufa.eu')
})

test('REQ-PROBE-007: WHOIS status family mapping is stable', () => {
  assert.equal(getWhoisStatusFamily('clientTransferProhibited'), 'ICANN EPP')
  assert.equal(getWhoisStatusFamily('connect'), 'DENIC')
  assert.equal(getWhoisStatusFamily('something-unknown'), 'Unknown')
})

test('REQ-PROBE-008: WHOIS status definition mapping', () => {
  assert.match(getWhoisStatusDefinition('connect') || '', /delegated and connected/i)
  assert.equal(getWhoisStatusDefinition('this-is-not-mapped'), undefined)
})

test('REQ-PROBE-009: name server SLD extraction', () => {
  assert.equal(getNameServerSld('ns1.kcs-netz.de'), 'kcs-netz.de')
  assert.equal(getNameServerSld(''), '')
  assert.equal(getNameServerSld(undefined), '')
})

test('REQ-PROBE-010: probe batch concurrency normalization', () => {
  assert.equal(normalizeProbeBatchConcurrency(undefined), PROBE_BATCH_CONCURRENCY_DEFAULT)
  assert.equal(normalizeProbeBatchConcurrency(Number.NaN), PROBE_BATCH_CONCURRENCY_DEFAULT)
  assert.equal(normalizeProbeBatchConcurrency(''), PROBE_BATCH_CONCURRENCY_DEFAULT)
  assert.equal(normalizeProbeBatchConcurrency('not-a-number'), PROBE_BATCH_CONCURRENCY_DEFAULT)
  assert.equal(normalizeProbeBatchConcurrency(0), 1)
  assert.equal(normalizeProbeBatchConcurrency(999), 50)
  assert.equal(normalizeProbeBatchConcurrency(12), 12)
  assert.equal(normalizeProbeBatchConcurrency('12'), 12)
})

test('REQ-PROBE-012: probe progress label formatting', () => {
  assert.equal(formatProbeProgress(0, 10), '0 von 10')
  assert.equal(formatProbeProgress(5, 10), '5 von 10')
  assert.equal(formatProbeProgress(999, 10), '10 von 10')
  assert.equal(formatProbeProgress(-3, 10), '0 von 10')
})

test('REQ-PROBE-013: probe fallback result shape', () => {
  const fallback = createProbeFailureResult({ id: 'd1', domain: 'example.com' }, 'timeout')
  assert.equal(fallback.domainId, 'd1')
  assert.equal(fallback.domain, 'example.com')
  assert.equal(fallback.status, 'unreachable')
  assert.equal(fallback.error, 'timeout')
  assert.deepEqual(fallback.redirectChain, [])
  assert.deepEqual(fallback.ipAddresses, [])
})

test('REQ-PROBE-014: probe max attempts normalization', () => {
  assert.equal(normalizeProbeMaxAttempts(undefined), PROBE_MAX_ATTEMPTS_DEFAULT)
  assert.equal(normalizeProbeMaxAttempts(Number.NaN), PROBE_MAX_ATTEMPTS_DEFAULT)
  assert.equal(normalizeProbeMaxAttempts(''), PROBE_MAX_ATTEMPTS_DEFAULT)
  assert.equal(normalizeProbeMaxAttempts('not-a-number'), PROBE_MAX_ATTEMPTS_DEFAULT)
  assert.equal(normalizeProbeMaxAttempts(0), 1)
  assert.equal(normalizeProbeMaxAttempts(999), 5)
  assert.equal(normalizeProbeMaxAttempts(2), 2)
  assert.equal(normalizeProbeMaxAttempts('3'), 3)
})

test('REQ-PROBE-015: frameset redirect detection exposes absolute framesetUrl', () => {
  const html = '<html><frameset rows="100%"><frame src="/schufa-frei/" /></frameset></html>'
  const framesetUrl = extractFramesetUrl('https://www.schufa.de/root/path', 'text/html; charset=utf-8', html)
  assert.equal(framesetUrl, 'https://www.schufa.de/schufa-frei/')

  const noFrameset = extractFramesetUrl('https://www.schufa.de/root/path', 'text/html; charset=utf-8', '<html><body>Hello</body></html>')
  assert.equal(noFrameset, undefined)
})

test('REQ-PROBE-016: configurable parked pattern matching', () => {
  const patterns = normalizeParkedPatterns([
    { nsSld: 'udag', responseRegex: 'Diese neue Domain wurde im Kundenauftrag registriert' },
    { nsSld: '', responseRegex: '^for sale$' },
    { nsSld: 'ignored', responseRegex: '' },
    { nsSld: 'ignored', responseRegex: '[' },
  ])

  assert.equal(patterns.length, 3)
  assert.equal(
    matchesConfiguredParkedPatterns(
      patterns,
      ['ns1.udag.net'],
      'Diese neue Domain wurde im Kundenauftrag registriert.'
    ),
    true
  )
  assert.equal(matchesConfiguredParkedPatterns(patterns, ['ns1.other.net'], 'for sale'), true)
  assert.equal(
    matchesConfiguredParkedPatterns(
      patterns,
      ['ns1.other.net'],
      'Diese neue Domain wurde im Kundenauftrag registriert.'
    ),
    false
  )
})
