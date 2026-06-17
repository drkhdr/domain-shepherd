import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildRedirectChainWithFinal,
  calculateWhoisSharePercent,
  classifyProbeStatus,
  createDefaultProbeSettings,
  createProbeFailureResult,
  DEFAULT_PARKED_PATTERNS,
  extractFramesetUrl,
  formatProbeProgress,
  getResponseBadgeHttpStatus,
  getDefaultParkedPatterns,
  getNameServerSld,
  matchesDomainTargetSearchFilter,
  matchesConfiguredParkedPatterns,
  matchesTargetStatusFilter,
  normalizeParkedPatterns,
  PROBE_BATCH_CONCURRENCY_DEFAULT,
  PROBE_MAX_ATTEMPTS_DEFAULT,
  getWhoisStatusDefinition,
  getWhoisStatusFamily,
  isImplicitlyRedirectedResponse,
  normalizeProbeBatchConcurrency,
  normalizeProbeMaxAttempts,
  shouldContinueToHttpsCounterpart,
  shouldFetchWhoisOnExpand,
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
  assert.equal(fallback.dnsMs, 0)
  assert.equal(fallback.httpMs, 0)
  assert.equal(fallback.whoisMs, 0)
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

test('REQ-PROBE-018: default parked patterns stay available and clone safely', () => {
  assert.deepEqual(DEFAULT_PARKED_PATTERNS, [
    { nsSld: 'udag', responseRegex: 'Diese neue Domain wurde im Kundenauftrag registriert.' },
    { nsSld: 'nic', responseRegex: String.raw`\.tel` },
  ])

  const clonedDefaults = getDefaultParkedPatterns()
  assert.deepEqual(clonedDefaults, DEFAULT_PARKED_PATTERNS)
  assert.notEqual(clonedDefaults, DEFAULT_PARKED_PATTERNS)

  clonedDefaults[0].responseRegex = 'changed'
  assert.equal(DEFAULT_PARKED_PATTERNS[0].responseRegex, 'Diese neue Domain wurde im Kundenauftrag registriert.')
})

test('REQ-PROBE-019: default probe settings restore concurrency attempts and parked patterns', () => {
  const defaults = createDefaultProbeSettings()

  assert.equal(defaults.batchConcurrency, PROBE_BATCH_CONCURRENCY_DEFAULT)
  assert.equal(defaults.maxAttempts, PROBE_MAX_ATTEMPTS_DEFAULT)
  assert.deepEqual(defaults.parkedPatterns, DEFAULT_PARKED_PATTERNS)

  defaults.parkedPatterns[0].responseRegex = 'changed'
  assert.equal(DEFAULT_PARKED_PATTERNS[0].responseRegex, 'Diese neue Domain wurde im Kundenauftrag registriert.')
})

test('REQ-PROBE-020: table search filter is restricted to domain and target', () => {
  assert.equal(
    matchesDomainTargetSearchFilter('example.com', 'https://target.example.com', 'example'),
    true
  )
  assert.equal(
    matchesDomainTargetSearchFilter('example.com', 'https://target.example.com', 'target'),
    true
  )
  assert.equal(
    matchesDomainTargetSearchFilter('example.com', 'https://target.example.com', 'clienttransferprohibited'),
    false
  )
})

test('REQ-PROBE-020: target status class filter behavior', () => {
  assert.equal(matchesTargetStatusFilter(undefined, 'all'), true)
  assert.equal(matchesTargetStatusFilter(undefined, 'none'), true)
  assert.equal(matchesTargetStatusFilter(0, 'none'), true)
  assert.equal(matchesTargetStatusFilter(200, '2xx'), true)
  assert.equal(matchesTargetStatusFilter(302, '3xx'), true)
  assert.equal(matchesTargetStatusFilter(404, '4xx'), true)
  assert.equal(matchesTargetStatusFilter(503, '5xx'), true)
  assert.equal(matchesTargetStatusFilter(404, '2xx'), false)
})

test('REQ-PROBE-021: whois timing share percent helper', () => {
  assert.equal(calculateWhoisSharePercent(0, 100), 0)
  assert.equal(calculateWhoisSharePercent(1000, 0), 0)
  assert.equal(calculateWhoisSharePercent(1000, 250), 25)
  assert.equal(calculateWhoisSharePercent(999, 333), 33)
  assert.equal(calculateWhoisSharePercent(1000, 1200), 100)
})

test('REQ-PROBE-022: response badge hides volatile target code for redirected status', () => {
  assert.equal(getResponseBadgeHttpStatus('redirected', 404), undefined)
  assert.equal(getResponseBadgeHttpStatus('redirected', 200), undefined)
  assert.equal(getResponseBadgeHttpStatus('ok', 200), 200)
  assert.equal(getResponseBadgeHttpStatus('unreachable', 0), undefined)
})

test('REQ-PROBE-023: redirect chain exposes per-hop status and optional server header including final target', () => {
  const chain = buildRedirectChainWithFinal(
    [
      { url: 'http://example.com', responseStatus: 301, serverHeader: 'cloudflare' },
      { url: 'https://www.example.com', responseStatus: 302, serverHeader: 'nginx' },
      'https://legacy.example.com/path',
    ],
    'https://target.example.net/',
    200,
    'envoy'
  )

  assert.deepEqual(chain, [
    { url: 'http://example.com', responseStatus: 301, serverHeader: 'cloudflare' },
    { url: 'https://www.example.com', responseStatus: 302, serverHeader: 'nginx' },
    { url: 'https://legacy.example.com/path' },
    { url: 'https://target.example.net/', responseStatus: 200, serverHeader: 'envoy' },
  ])
})

test('REQ-PROBE-024: implicit redirect detection compares effective response URL', () => {
  assert.equal(
    isImplicitlyRedirectedResponse('http://www.meineschufa.de/bonitaetsauskunft', 'https://www.meineschufa.de/bonitaetsauskunft'),
    true
  )
  assert.equal(
    isImplicitlyRedirectedResponse('https://www.example.com/path/', 'https://www.example.com/path'),
    false
  )
  assert.equal(isImplicitlyRedirectedResponse('https://www.example.com/path', undefined), false)
})

test('REQ-PROBE-025: redirected HTTP success continues with explicit HTTPS counterpart request', () => {
  assert.equal(shouldContinueToHttpsCounterpart('http://www.meineschufa.de/bonitaetsauskunft', ['http://xn--datenbersicht-0ob.de'], 200), true)
  assert.equal(shouldContinueToHttpsCounterpart('http://www.meineschufa.de/bonitaetsauskunft', ['http://xn--datenbersicht-0ob.de'], 404), false)
  assert.equal(shouldContinueToHttpsCounterpart('https://www.meineschufa.de/bonitaetsauskunft', ['http://xn--datenbersicht-0ob.de'], 200), false)
  assert.equal(shouldContinueToHttpsCounterpart('http://www.meineschufa.de/bonitaetsauskunft', [], 200), false)
})

test('REQ-PROBE-026: WHOIS fetch is deferred until details expansion and only requested once per expansion state', () => {
  assert.equal(shouldFetchWhoisOnExpand(false, false, false), false)
  assert.equal(shouldFetchWhoisOnExpand(true, true, false), false)
  assert.equal(shouldFetchWhoisOnExpand(true, false, true), false)
  assert.equal(shouldFetchWhoisOnExpand(true, false, false), true)
})

