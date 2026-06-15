# Probe Functional Requirements

This document is the formal behavior contract for probe logic.

## REQ-PROBE-001 Redirect Chain Status Priority
- If one or more redirects are detected, status must be redirected.
- This has priority over host-equality checks.

## REQ-PROBE-002 Parking Detection
- If known parking signals are detected in final URL, server header, or content type, status must be parked.
- Parking detection must work even when final host equals the original host.

## REQ-PROBE-003 Cross-Host Redirect Classification
- If final URL host differs from domain or www.domain, status must be redirected.

## REQ-PROBE-004 Same-Host Success Classification
- If final URL host equals domain or www.domain and no parked/redirect-chain rule applies, status must be ok.

## REQ-PROBE-005 Missing Final URL Classification
- If no final URL exists, status must be unreachable.

## REQ-PROBE-006 Domain Normalization
- Domain normalization must trim whitespace, lowercase, and remove trailing dots.
- URL-like input must normalize to hostname-only (scheme, path, query, and fragment removed).

## REQ-PROBE-007 WHOIS Status Family Mapping
- Known ICANN EPP statuses must map to family ICANN EPP.
- Known DENIC statuses must map to family DENIC.
- Unknown statuses must map to family Unknown.

## REQ-PROBE-008 WHOIS Status Definition Mapping
- Known status values must return a human-readable definition.
- Unknown status values must return no definition.

## REQ-PROBE-009 Name Server SLD Extraction
- Name server SLD extraction must return the last two labels of a hostname.
- Missing or invalid input must return an empty string.

## REQ-PROBE-010 Probe Batch Concurrency Normalization
- Probe batch concurrency must be centrally configurable with a default value of 10.
- Invalid values must fall back to default 10.
- Values below 1 must clamp to 1; values above 50 must clamp to 50.

## REQ-PROBE-011 Node-Rust Probe Parity Regression
- A dedicated regression suite must execute the same domain set against Node probe runtime and Rust probe runtime.
- The suite must assert parity for core output semantics at minimum: status, final URL, redirect chain, DNS name server set, WHOIS server, and WHOIS raw text availability.

## REQ-PROBE-012 Probe Progress Label
- Probe progress label formatting must output "x von N".
- Completed value must be clamped to the inclusive range [0, N].

## REQ-PROBE-013 Probe Fallback Result Shape
- When a probe attempt fails and a fallback result is created, status must be unreachable.
- Fallback result must preserve domainId/domain and include the provided error message.

## REQ-PROBE-014 Probe Max Attempts Normalization
- Probe auto-retry max attempts must be centrally configurable with default value 2.
- Invalid values must fall back to default 2.
- Values below 1 must clamp to 1; values above 5 must clamp to 5.

## REQ-PROBE-015 Frameset Redirect Detection
- If the final HTML response contains a frameset with a frame src target, status must be frameset.
- Frameset target URL must be resolved against the final URL, then followed for redirects; the final destination must be exposed as framesetUrl.
- Frameset destination HTTP status must be exposed as framesetHttpStatus and shown as a status pill next to the displayed URL in UI.

## REQ-PROBE-016 Configurable Parked Pattern Matching
- User-configured parked patterns must support an optional NS SLD filter and a required response regex.
- A parked pattern must match only when the regex matches response body text and, if NS SLD is specified, one DNS name server SLD matches.
- Invalid regex patterns or empty regex values must be ignored safely without failing a probe.

## REQ-PROBE-017 .info WHOIS Parity Stability
- Node and Rust runtimes must produce parity-compatible WHOIS outcomes for `.info` domains in parity regression tests.
- Rust WHOIS/RDAP fallback behavior must not fail solely because an RDAP endpoint responds with HTTP redirects that Node follows successfully.

## REQ-PROBE-018 Default Parked Patterns
- Default parked patterns must include an `udag` rule for `Diese neue Domain wurde im Kundenauftrag registriert.` and a `nic` rule for `\\.tel`.
- New settings objects and legacy saved settings that do not yet contain a parked-patterns field must start with those defaults.
- Explicitly saved parked patterns, including an empty list, must be preserved as-is.

## REQ-PROBE-019 Restore Default Settings
- Restoring default settings in the settings dialog must reset probe batch concurrency, probe max attempts, and parked patterns to the shared application defaults.
- The restore operation must repopulate the default parked patterns even if the draft settings were previously cleared or edited.

## REQ-PROBE-020 Table Filter Scope and Target Status Filter
- The free-text table search filter must match only against table Domain and Target values.
- Additional table filters must support filtering by Target status class (`none`, `2xx`, `3xx`, `4xx`, `5xx`) and NS SLD.

## REQ-PROBE-021 Probe Timing Breakdown
- Probe results must expose `dnsMs`, `httpMs`, and `whoisMs` timing fields in addition to `probeMs`.
- UI probe details must show WHOIS timing percentage computed from `whoisMs / probeMs`, rounded to whole percent and clamped to a maximum of `100%`.

## REQ-PROBE-022 Stable Redirected Response Badge
- The response badge label must not append target HTTP status when probe status is `redirected`.
- This keeps the primary response badge stable across different probe vantage points while preserving target HTTP status in dedicated target-status UI.

## REQ-PROBE-023 Redirect Chain Response Statuses
- Redirect chain data must include per-hop response status for each redirect source URL.
- Redirect chain data should include per-hop server header values when available.
- Redirect chain UI must display each line item as `<url> (<response status>) [<server>]` when server data exists, including the final target URL with its final HTTP status and server header when available.

## REQ-PROBE-024 Implicit Redirect Preservation
- If HTTP client/runtime behavior returns a response whose effective URL differs from the requested URL, probing must treat that as an implicit redirect hop.
- The original requested URL must be appended to the redirect chain even when no `Location` header is observable by application code.

## REQ-PROBE-025 Explicit HTTPS Counterpart Continuation
- If a redirected chain reaches an HTTP URL with a terminal 2xx response, probing must issue an explicit separate request to the HTTPS counterpart URL.
- When this continuation is performed, the HTTP URL must remain in the redirect chain with its observed HTTP status.