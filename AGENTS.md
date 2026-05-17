# Agent Instructions

## Source Of Truth
- The Node implementation in src/lib/probe-runtime.ts is the canonical source of truth for probing behavior.
- The Rust implementation (Tauri) must strictly mirror Node behavior 1:1.

## Change Policy
- Do not change probe behavior first in Rust.
- Implement behavior changes in Node first, then port to Rust with parity checks.
- Do not change UI behavior or presentation in src/app/list/ListPage.tsx unless explicitly requested.

## Parity Requirements (Node -> Rust)
- Keep output schema identical to ProbeResult/WhoisResult field semantics.
- Keep identical status classification semantics (ok, redirected, parked, unreachable, no-dns, timeout).
- Keep identical redirect chain semantics (source URL per hop + finalUrl).
- Keep identical WHOIS rules (server discovery, referral handling, raw plain text behavior, parsing normalization).
- Keep identical DNS sourcing and normalization semantics.

## Validation Gate
- Every Rust probe change must be validated against Node using the same domain set and compared for behavioral parity.
- If parity is not reached, treat Rust as non-compliant and do not switch Tauri runtime to Rust output for that path.

## Requirements Discipline
- Functional behavior changes must be recorded with a stable requirement ID in docs/requirements/probe-requirements.md.
- Requirement IDs must use the format REQ-PROBE-XXX.
- Every requirement change must include or update an automated test in tests/probe-requirements.test.ts.
- No behavior-only code change is complete without a matching requirement entry and test assertion.

## Safety Rule
- When uncertain, preserve existing Node behavior and ask for clarification before changing semantics.
