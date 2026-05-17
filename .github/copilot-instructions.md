# Copilot Repository Instructions

## Canonical Logic
- Node logic in src/lib/probe-runtime.ts is authoritative.
- Rust (src-tauri) is a strict follower and must not define independent behavior.

## Required Workflow For Probe Changes
1. Apply behavior change in Node first.
2. Add or update parity checks/examples for the changed behavior.
3. Port the exact behavior to Rust.
4. Verify parity (status, redirect chain, DNS/WHOIS fields, raw text handling).

## UI Stability Constraint
- Keep existing UI behavior and layout unchanged unless a UI change is explicitly requested.
- Transport/runtime wiring changes (Web vs Tauri) must not alter displayed semantics.

## Non-Regression Constraints
- Do not remove existing Node paths for web runtime.
- Do not silently alter field names, optionality, or meaning in probe results.
- Prefer minimal diffs and preserve existing behavior.

## Decision Rule
- If there is any conflict between Node and Rust behavior, Node wins.

## Functional Requirements Rule
- Track functional behavior as explicit requirement IDs in docs/requirements/probe-requirements.md.
- Keep tests in tests/probe-requirements.test.ts aligned with requirement IDs.
- Any behavior change must update both the requirement text and at least one automated test.
