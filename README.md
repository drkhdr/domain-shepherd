# Domain Shepherd

Domain Shepherd helps keep track of a domain portfolio.

*Track your domains. No account needed.*

## Architecture

- API-free app: no Next.js API routes are used.
- One implementation path: web and Tauri use the same TypeScript probe runtime in `src/lib/probe-runtime.ts`.
- Local-first storage: the domain list is stored locally in the browser/Tauri webview storage.
- Rust host only: Tauri Rust code only hosts the app shell and does not duplicate probe logic.

## What You Can Track
Response and target

- See whether a domain is OK, redirected, parked, unreachable, timed out, or missing DNS, plus the resolved target URL.

WHOIS context

- Surface registrar details, expiry dates, WHOIS status values, and readable explanations for common ICANN and DENIC states.

Operational workflow

- Bulk import domains, re-probe the full list, inspect details row by row, and copy the table out as CSV when you need to report or hand off.

## Features
- Track domain status and HTTP response codes
- Inspect WHOIS data, registrar information, and nameservers
- Export your list as CSV for analysis or reporting

*All data is processed and stored locally on your device. No accounts, no server-side storage.*

## License
Licensed under the MIT License.
Copyright (c) 2026 Dirk Heider (LinkedIn)

## Voraussetzungen
- Betriebssystem: 
  - Web App: Anything running Node.js
  - Tauri App: Windows
- Abhängigkeiten:
  - Node.js >= 16.2.6
  - Tauri >= 2.11.1

## Installation

### Web App
- Dev
  - npm install
  - npm run dev
- Prod
  - npm run build
  - npm start

### Tauri App

To build the dev version, run:
- npm run tauri:dev

Once complete, the executable will be here:
- src-tauri/target/debug/domain-shepherd.exe

To build the release version with installers, run:

- npm run tauri:build

Once complete, the distributable files will be in:

- MSI Installer: src-tauri/target/release/bundle/msi/
- Portable EXE: src-tauri/target/release/domain-shepherd.exe
- NSIS Installer: src-tauri/target/release/bundle/nsis/