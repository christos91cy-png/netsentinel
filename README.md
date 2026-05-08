# NetSentinel

> Open-source Linux desktop network vulnerability scanner — built with Tauri v2, Rust, and React 18.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v0.2.0-brightgreen)](https://github.com/christos91cy-png/netsentinel/releases)
[![Tauri](https://img.shields.io/badge/Tauri-2.x-blue?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?logo=rust)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://react.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-yellow?logo=linux)](https://kernel.org)

NetSentinel is a local-first, no-telemetry network security tool for Linux desktops. It wraps Nmap with a modern UI, correlates discovered services against the NIST NVD CVE database, cross-references the CISA Known Exploited Vulnerabilities feed, and stores all scan history in a local SQLite database — nothing leaves your machine unless you ask it to.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Legal & Ethical Use](#legal--ethical-use)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Scanning

| Mode | Description | Typical Duration |
|------|-------------|-----------------|
| **Quick Scan** | Top 100 ports with fast service detection | ~5 seconds |
| **Full Scan** | All 65535 ports with version detection | 3–8 minutes |
| **Vuln Scan** | Nmap vulnerability scripts against discovered services | 5–15 minutes |
| **Discover Scan** | Ping sweep to find live hosts on the local network | 5–30 seconds |

- Real-time progress bar showing percentage complete, current phase label, and elapsed timer
- Cancel button terminates the Nmap subprocess immediately
- Shodan InternetDB passive lookup on public IPs — no API key required

> **Note:** Full, Vuln, and Discover scans require Nmap to run with elevated privileges. NetSentinel will prompt for sudo as needed.

### Threat Intelligence

| Capability | Description |
|------------|-------------|
| **CVE Correlation** | Auto-maps discovered open ports and service banners to NIST NVD CVE queries |
| **CISA KEV Integration** | Cross-references results against the Known Exploited Vulnerabilities catalog |
| **EPSS Scoring** | Displays the Exploit Prediction Scoring System percentage for each CVE |
| **OS Fingerprinting** | Parses Nmap `osmatch` results and displays operating system confidence scores |
| **CVE Search** | Live NIST NVD API search with CVSS v3 scores, severity ratings, and descriptions |

### History & Reporting

- All scans stored locally in SQLite — searchable, persistent, no cloud dependency
- Scan diff: compare any two historical scans side-by-side — new ports, closed ports, and unchanged ports highlighted
- Export scan results to JSON or CSV in `~/Downloads/`
- Print / PDF report via browser print dialog with a clean A4 layout
- Delete individual scan records with a confirmation prompt

### UI/UX

- Dashboard with 4 KPI cards (total scans, open ports, vulnerabilities found, last scan age), 14-day activity bar chart, recent scans timeline, and system health bar
- Toast notification system (success / error / warning / info) with auto-dismiss
- Dark security-tool aesthetic: `#0f1117` background, `#00ff88` green accents, `#00bcd4` teal highlights
- Full-width responsive layout — scales to any window size (minimum 900x600)
- Settings page: configure NVD API key, Shodan API key, and default scan type
- Learn page: built-in reference covering CVSS scoring, scan types, vulnerability classes, and responsible disclosure

---

## Requirements

| Dependency | Version | Install |
|------------|---------|---------|
| Rust | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Node.js | 22+ | [nodejs.org](https://nodejs.org) |
| Nmap | 7.x+ | `sudo apt install nmap` |
| WebKit2GTK | 4.1 | `sudo apt install libwebkit2gtk-4.1-dev` |

Install all Linux system dependencies in one command:

```bash
sudo apt install -y \
  nmap \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev
```

---

## Getting Started

### Clone & Install

```bash
git clone https://github.com/christos91cy-png/netsentinel.git
cd netsentinel
npm install
```

### Development Mode

```bash
npm run tauri dev
```

Starts the Vite dev server and the Tauri development window with hot reload.

### Production Build

```bash
npm run tauri build
```

Produces an AppImage and `.deb` package at `src-tauri/target/release/bundle/`.

---

## Architecture

NetSentinel follows a clean separation between a Rust async backend and a React frontend, communicating via Tauri's IPC bridge.

```
┌──────────────────────────────────────────────────────────┐
│                     React Frontend                       │
│   Dashboard | Scanner | History | CVE Search | Settings  │
└──────────────────────────┬───────────────────────────────┘
                           │  Tauri IPC (invoke / emit)
┌──────────────────────────▼───────────────────────────────┐
│                     Rust Backend                         │
│  scanner.rs | cve.rs | threat_intel.rs | shodan.rs       │
│  database.rs | diff.rs                                   │
└──────┬─────────────────────┬────────────────────────────-┘
       │                     │
  ┌────▼──────┐    ┌─────────▼──────────────────────┐
  │   Nmap    │    │  External APIs (HTTPS)          │
  │ (local    │    │  NVD | CISA KEV | EPSS | Shodan │
  │ process)  │    └────────────────────────────────-┘
  └────┬──────┘
       │
  ┌────▼─────────────┐
  │  SQLite Database  │
  │  (local, bundled) │
  └───────────────────┘
```

**Rust backend** — async `tokio` runtime. Nmap is launched as a subprocess via `tokio::process::Command` and XML output is parsed with `quick-xml`. `rusqlite` (bundled, no system dependency) handles all local storage. `reqwest` drives all HTTP requests to NVD, CISA KEV, EPSS, and Shodan InternetDB.

**Frontend** — React 18 with Zustand for global state management. Pages communicate with the backend exclusively through Tauri `invoke` calls and `emit` events. Recharts renders the dashboard activity chart. Lucide React provides all icons. Tailwind CSS v3 handles styling.

**Real-time scan events:**

| Event | Payload |
|-------|---------|
| `scan:start` | `{ target, scan_type }` |
| `scan:progress` | `{ percent, phase, elapsed_secs }` |
| `scan:complete` | `{ scan_id, results }` |
| `scan:error` | `{ message }` |

---

## Project Structure

```
netsentinel/
├── src/                            # React + TypeScript frontend
│   ├── pages/
│   │   ├── Dashboard.tsx           # KPI cards, 14-day chart, recent scans
│   │   ├── Scanner.tsx             # Scan UI, live progress, results table
│   │   ├── History.tsx             # Scan history browser with delete
│   │   ├── Diff.tsx                # Side-by-side scan comparison
│   │   ├── Report.tsx              # Print/PDF report layout
│   │   ├── CveSearch.tsx           # Live NVD CVE search
│   │   ├── Settings.tsx            # API keys and preferences
│   │   └── Learn.tsx               # Built-in security reference
│   ├── components/
│   │   ├── Sidebar.tsx             # Navigation
│   │   ├── ScanResultsTable.tsx    # Port/service/CVE result rows
│   │   ├── ThreatIntelPanel.tsx    # KEV / EPSS / Shodan panel
│   │   ├── CveCard.tsx             # CVE detail card
│   │   ├── SeverityBadge.tsx       # CVSS severity label
│   │   └── Toast.tsx               # Notification system
│   ├── store/
│   │   ├── scanStore.ts            # Active scan state (Zustand)
│   │   └── historyStore.ts         # Scan history state (Zustand)
│   ├── types.ts                    # Shared TypeScript types
│   └── App.tsx
├── src-tauri/                      # Rust backend (Tauri v2)
│   ├── src/
│   │   ├── lib.rs                  # Tauri command registration
│   │   ├── scanner.rs              # Nmap subprocess + XML parser
│   │   ├── cve.rs                  # NIST NVD API client
│   │   ├── threat_intel.rs         # CISA KEV + EPSS integration
│   │   ├── shodan.rs               # Shodan InternetDB client
│   │   ├── diff.rs                 # Scan comparison logic
│   │   └── database.rs             # SQLite persistence layer
│   ├── Cargo.toml
│   └── tauri.conf.json
└── package.json
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Desktop shell | Tauri v2 |
| Backend language | Rust (edition 2021) |
| Async runtime | tokio 1.x (full features) |
| Local database | rusqlite 0.31 (bundled SQLite) |
| HTTP client | reqwest 0.12 |
| XML parsing | quick-xml 0.36 |
| Date/time | chrono 0.4 |
| Frontend framework | React 18 |
| Language | TypeScript 5.x |
| Build tool | Vite 5.x |
| Styling | Tailwind CSS v3 |
| State management | Zustand 5.x |
| Charts | Recharts 3.x |
| Icons | Lucide React |

---

## Roadmap

The following items are planned for Phase 4:

- **Ollama LLM integration** — "Explain This Vulnerability" button sends CVE details to a local Ollama instance for plain-language analysis, no data sent to external AI services
- **Attack Surface Score** — 0–100 composite risk score per scan, derived from open port count, CVE severity distribution, and KEV presence
- **Network topology map** — Visual graph of discovered hosts and their relationships on the local network
- **Scheduled scans** — Cron-style recurring scans with change detection alerts
- **Windows and macOS support** — Cross-platform packaging once the Linux baseline is stable

---

## Legal & Ethical Use

**WARNING:** Unauthorized network scanning is illegal in many jurisdictions, including under the Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), and equivalent laws worldwide.

- Only scan networks and systems you own or have explicit written permission to scan.
- This tool is intended for security professionals, IT administrators, penetration testers, and students operating in authorized environments.
- The authors and contributors accept no liability for misuse.

---

## Contributing

Contributions are welcome. Please open an issue before starting significant work so we can discuss direction.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes following conventional commits: `git commit -m 'feat: add your feature'`
4. Push and open a pull request against `main`

Rust code must pass `cargo clippy -- -D warnings` and `cargo fmt --check`. TypeScript must pass `tsc --noEmit`.

---

## License

MIT © [christos91cy-png](https://github.com/christos91cy-png) — see [LICENSE](LICENSE) for details.
