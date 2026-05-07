# NetSentinel

> A professional Linux desktop application for network vulnerability scanning, CVE tracking, and security education — built with Tauri, Rust, and React.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tauri](https://img.shields.io/badge/Tauri-2.x-blue?logo=tauri)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?logo=rust)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://react.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-yellow?logo=linux)](https://kernel.org)

---

## Screenshots

> Dashboard, Scanner, CVE Search, and Learn sections — dark security-tool aesthetic with green/cyan accents.

---

## Features

| Feature | Description |
|---------|-------------|
| **Network Scanner** | Nmap-powered port and vulnerability scanning (Quick / Full / Vuln modes) |
| **CVE Search** | Live queries to the NIST NVD API with CVSS scores and severity ratings |
| **Scan History** | All scans stored locally in SQLite — searchable and persistent |
| **Learn** | Built-in reference covering CVSS, scan types, vulnerability classes, responsible disclosure |
| **Dark UI** | Security-tool aesthetic — dark theme with green/cyan accent colors |

---

## Requirements

| Dependency | Version | Install |
|------------|---------|---------|
| Rust | 1.75+ | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Node.js | 18+ | [nodejs.org](https://nodejs.org) |
| Nmap | 7.x+ | `sudo apt install nmap` |
| WebKit2GTK | 4.1 | `sudo apt install libwebkit2gtk-4.1-dev` |

Full list of Linux system dependencies:

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

### Run in Development Mode

```bash
npm run tauri dev
```

### Build for Production

```bash
npm run tauri build
```

The packaged app (AppImage / .deb) will be output to `src-tauri/target/release/bundle/`.

---

## Project Structure

```
netsentinel/
├── src/                        # React + TypeScript frontend
│   ├── pages/
│   │   ├── Dashboard.tsx       # Overview with stats and quick scan
│   │   ├── Scanner.tsx         # Nmap scan UI with live results
│   │   ├── History.tsx         # Persistent scan history viewer
│   │   ├── CveSearch.tsx       # NVD CVE search and detail view
│   │   └── Learn.tsx           # Security reference and education
│   ├── components/
│   │   ├── Sidebar.tsx         # Navigation sidebar
│   │   ├── ScanResultsTable.tsx
│   │   ├── CveCard.tsx
│   │   └── SeverityBadge.tsx
│   └── App.tsx
├── src-tauri/                  # Rust backend (Tauri)
│   ├── src/
│   │   ├── lib.rs              # Tauri command registration
│   │   ├── scanner.rs          # Nmap integration + XML parser
│   │   ├── cve.rs              # NVD API client
│   │   └── database.rs         # SQLite persistence layer
│   ├── Cargo.toml
│   └── tauri.conf.json
└── package.json
```

---

## Architecture

```
┌─────────────────────────────────┐
│        React Frontend           │
│  Dashboard │ Scanner │ CVE │ Learn│
└────────────┬────────────────────┘
             │ Tauri IPC (invoke)
┌────────────▼────────────────────┐
│         Rust Backend            │
│  scanner.rs │ cve.rs │ db.rs    │
└──────┬──────────────┬───────────┘
       │              │
  ┌────▼────┐   ┌─────▼──────┐
  │  Nmap   │   │  NVD API   │
  │ (local) │   │  (HTTPS)   │
  └─────────┘   └────────────┘
       │
  ┌────▼────────┐
  │  SQLite DB  │
  │ (~/.local/) │
  └─────────────┘
```

---

## Legal & Ethical Use

> **WARNING:** Unauthorized network scanning is illegal in many jurisdictions, including under the Computer Fraud and Abuse Act (USA), the Computer Misuse Act (UK), and equivalent laws worldwide.

- **Only scan networks and systems you own or have explicit written permission to scan.**
- This tool is intended for security professionals, IT administrators, and students in authorized environments.
- The authors and contributors accept no liability for misuse.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m 'feat: add your feature'`
4. Push and open a PR

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

MIT © [christos91cy-png](https://github.com/christos91cy-png) — see [LICENSE](LICENSE) for details.
