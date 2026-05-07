# Changelog

All notable changes to NetSentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-05-07

### Added
- **Network Scanner** — Nmap-powered scanning with Quick (top 100 ports), Full (all 65535 ports), and Vulnerability (NSE scripts) modes
- **CVE Search** — Real-time search against the NIST National Vulnerability Database (NVD) API v2 with CVSS v3.1 scoring and severity badges
- **Scan History** — SQLite-backed persistent scan history with port and vulnerability details
- **Dashboard** — Overview page with scan statistics and quick scan input
- **Learn** — Built-in security reference covering CVSS scoring, network scanning fundamentals, common vulnerability types, and responsible disclosure
- **Dark UI** — Security-tool aesthetic with dark theme (green/cyan accent palette)
- Tauri v2 desktop shell targeting Linux (AppImage, .deb bundles)
- React 18 + TypeScript + Vite frontend
- Rust backend with `rusqlite`, `reqwest`, and `quick-xml`
- Legal warning banner on all scan interfaces

[0.1.0]: https://github.com/christos91cy-png/netsentinel/releases/tag/v0.1.0
