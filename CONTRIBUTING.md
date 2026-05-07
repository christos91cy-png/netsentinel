# Contributing to NetSentinel

Thank you for your interest in contributing! This document outlines the process for contributing code, reporting bugs, and suggesting features.

---

## Code of Conduct

Be respectful and professional. This is a security tool — all contributions must be for defensive, educational, or authorized testing purposes only.

---

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/christos91cy-png/netsentinel/issues) to avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Include: OS version, reproduction steps, expected vs. actual behaviour, and any relevant logs.

### Suggesting Features

Open an issue using the **Feature Request** template. Describe the use case, not just the solution.

### Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Follow the code style:
   - **Rust:** `cargo fmt` and `cargo clippy` must pass with no warnings
   - **TypeScript:** No TypeScript errors (`npx tsc --noEmit`)
   - No unnecessary comments — code should be self-documenting

3. Write a clear commit message following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add CIDR range validation to scanner input
   fix: handle nmap timeout on slow networks
   docs: update installation requirements
   ```

4. Open a pull request against `main`. Fill in the PR template.

---

## Development Setup

```bash
# Install system deps (Ubuntu/Debian)
sudo apt install -y nmap libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and run
git clone https://github.com/christos91cy-png/netsentinel.git
cd netsentinel
npm install
npm run tauri dev
```

---

## Versioning

NetSentinel follows [Semantic Versioning](https://semver.org/):

- `MAJOR` — breaking changes
- `MINOR` — new features, backwards-compatible
- `PATCH` — bug fixes

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
