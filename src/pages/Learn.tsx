import { useState } from "react";

const TOPICS = [
  {
    id: "cvss",
    title: "CVSS Scores & Severity",
    icon: "◎",
    content: `
**What is CVSS?**
The Common Vulnerability Scoring System (CVSS) is an open standard for rating the severity of security vulnerabilities on a scale of 0.0–10.0.

**Severity Levels**
| Score | Severity | Meaning |
|-------|----------|---------|
| 9.0–10.0 | CRITICAL | Exploit is trivial, no auth needed, full system compromise |
| 7.0–8.9 | HIGH | Significant impact, often remotely exploitable |
| 4.0–6.9 | MEDIUM | Harder to exploit or limited impact |
| 0.1–3.9 | LOW | Requires local access or unusual conditions |
| 0.0 | NONE | Informational only |

**CVSSv3 Base Metrics**
- **Attack Vector (AV):** Network / Adjacent / Local / Physical
- **Attack Complexity (AC):** Low / High
- **Privileges Required (PR):** None / Low / High
- **User Interaction (UI):** None / Required
- **Scope (S):** Unchanged / Changed
- **Confidentiality / Integrity / Availability (C/I/A):** None / Low / High
    `.trim()
  },
  {
    id: "scanning",
    title: "Network Scanning Basics",
    icon: "◈",
    content: `
**What is port scanning?**
Port scanning probes a host's TCP/UDP ports to discover which services are listening. Each open port reveals a potential attack surface.

**Common Nmap Scan Types**
- **SYN scan (-sS):** Sends a TCP SYN, doesn't complete the handshake. Fast and stealthy.
- **Version detection (-sV):** Probes open ports to determine service name and version.
- **Script scan (--script vuln):** Runs NSE (Nmap Scripting Engine) scripts to detect known vulnerabilities.
- **ICMP ping (-sn):** Host discovery only, no port scanning.

**Reading Results**
- **open** — a service is actively accepting connections
- **closed** — port is reachable but no service is listening
- **filtered** — a firewall is blocking the probe; state is unknown

**Legal Reminder**
Always obtain written authorization before scanning any network you do not own. Unauthorized scanning can violate laws such as the Computer Fraud and Abuse Act (USA), Computer Misuse Act (UK), and equivalent laws in other jurisdictions.
    `.trim()
  },
  {
    id: "vuln-types",
    title: "Common Vulnerability Types",
    icon: "⚠",
    content: `
**Injection Attacks**
- **SQL Injection:** Attacker inserts SQL into input fields to manipulate database queries, potentially dumping all data or bypassing authentication.
- **Command Injection:** User input is passed unsanitized to a shell command, giving the attacker arbitrary code execution.
- **LDAP / XPath / NoSQL Injection:** Same concept applied to other query languages.

**Cross-Site Scripting (XSS)**
Malicious scripts are injected into web pages viewed by other users. Can steal session tokens, credentials, or redirect users.
- **Reflected XSS:** Payload is in the request URL.
- **Stored XSS:** Payload is saved in the database and served to all visitors.

**Buffer Overflow**
Writing more data into a buffer than it can hold overwrites adjacent memory, potentially hijacking program execution. Common in C/C++ applications.

**Man-in-the-Middle (MitM)**
Attacker intercepts traffic between two parties—often by ARP poisoning on a LAN or via a rogue Wi-Fi access point.

**Broken Authentication**
Weak password policies, missing MFA, insecure session tokens, or predictable token generation allow attackers to hijack accounts.

**CVE vs. CWE**
- **CVE (Common Vulnerabilities and Exposures):** A specific vulnerability in a specific product version (e.g., CVE-2021-44228 = Log4Shell).
- **CWE (Common Weakness Enumeration):** A category of vulnerability class (e.g., CWE-89 = SQL Injection).
    `.trim()
  },
  {
    id: "responsible",
    title: "Responsible Disclosure",
    icon: "⬡",
    content: `
**What is responsible disclosure?**
When a security researcher finds a vulnerability, responsible disclosure means privately notifying the affected vendor and giving them time to fix it before publishing details publicly. This protects users while ensuring the issue is eventually made public.

**The Standard Process**
1. **Discover** the vulnerability and document it clearly (affected versions, PoC steps, impact).
2. **Contact** the vendor's security team (look for security.txt, HackerOne, or a dedicated security email).
3. **Agree on a timeline** — typically 90 days (Google Project Zero standard). Some vendors ask for an extension.
4. **Vendor releases a patch.**
5. **Publish** a CVE entry and your research after the patch is widely deployed.

**Bug Bounty Programs**
Many organizations offer monetary rewards for reported vulnerabilities:
- HackerOne, Bugcrowd — platforms connecting researchers and companies
- Some pay from hundreds to hundreds of thousands of dollars depending on severity

**Key Principle**
Never exploit a vulnerability beyond what is needed to prove it exists. Accessing or exfiltrating real user data, even to demonstrate a flaw, can turn your research into a crime.
    `.trim()
  },
];

function renderMarkdown(text: string) {
  // Simple renderer for bold and tables
  const lines = text.split("\n");
  return lines.map((line, i) => {
    if (line.startsWith("**") && line.endsWith("**") && line.length > 4) {
      return <h3 key={i} className="text-sm font-bold mt-4 mb-1" style={{ color: "#00bcd4" }}>{line.slice(2, -2)}</h3>;
    }
    if (line.startsWith("- **")) {
      const match = line.match(/^- \*\*(.+?)\*\*:? ?(.*)/);
      if (match) {
        return (
          <p key={i} className="text-sm mb-1 pl-3">
            <span className="font-bold" style={{ color: "#00ff88" }}>{match[1]}:</span>{" "}
            <span style={{ color: "#e6edf3" }}>{match[2]}</span>
          </p>
        );
      }
    }
    if (line.startsWith("- ")) {
      return <p key={i} className="text-sm mb-0.5 pl-3" style={{ color: "#e6edf3" }}>• {line.slice(2)}</p>;
    }
    if (line.startsWith("|")) {
      return null; // skip table lines for simplicity
    }
    if (line.startsWith("#")) {
      return null;
    }
    if (line.trim() === "") return <div key={i} className="h-2" />;
    return <p key={i} className="text-sm mb-1" style={{ color: "#e6edf3" }}>{line}</p>;
  });
}

export default function Learn() {
  const [active, setActive] = useState(TOPICS[0].id);
  const topic = TOPICS.find((t) => t.id === active) ?? TOPICS[0];

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>Learn</h1>
      <p className="text-sm mb-6" style={{ color: "#8b949e" }}>
        Security concepts, vulnerability types, and best practices.
      </p>

      <div className="grid grid-cols-4 gap-4">
        <div className="col-span-1 space-y-1">
          {TOPICS.map((t) => (
            <button
              key={t.id}
              className="w-full text-left px-3 py-2.5 rounded text-sm transition-colors flex items-center gap-2"
              style={{
                background: active === t.id ? "#00ff8815" : "transparent",
                color: active === t.id ? "#00ff88" : "#8b949e",
                border: active === t.id ? "1px solid #00ff8830" : "1px solid transparent",
              }}
              onClick={() => setActive(t.id)}
            >
              <span>{t.icon}</span>
              <span className="leading-tight">{t.title}</span>
            </button>
          ))}
        </div>

        <div
          className="col-span-3 rounded border p-5"
          style={{ borderColor: "#30363d", background: "#161b22" }}
        >
          <h2 className="text-base font-bold mb-4" style={{ color: "#e6edf3" }}>{topic.title}</h2>
          <div>{renderMarkdown(topic.content)}</div>
        </div>
      </div>
    </div>
  );
}
