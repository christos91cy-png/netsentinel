import { useState, useEffect } from "react";

const STORAGE_KEYS = {
  nvdApiKey: "nvd_api_key",
  shodanApiKey: "shodan_api_key",
  defaultScanType: "default_scan_type",
} as const;

export default function Settings() {
  const [nvdApiKey, setNvdApiKey] = useState("");
  const [shodanApiKey, setShodanApiKey] = useState("");
  const [defaultScanType, setDefaultScanType] = useState("quick");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setNvdApiKey(localStorage.getItem(STORAGE_KEYS.nvdApiKey) ?? "");
    setShodanApiKey(localStorage.getItem(STORAGE_KEYS.shodanApiKey) ?? "");
    setDefaultScanType(localStorage.getItem(STORAGE_KEYS.defaultScanType) ?? "quick");
  }, []);

  function handleSave() {
    localStorage.setItem(STORAGE_KEYS.nvdApiKey, nvdApiKey.trim());
    localStorage.setItem(STORAGE_KEYS.shodanApiKey, shodanApiKey.trim());
    localStorage.setItem(STORAGE_KEYS.defaultScanType, defaultScanType);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  const inputClass =
    "bg-[#0f1117] border border-[#30363d] rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-[#00ff88] w-full";

  const sectionClass =
    "bg-[#161b22] border border-[#30363d] rounded-lg p-5 space-y-5";

  return (
    <div className="max-w-2xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>
          Settings
        </h1>
        <p className="text-sm" style={{ color: "#8b949e" }}>
          Configure API keys, scan defaults, and application preferences.
        </p>
      </div>

      {/* API Keys */}
      <section className={sectionClass}>
        <h2 className="text-sm font-semibold" style={{ color: "#e6edf3" }}>
          API Keys
        </h2>

        <div className="space-y-1.5">
          <label
            className="block text-sm font-medium"
            style={{ color: "#e6edf3" }}
            htmlFor="nvd-api-key"
          >
            NVD API Key
          </label>
          <input
            id="nvd-api-key"
            type="password"
            className={inputClass}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            value={nvdApiKey}
            onChange={(e) => setNvdApiKey(e.target.value)}
            autoComplete="off"
          />
          <p className="text-xs" style={{ color: "#8b949e" }}>
            Increases CVE search rate limit from 5 to 50 req/30s. Get one free
            at{" "}
            <a
              href="https://nvd.nist.gov/developers/request-an-api-key"
              target="_blank"
              rel="noreferrer"
              style={{ color: "#00bcd4" }}
              className="hover:underline"
            >
              nvd.nist.gov
            </a>
          </p>
        </div>

        <div className="space-y-1.5">
          <label
            className="block text-sm font-medium"
            style={{ color: "#e6edf3" }}
            htmlFor="shodan-api-key"
          >
            Shodan API Key
          </label>
          <input
            id="shodan-api-key"
            type="password"
            className={inputClass}
            placeholder="your-shodan-api-key"
            value={shodanApiKey}
            onChange={(e) => setShodanApiKey(e.target.value)}
            autoComplete="off"
          />
          <p className="text-xs" style={{ color: "#8b949e" }}>
            Unlocks full Shodan host data. Get one at{" "}
            <a
              href="https://shodan.io"
              target="_blank"
              rel="noreferrer"
              style={{ color: "#00bcd4" }}
              className="hover:underline"
            >
              shodan.io
            </a>
          </p>
        </div>
      </section>

      {/* Scan Defaults */}
      <section className={sectionClass}>
        <h2 className="text-sm font-semibold" style={{ color: "#e6edf3" }}>
          Scan Defaults
        </h2>

        <div className="space-y-1.5">
          <label
            className="block text-sm font-medium"
            style={{ color: "#e6edf3" }}
            htmlFor="default-scan-type"
          >
            Default Scan Type
          </label>
          <select
            id="default-scan-type"
            className={inputClass}
            value={defaultScanType}
            onChange={(e) => setDefaultScanType(e.target.value)}
            style={{
              background: "#0f1117",
              appearance: "auto",
            }}
          >
            <option value="quick">Quick — top 100 ports, fast</option>
            <option value="full">Full — all 65535 ports</option>
            <option value="vuln">Vuln — CVE detection enabled</option>
            <option value="discover">Discover — host discovery only</option>
          </select>
          <p className="text-xs" style={{ color: "#8b949e" }}>
            Pre-selected scan type when opening the Scanner page.
          </p>
        </div>
      </section>

      {/* Save button */}
      <div>
        <button
          onClick={handleSave}
          className="px-5 py-2 rounded text-sm font-semibold transition-colors"
          style={{
            background: saved ? "#00ff8820" : "#00ff8815",
            color: saved ? "#00ff88" : "#00ff88",
            border: "1px solid #00ff8840",
          }}
        >
          {saved ? "Saved!" : "Save Settings"}
        </button>
      </div>

      {/* About */}
      <section className={sectionClass}>
        <h2 className="text-sm font-semibold" style={{ color: "#e6edf3" }}>
          About
        </h2>
        <div className="space-y-2 text-sm" style={{ color: "#8b949e" }}>
          <div className="flex items-center gap-2">
            <span className="font-bold" style={{ color: "#00ff88" }}>
              NET<span style={{ color: "#00bcd4" }}>SENTINEL</span>
            </span>
            <span style={{ color: "#8b949e" }}>v0.1.0</span>
          </div>
          <p>
            A local-first network vulnerability scanner built with Tauri, Rust,
            and React. No data leaves your machine.
          </p>
          <a
            href="https://github.com/christos91cy-png/netsentinel"
            target="_blank"
            rel="noreferrer"
            style={{ color: "#00bcd4" }}
            className="hover:underline inline-block"
          >
            GitHub Repository
          </a>
        </div>
      </section>
    </div>
  );
}
