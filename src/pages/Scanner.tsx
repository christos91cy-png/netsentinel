import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import ScanResultsTable from "../components/ScanResultsTable";

interface ScanResult {
  target: string;
  scan_type: string;
  started_at: string;
  ports: Port[];
  vulns: Vuln[];
}

interface Port {
  port: number;
  protocol: string;
  state: string;
  service?: string | null;
  version?: string | null;
}

interface Vuln {
  port?: number | null;
  script_id: string;
  output: string;
}

const SCAN_TYPES = [
  { id: "quick", label: "Quick", desc: "Top 100 ports, fast service detection" },
  { id: "full", label: "Full", desc: "All 65535 ports, thorough version scan" },
  { id: "vuln", label: "Vuln", desc: "Run Nmap vulnerability scripts" },
];

export default function Scanner() {
  const [params] = useSearchParams();
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [scanType, setScanType] = useState("quick");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = params.get("target");
    if (t) setTarget(t);
  }, [params]);

  async function startScan() {
    if (!target.trim()) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await invoke<ScanResult>("run_scan", { target: target.trim(), scanType });
      setResult(res);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>Network Scanner</h1>
      <p className="text-sm mb-4" style={{ color: "#8b949e" }}>
        Powered by Nmap. Scan hosts, IP ranges, or CIDR blocks.
      </p>

      {/* Legal warning */}
      <div className="rounded border px-4 py-3 mb-6 flex gap-3" style={{ borderColor: "#e3b34160", background: "#e3b34110" }}>
        <span style={{ color: "#e3b341" }}>⚠</span>
        <p className="text-sm" style={{ color: "#e3b341" }}>
          <strong>WARNING:</strong> Unauthorized network scanning is illegal in many jurisdictions.
          Only scan systems you own or have explicit written permission to scan.
          The authors of this tool are not responsible for misuse.
        </p>
      </div>

      {/* Scan form */}
      <div className="rounded border p-5 mb-6 space-y-4" style={{ borderColor: "#30363d", background: "#161b22" }}>
        <div>
          <label className="block text-xs font-semibold mb-1 uppercase tracking-wide" style={{ color: "#8b949e" }}>
            Target
          </label>
          <input
            className="w-full rounded px-3 py-2 text-sm font-mono border outline-none focus:border-cyan-500"
            style={{ background: "#0f1117", borderColor: "#30363d", color: "#e6edf3" }}
            placeholder="e.g. 192.168.1.1  |  10.0.0.0/24  |  example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>

        <div>
          <label className="block text-xs font-semibold mb-2 uppercase tracking-wide" style={{ color: "#8b949e" }}>
            Scan Type
          </label>
          <div className="flex gap-3">
            {SCAN_TYPES.map((st) => (
              <button
                key={st.id}
                className="flex-1 rounded border px-3 py-2 text-sm text-left transition-colors"
                style={{
                  borderColor: scanType === st.id ? "#00ff88" : "#30363d",
                  background: scanType === st.id ? "#00ff8815" : "transparent",
                  color: scanType === st.id ? "#00ff88" : "#8b949e",
                }}
                onClick={() => setScanType(st.id)}
              >
                <div className="font-semibold">{st.label}</div>
                <div className="text-xs mt-0.5">{st.desc}</div>
              </button>
            ))}
          </div>
        </div>

        <button
          className="w-full py-2.5 rounded font-semibold text-sm transition-opacity disabled:opacity-50"
          style={{ background: "#00ff88", color: "#0f1117" }}
          onClick={startScan}
          disabled={scanning || !target.trim()}
        >
          {scanning ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      {scanning && (
        <div className="rounded border p-6 text-center" style={{ borderColor: "#30363d", background: "#161b22" }}>
          <div className="animate-pulse text-sm" style={{ color: "#00ff88" }}>
            Running nmap against {target}...
          </div>
          <p className="text-xs mt-2" style={{ color: "#8b949e" }}>
            This may take a minute depending on scan type.
          </p>
        </div>
      )}

      {error && (
        <div className="rounded border px-4 py-3" style={{ borderColor: "#f8514940", background: "#f8514910", color: "#f85149" }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && !scanning && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold" style={{ color: "#e6edf3" }}>
              Results for <span style={{ color: "#00bcd4" }}>{result.target}</span>
            </h2>
            <span className="text-xs" style={{ color: "#8b949e" }}>{result.started_at}</span>
          </div>
          <ScanResultsTable ports={result.ports} vulns={result.vulns} />
        </div>
      )}
    </div>
  );
}
