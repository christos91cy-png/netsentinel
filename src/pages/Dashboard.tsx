import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";

interface ScanSummary {
  id: number;
  target: string;
  scan_type: string;
  started_at: string;
  port_count: number;
  vuln_count: number;
}

export default function Dashboard() {
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [quickTarget, setQuickTarget] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    invoke<ScanSummary[]>("get_scan_history").then(setHistory).catch(() => {});
  }, []);

  const totalPorts = history.reduce((a, s) => a + s.port_count, 0);
  const totalVulns = history.reduce((a, s) => a + s.vuln_count, 0);

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>Dashboard</h1>
      <p className="text-sm mb-6" style={{ color: "#8b949e" }}>
        Network vulnerability scanner, CVE tracker, and security reference.
      </p>

      <div className="grid grid-cols-3 gap-4 mb-8">
        {[
          { label: "Total Scans", value: history.length, color: "#00bcd4" },
          { label: "Open Ports Found", value: totalPorts, color: "#e3b341" },
          { label: "Vulnerabilities", value: totalVulns, color: "#f85149" },
        ].map((stat) => (
          <div key={stat.label} className="rounded border p-4" style={{ borderColor: "#30363d", background: "#161b22" }}>
            <p className="text-xs uppercase tracking-wide mb-1" style={{ color: "#8b949e" }}>{stat.label}</p>
            <p className="text-3xl font-bold font-mono" style={{ color: stat.color }}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="rounded border p-5 mb-6" style={{ borderColor: "#30363d", background: "#161b22" }}>
        <h2 className="text-sm font-semibold mb-3" style={{ color: "#e6edf3" }}>Quick Scan</h2>
        <div className="flex gap-2">
          <input
            className="flex-1 rounded px-3 py-2 text-sm font-mono border outline-none focus:border-cyan-500"
            style={{ background: "#0f1117", borderColor: "#30363d", color: "#e6edf3" }}
            placeholder="192.168.1.1 or hostname"
            value={quickTarget}
            onChange={(e) => setQuickTarget(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && quickTarget.trim()) {
                navigate(`/scanner?target=${encodeURIComponent(quickTarget.trim())}`);
              }
            }}
          />
          <button
            className="px-4 py-2 rounded text-sm font-semibold transition-colors"
            style={{ background: "#00ff8820", color: "#00ff88", border: "1px solid #00ff8840" }}
            onClick={() => {
              if (quickTarget.trim()) navigate(`/scanner?target=${encodeURIComponent(quickTarget.trim())}`);
            }}
          >
            Scan
          </button>
        </div>
      </div>

      {history.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold mb-3" style={{ color: "#e6edf3" }}>Recent Scans</h2>
          <div className="space-y-2">
            {history.slice(0, 5).map((s) => (
              <div
                key={s.id}
                className="flex items-center justify-between rounded border px-4 py-3 cursor-pointer hover:border-gray-500 transition-colors"
                style={{ borderColor: "#30363d", background: "#161b22" }}
                onClick={() => navigate("/history")}
              >
                <div>
                  <span className="font-mono text-sm" style={{ color: "#00bcd4" }}>{s.target}</span>
                  <span className="ml-3 text-xs uppercase" style={{ color: "#8b949e" }}>{s.scan_type}</span>
                </div>
                <div className="flex gap-4 text-xs" style={{ color: "#8b949e" }}>
                  <span>{s.port_count} ports</span>
                  {s.vuln_count > 0 && (
                    <span style={{ color: "#f85149" }}>{s.vuln_count} vulns</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
