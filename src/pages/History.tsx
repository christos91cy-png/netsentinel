import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import ScanResultsTable from "../components/ScanResultsTable";

interface ScanSummary {
  id: number;
  target: string;
  scan_type: string;
  started_at: string;
  port_count: number;
  vuln_count: number;
}

interface ScanResult {
  target: string;
  scan_type: string;
  started_at: string;
  ports: { port: number; protocol: string; state: string; service?: string | null; version?: string | null }[];
  vulns: { port?: number | null; script_id: string; output: string }[];
}

export default function History() {
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    invoke<ScanSummary[]>("get_scan_history").then(setHistory).catch(() => {});
  }, []);

  async function loadDetail(id: number) {
    setLoading(true);
    try {
      const detail = await invoke<ScanResult | null>("get_scan_detail", { id });
      setSelected(detail);
      setSelectedId(id);
    } catch {
      setSelected(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-5xl">
      <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>Scan History</h1>
      <p className="text-sm mb-6" style={{ color: "#8b949e" }}>All previous scans stored locally.</p>

      {history.length === 0 ? (
        <div className="rounded border p-8 text-center" style={{ borderColor: "#30363d", background: "#161b22" }}>
          <p style={{ color: "#8b949e" }}>No scans yet. Run your first scan from the Scanner page.</p>
        </div>
      ) : (
        <div className="grid grid-cols-5 gap-4">
          <div className="col-span-2 space-y-2">
            {history.map((s) => (
              <div
                key={s.id}
                className="rounded border p-3 cursor-pointer transition-colors"
                style={{
                  borderColor: selectedId === s.id ? "#00ff88" : "#30363d",
                  background: selectedId === s.id ? "#00ff8810" : "#161b22",
                }}
                onClick={() => loadDetail(s.id)}
              >
                <div className="font-mono text-sm font-bold" style={{ color: "#00bcd4" }}>{s.target}</div>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs uppercase" style={{ color: "#8b949e" }}>{s.scan_type}</span>
                  <div className="flex gap-3 text-xs">
                    <span style={{ color: "#e6edf3" }}>{s.port_count}p</span>
                    {s.vuln_count > 0 && (
                      <span style={{ color: "#f85149" }}>{s.vuln_count}v</span>
                    )}
                  </div>
                </div>
                <div className="text-xs mt-1" style={{ color: "#8b949e" }}>{s.started_at}</div>
              </div>
            ))}
          </div>

          <div className="col-span-3">
            {loading && (
              <div className="rounded border p-6 text-center" style={{ borderColor: "#30363d", background: "#161b22" }}>
                <span className="animate-pulse text-sm" style={{ color: "#00ff88" }}>Loading...</span>
              </div>
            )}
            {!loading && selected && (
              <div className="rounded border p-4" style={{ borderColor: "#30363d", background: "#161b22" }}>
                <ScanResultsTable ports={selected.ports} vulns={selected.vulns} />
              </div>
            )}
            {!loading && !selected && (
              <div className="rounded border p-6 text-center" style={{ borderColor: "#30363d", background: "#161b22" }}>
                <p className="text-sm" style={{ color: "#8b949e" }}>Select a scan to view details.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
