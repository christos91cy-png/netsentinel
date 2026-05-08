import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import ScanResultsTable from "../components/ScanResultsTable";
import ThreatIntelPanel from "../components/ThreatIntelPanel";
import "../print.css";

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
  const [exportMsg, setExportMsg] = useState<{ text: string; error: boolean } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [showThreatIntel, setShowThreatIntel] = useState(false);

  useEffect(() => {
    invoke<ScanSummary[]>("get_scan_history")
      .then(setHistory)
      .catch((err) => console.error("Failed to load scan history:", err));
  }, []);

  async function loadDetail(id: number) {
    setLoading(true);
    setExportMsg(null);
    setShowThreatIntel(false);
    const timeout = setTimeout(() => {
      setLoading(false);
      setSelected(null);
      console.error("get_scan_detail timed out");
    }, 10000);
    try {
      const detail = await invoke<ScanResult | null>("get_scan_detail", { id });
      clearTimeout(timeout);
      setSelected(detail);
      setSelectedId(id);
    } catch (err) {
      clearTimeout(timeout);
      console.error("Failed to load scan detail:", err);
      setSelected(null);
    } finally {
      setLoading(false);
    }
  }

  async function handleExportJson(id: number) {
    setExportMsg(null);
    try {
      const path = await invoke<string>("export_scan_json", { id });
      setExportMsg({ text: `Saved to ${path}`, error: false });
    } catch (err) {
      setExportMsg({ text: `Export failed: ${err}`, error: true });
    }
  }

  async function handleExportCsv(id: number) {
    setExportMsg(null);
    try {
      const path = await invoke<string>("export_scan_csv", { id });
      setExportMsg({ text: `Saved to ${path}`, error: false });
    } catch (err) {
      setExportMsg({ text: `Export failed: ${err}`, error: true });
    }
  }

  async function handleDelete(id: number) {
    try {
      await invoke("delete_scan", { id });
      setHistory((h) => h.filter((s) => s.id !== id));
      if (selectedId === id) { setSelected(null); setSelectedId(null); }
      setConfirmDelete(null);
    } catch (err) {
      console.error("Failed to delete scan:", err);
    }
  }

  return (
    <div className="w-full">
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
              <div key={s.id} className="relative group">
                <button
                  className="w-full text-left rounded border p-3 cursor-pointer transition-colors focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
                  style={{
                    borderColor: selectedId === s.id ? "#00ff88" : "#30363d",
                    background: selectedId === s.id ? "#00ff8810" : "#161b22",
                  }}
                  onClick={() => loadDetail(s.id)}
                >
                  <div className="font-mono text-sm font-bold pr-6" style={{ color: "#00bcd4" }}>{s.target}</div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs uppercase" style={{ color: "#8b949e" }}>{s.scan_type}</span>
                    <div className="flex gap-3 text-xs">
                      <span style={{ color: "#e6edf3" }}>{s.port_count}p</span>
                      {s.vuln_count > 0 && <span style={{ color: "#f85149" }}>{s.vuln_count}v</span>}
                    </div>
                  </div>
                  <div className="text-xs mt-1" style={{ color: "#8b949e" }}>{s.started_at}</div>
                </button>
                {confirmDelete === s.id ? (
                  <div className="absolute top-2 right-2 flex gap-1">
                    <button
                      className="text-xs px-2 py-0.5 rounded bg-[#f85149] text-white hover:bg-red-400"
                      onClick={() => handleDelete(s.id)}
                    >Yes</button>
                    <button
                      className="text-xs px-2 py-0.5 rounded border border-[#30363d] text-[#8b949e] hover:text-white"
                      onClick={() => setConfirmDelete(null)}
                    >No</button>
                  </div>
                ) : (
                  <button
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 text-xs px-2 py-0.5 rounded border border-[#30363d] text-[#8b949e] hover:text-[#f85149] hover:border-[#f85149] transition-all"
                    onClick={(e) => { e.stopPropagation(); setConfirmDelete(s.id); }}
                    aria-label={`Delete scan ${s.id}`}
                  >✕</button>
                )}
              </div>
            ))}
          </div>

          <div className="col-span-3">
            {loading && (
              <div className="rounded border p-6 text-center" style={{ borderColor: "#30363d", background: "#161b22" }}>
                <span className="animate-pulse text-sm" style={{ color: "#00ff88" }}>Loading...</span>
              </div>
            )}
            {!loading && selected && selectedId !== null && (
              <div className="rounded border p-4" style={{ borderColor: "#30363d", background: "#161b22" }}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "#8b949e" }}>
                    Scan #{selectedId}
                  </span>
                  <div className="flex gap-2">
                    <button
                      className="text-xs px-3 py-1 rounded border border-[#30363d] text-[#8b949e] hover:text-white hover:border-[#484f58] transition-colors"
                      onClick={() => handleExportJson(selectedId)}
                      aria-label={`Export scan ${selectedId} as JSON`}
                    >
                      Export JSON
                    </button>
                    <button
                      className="text-xs px-3 py-1 rounded border border-[#30363d] text-[#8b949e] hover:text-white hover:border-[#484f58] transition-colors"
                      onClick={() => handleExportCsv(selectedId)}
                      aria-label={`Export scan ${selectedId} as CSV`}
                    >
                      Export CSV
                    </button>
                    <button
                      className="text-xs px-3 py-1 rounded border border-[#30363d] text-[#8b949e] hover:text-white hover:border-[#484f58] transition-colors"
                      onClick={() => window.open(`/report?id=${selectedId}`, "_blank")}
                      aria-label={`Print report for scan ${selectedId}`}
                    >
                      Print Report
                    </button>
                    <button
                      className="text-xs px-3 py-1 rounded border transition-colors"
                      style={{
                        borderColor: showThreatIntel ? "#f85149" : "#30363d",
                        color: showThreatIntel ? "#f85149" : "#8b949e",
                      }}
                      onClick={() => setShowThreatIntel((v) => !v)}
                      aria-label="Toggle threat intelligence panel"
                    >
                      Threat Intel
                    </button>
                  </div>
                </div>
                {exportMsg && (
                  <p className="text-xs mb-3" style={{ color: exportMsg.error ? "#f85149" : "#00ff88" }}>{exportMsg.text}</p>
                )}
                <ScanResultsTable ports={selected.ports} vulns={selected.vulns} scan_type={selected.scan_type} />
                {showThreatIntel && (
                  <ThreatIntelPanel
                    cveIds={selected.vulns
                      .map((v) => v.script_id)
                      .filter((id) => id.startsWith("CVE-"))}
                  />
                )}
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
