import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import ScanResultsTable from "../components/ScanResultsTable";
import { useScanStore } from "../store/scanStore";
import { useToast } from "../components/Toast";
import { ScanResult, ShodanHost } from "../types";

const SCAN_TYPES = [
  { id: "quick", label: "Quick", desc: "Top 100 ports, fast service detection", est: "~5s" },
  { id: "full", label: "Full", desc: "All 65535 ports, thorough version scan", est: "~3-8min" },
  { id: "vuln", label: "Vuln", desc: "Run Nmap vulnerability scripts", est: "~5-15min" },
  { id: "discover", label: "Discover", desc: "Find live hosts on network", est: "~5-30s" },
];

function isPrivateOrLocalhost(target: string): boolean {
  const t = target.trim().toLowerCase();
  if (t === "localhost" || t === "127.0.0.1" || t === "::1") return true;
  if (t.startsWith("192.168.") || t.startsWith("10.") || t.startsWith("172.")) return true;
  return false;
}

function triggerDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function formatElapsed(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export default function Scanner() {
  const [params] = useSearchParams();
  const [target, setTarget] = useState(params.get("target") ?? "");
  const [scanType, setScanType] = useState(() => localStorage.getItem("default_scan_type") ?? "quick");
  const [resultId, setResultId] = useState<number | null>(null);
  const [shodanData, setShodanData] = useState<ShodanHost | null>(null);
  const [shodanOpen, setShodanOpen] = useState(true);
  const [exportError, setExportError] = useState<string | null>(null);

  const { isScanning, progress, currentResult, error, setScanning, setProgress, setResult, setError, reset } =
    useScanStore();
  const { addToast } = useToast();

  useEffect(() => {
    const t = params.get("target");
    if (t) setTarget(t);
  }, [params]);

  // Listen to Tauri scan events
  useEffect(() => {
    const unlisten: Array<() => void> = [];

    (async () => {
      unlisten.push(
        await listen<{ percent: number; phase: string; elapsed_secs: number }>("scan:progress", (e) => {
          setProgress(e.payload);
        })
      );
      unlisten.push(
        await listen("scan:start", () => {
          reset();
          setScanning(true);
        })
      );
      unlisten.push(
        await listen<ScanResult>("scan:complete", (e) => {
          setScanning(false);
          setResult(e.payload);
        })
      );
      unlisten.push(
        await listen<{ error: string }>("scan:error", (e) => {
          setScanning(false);
          setError(e.payload.error);
        })
      );
    })();

    return () => {
      unlisten.forEach((fn) => fn());
    };
  }, [setProgress, setScanning, setResult, setError, reset]);

  // When currentResult changes (after a scan completes), fetch result ID and Shodan data
  useEffect(() => {
    if (!currentResult) return;

    const res = currentResult;

    addToast({
      type: "success",
      title: "Scan complete",
      message: `Found ${res.ports.length} ports on ${res.target}`,
    });

    // Try to get the scan ID from history for export
    (async () => {
      try {
        const history = await invoke<{ id: number; target: string; started_at: string }[]>("get_scan_history");
        const match = history.find((h) => h.target === res.target && h.started_at === res.started_at);
        if (match) setResultId(match.id);
        else if (history.length > 0) setResultId(history[0].id);
      } catch {
        // export buttons simply won't appear if ID is unavailable
      }
    })();

    // Attempt Shodan lookup for non-private targets
    if (!isPrivateOrLocalhost(res.target)) {
      (async () => {
        try {
          const shodan = await invoke<ShodanHost>("lookup_shodan", { ip: res.target });
          setShodanData(shodan);
          setShodanOpen(true);
        } catch {
          // Silently ignore — Shodan may not have data for this IP
        }
      })();
    }
  // addToast is stable (useCallback), currentResult identity changes on each new scan
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentResult]);

  async function startScan() {
    if (!target.trim()) return;
    reset();
    setScanning(true);
    setError(null);
    setResult(null);
    setResultId(null);
    setShodanData(null);
    setExportError(null);
    try {
      await invoke("run_scan", { target: target.trim(), scanType });
      // result + setScanning(false) handled by scan:complete event listener
    } catch (e: unknown) {
      setScanning(false);
      setError(String(e));
    }
  }

  async function handleAbort() {
    try {
      await invoke("cancel_scan");
    } catch {
      // ignore
    }
    setScanning(false);
  }

  async function handleExportJson() {
    if (resultId === null) return;
    setExportError(null);
    try {
      const content = await invoke<string>("export_scan_json", { id: resultId });
      triggerDownload(content, `scan-${resultId}.json`, "application/json");
    } catch (err) {
      console.error("Failed to export JSON:", err);
      setExportError("Export failed. Please try again.");
    }
  }

  async function handleExportCsv() {
    if (resultId === null) return;
    setExportError(null);
    try {
      const content = await invoke<string>("export_scan_csv", { id: resultId });
      triggerDownload(content, `scan-${resultId}.csv`, "text/csv");
    } catch (err) {
      console.error("Failed to export CSV:", err);
      setExportError("Export failed. Please try again.");
    }
  }

  return (
    <div className="w-full">
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
          <label
            htmlFor="scan-target"
            className="block text-xs font-semibold mb-1 uppercase tracking-wide"
            style={{ color: "#8b949e" }}
          >
            Target
          </label>
          <input
            id="scan-target"
            aria-label="Scan target — enter an IP address, hostname, IP range, or CIDR block"
            className="w-full rounded px-3 py-2 text-sm font-mono border outline-none focus:border-cyan-500"
            style={{ background: "#0f1117", borderColor: "#30363d", color: "#e6edf3" }}
            placeholder="e.g. 192.168.1.1  |  10.0.0.0/24  |  example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && target.trim() && !isScanning) startScan();
            }}
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
                className="flex-1 rounded border px-3 py-2 text-sm text-left transition-colors focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
                style={{
                  borderColor: scanType === st.id ? "#00ff88" : "#30363d",
                  background: scanType === st.id ? "#00ff8815" : "transparent",
                  color: scanType === st.id ? "#00ff88" : "#8b949e",
                }}
                onClick={() => setScanType(st.id)}
                aria-pressed={scanType === st.id}
              >
                <div className="font-semibold">{st.label}</div>
                <div className="text-xs mt-0.5">{st.desc}</div>
                <div className="text-xs mt-0.5 opacity-70">{st.est}</div>
              </button>
            ))}
          </div>
        </div>

        <button
          className="w-full py-2.5 rounded font-semibold text-sm transition-opacity disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
          style={{ background: "#00ff88", color: "#0f1117" }}
          onClick={startScan}
          disabled={isScanning || !target.trim()}
        >
          {isScanning ? "Scanning..." : "Start Scan"}
        </button>
      </div>

      {/* Progress panel */}
      {isScanning && (
        <div className="rounded border p-5 mb-6 space-y-3" style={{ borderColor: "#30363d", background: "#161b22" }}>
          {/* Progress bar */}
          <div className="w-full rounded-full overflow-hidden" style={{ background: "#21262d", height: 6 }}>
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{ width: `${progress?.percent ?? 0}%`, background: "#00ff88" }}
            />
          </div>

          {/* Phase label */}
          <p className="text-sm" style={{ color: "#00ff88" }}>
            {progress
              ? `${progress.phase} — ${Math.round(progress.percent)}% complete`
              : `Running nmap against ${target}...`}
          </p>

          {/* Elapsed + abort row */}
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono" style={{ color: "#8b949e" }}>
              {progress ? `Elapsed: ${formatElapsed(progress.elapsed_secs)}` : "Starting…"}
            </span>
            <button
              className="text-xs px-3 py-1 rounded border transition-colors focus-visible:ring-2 focus-visible:ring-[#f85149] focus-visible:outline-none"
              style={{ borderColor: "#f8514960", color: "#f85149" }}
              onClick={handleAbort}
              aria-label="Abort scan"
            >
              Abort
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="rounded border px-4 py-3 mb-6" style={{ borderColor: "#f8514940", background: "#f8514910", color: "#f85149" }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {currentResult && !isScanning && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold" style={{ color: "#e6edf3" }}>
              Results for <span style={{ color: "#00bcd4" }}>{currentResult.target}</span>
            </h2>
            <span className="text-xs" style={{ color: "#8b949e" }}>{currentResult.started_at}</span>
          </div>

          <ScanResultsTable ports={currentResult.ports} vulns={currentResult.vulns} scan_type={currentResult.scan_type} os_guess={currentResult.os_guess} />

          {/* Export buttons */}
          {resultId !== null && (
            <div className="flex items-center gap-2 mt-4">
              <span className="text-xs" style={{ color: "#8b949e" }}>Export:</span>
              <button
                className="text-xs px-3 py-1 rounded border border-[#30363d] text-[#8b949e] hover:text-white hover:border-[#484f58] transition-colors focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
                onClick={handleExportJson}
                aria-label="Export scan results as JSON"
              >
                Export JSON
              </button>
              <button
                className="text-xs px-3 py-1 rounded border border-[#30363d] text-[#8b949e] hover:text-white hover:border-[#484f58] transition-colors focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
                onClick={handleExportCsv}
                aria-label="Export scan results as CSV"
              >
                Export CSV
              </button>
              {exportError && (
                <span className="text-xs" style={{ color: "#f85149" }}>{exportError}</span>
              )}
            </div>
          )}

          {/* Shodan panel */}
          {shodanData && (
            <div
              className="mt-6 rounded border"
              style={{
                borderColor: "#30363d",
                background: "#161b22",
                borderLeft: "3px solid #00bcd4",
              }}
            >
              <button
                className="w-full flex items-center justify-between px-4 py-3 focus-visible:ring-2 focus-visible:ring-[#00ff88] focus-visible:outline-none"
                onClick={() => setShodanOpen((o) => !o)}
                aria-expanded={shodanOpen}
                aria-controls="shodan-panel-body"
              >
                <span className="text-sm font-semibold" style={{ color: "#00bcd4" }}>
                  External View (Shodan)
                </span>
                <span className="text-xs" style={{ color: "#8b949e" }}>
                  {shodanOpen ? "▲ collapse" : "▼ expand"}
                </span>
              </button>

              {shodanOpen && (
                <div id="shodan-panel-body" className="px-4 pb-4 space-y-2">
                  <div className="text-xs" style={{ color: "#8b949e" }}>
                    <span style={{ color: "#e6edf3" }}>Open ports:</span>{" "}
                    {shodanData.ports.length > 0
                      ? shodanData.ports.join(", ")
                      : <span style={{ color: "#8b949e" }}>None reported</span>}
                  </div>
                  {shodanData.hostnames.length > 0 && (
                    <div className="text-xs" style={{ color: "#8b949e" }}>
                      <span style={{ color: "#e6edf3" }}>Hostnames:</span>{" "}
                      {shodanData.hostnames.join(", ")}
                    </div>
                  )}
                  {shodanData.tags.length > 0 && (
                    <div className="text-xs" style={{ color: "#8b949e" }}>
                      <span style={{ color: "#e6edf3" }}>Tags:</span>{" "}
                      {shodanData.tags.join(", ")}
                    </div>
                  )}
                  {shodanData.cpes.length > 0 && (
                    <div className="text-xs" style={{ color: "#8b949e" }}>
                      <span style={{ color: "#e6edf3" }}>CPEs:</span>{" "}
                      {shodanData.cpes.join(", ")}
                    </div>
                  )}
                  {shodanData.vulns.length > 0 && (
                    <div className="text-xs">
                      <span style={{ color: "#e6edf3" }}>Known CVEs:</span>{" "}
                      <span style={{ color: "#f85149" }}>{shodanData.vulns.join(", ")}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
