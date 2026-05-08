import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ScanSummary } from "../types";

interface PortDiff {
  port: number;
  protocol: string;
  service?: string;
  version?: string;
  state: string;
}

interface VulnDiff {
  port?: number;
  script_id: string;
  output: string;
}

interface ScanDiff {
  scan_a_id: number;
  scan_b_id: number;
  scan_a_target: string;
  scan_b_target: string;
  scan_a_date: string;
  scan_b_date: string;
  new_ports: PortDiff[];
  closed_ports: PortDiff[];
  unchanged_ports: PortDiff[];
  new_vulns: VulnDiff[];
  resolved_vulns: VulnDiff[];
}

const card: React.CSSProperties = {
  background: "#161b22",
  border: "1px solid #30363d",
  borderRadius: 8,
  padding: "16px 20px",
  marginBottom: 16,
};

function PortTable({ ports, borderColor }: { ports: PortDiff[]; borderColor: string }) {
  if (ports.length === 0) return <p style={{ color: "#8b949e", fontSize: 13 }}>None</p>;
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
      <thead>
        <tr style={{ color: "#8b949e", textAlign: "left" }}>
          <th style={{ paddingBottom: 6, fontWeight: 500, width: 80 }}>Port</th>
          <th style={{ paddingBottom: 6, fontWeight: 500, width: 80 }}>Protocol</th>
          <th style={{ paddingBottom: 6, fontWeight: 500, width: 80 }}>State</th>
          <th style={{ paddingBottom: 6, fontWeight: 500, width: 140 }}>Service</th>
          <th style={{ paddingBottom: 6, fontWeight: 500 }}>Version</th>
        </tr>
      </thead>
      <tbody>
        {ports.map((p, i) => (
          <tr
            key={i}
            style={{
              borderLeft: `3px solid ${borderColor}`,
              paddingLeft: 8,
              color: "#e6edf3",
            }}
          >
            <td style={{ padding: "4px 8px 4px 10px", fontFamily: "monospace" }}>{p.port}</td>
            <td style={{ padding: "4px 8px", fontFamily: "monospace" }}>{p.protocol}</td>
            <td style={{ padding: "4px 8px" }}>{p.state}</td>
            <td style={{ padding: "4px 8px", color: "#8b949e" }}>{p.service ?? "—"}</td>
            <td style={{ padding: "4px 8px", color: "#8b949e" }}>{p.version ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function VulnTable({ vulns, label }: { vulns: VulnDiff[]; label: string }) {
  if (vulns.length === 0) return null;
  return (
    <div style={{ ...card, marginTop: 16 }}>
      <h3 style={{ color: "#e6edf3", fontSize: 14, marginBottom: 12 }}>{label}</h3>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ color: "#8b949e", textAlign: "left" }}>
            <th style={{ paddingBottom: 6, fontWeight: 500, width: 60 }}>Port</th>
            <th style={{ paddingBottom: 6, fontWeight: 500, width: 200 }}>Script ID</th>
            <th style={{ paddingBottom: 6, fontWeight: 500 }}>Output</th>
          </tr>
        </thead>
        <tbody>
          {vulns.map((v, i) => (
            <tr key={i} style={{ color: "#e6edf3" }}>
              <td style={{ padding: "4px 8px", fontFamily: "monospace" }}>{v.port ?? "—"}</td>
              <td style={{ padding: "4px 8px", fontFamily: "monospace", color: "#58a6ff" }}>
                {v.script_id}
              </td>
              <td
                style={{
                  padding: "4px 8px",
                  color: "#8b949e",
                  maxWidth: 400,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {v.output}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const selectStyle: React.CSSProperties = {
  background: "#161b22",
  color: "#e6edf3",
  border: "1px solid #30363d",
  borderRadius: 6,
  padding: "6px 10px",
  fontSize: 13,
  minWidth: 260,
  cursor: "pointer",
};

export default function Diff() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedA, setSelectedA] = useState<number | null>(null);
  const [selectedB, setSelectedB] = useState<number | null>(null);
  const [result, setResult] = useState<ScanDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<ScanSummary[]>("get_scan_history")
      .then(setScans)
      .catch((e) => setError(String(e)));
  }, []);

  async function handleCompare() {
    if (selectedA === null || selectedB === null) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const diff = await invoke<ScanDiff>("diff_scans", { idA: selectedA, idB: selectedB });
      setResult(diff);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function formatOption(s: ScanSummary) {
    return `#${s.id} ${s.target} (${s.started_at})`;
  }

  return (
    <div style={{ color: "#e6edf3", maxWidth: 900 }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4, color: "#e6edf3" }}>
        Scan Diff
      </h1>
      <p style={{ color: "#8b949e", fontSize: 13, marginBottom: 24 }}>
        Compare two scans to detect port and vulnerability changes.
      </p>

      {/* Controls */}
      <div style={{ ...card, display: "flex", gap: 16, alignItems: "flex-end", flexWrap: "wrap" }}>
        <div>
          <label style={{ display: "block", color: "#8b949e", fontSize: 12, marginBottom: 6 }}>
            Scan A (baseline)
          </label>
          <select
            style={selectStyle}
            value={selectedA ?? ""}
            onChange={(e) => setSelectedA(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">Select scan A…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {formatOption(s)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label style={{ display: "block", color: "#8b949e", fontSize: 12, marginBottom: 6 }}>
            Scan B (compare to)
          </label>
          <select
            style={selectStyle}
            value={selectedB ?? ""}
            onChange={(e) => setSelectedB(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">Select scan B…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {formatOption(s)}
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={handleCompare}
          disabled={selectedA === null || selectedB === null || loading}
          style={{
            background: selectedA !== null && selectedB !== null ? "#00ff88" : "#30363d",
            color: selectedA !== null && selectedB !== null ? "#0f1117" : "#8b949e",
            border: "none",
            borderRadius: 6,
            padding: "8px 20px",
            fontSize: 13,
            fontWeight: 600,
            cursor: selectedA !== null && selectedB !== null ? "pointer" : "not-allowed",
            transition: "background 0.15s",
          }}
        >
          {loading ? "Comparing…" : "Compare"}
        </button>
      </div>

      {error && (
        <div
          style={{
            ...card,
            borderColor: "#f85149",
            color: "#f85149",
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {!result && !loading && !error && (
        <div style={{ color: "#8b949e", fontSize: 14, textAlign: "center", marginTop: 48 }}>
          Select two scans and click Compare
        </div>
      )}

      {result && (
        <>
          {/* Summary header */}
          <div
            style={{
              ...card,
              display: "flex",
              gap: 32,
              flexWrap: "wrap",
              fontSize: 13,
              color: "#8b949e",
            }}
          >
            <div>
              <span style={{ color: "#e6edf3", fontWeight: 600 }}>A:</span>{" "}
              {result.scan_a_target} &mdash; {result.scan_a_date}
            </div>
            <div>
              <span style={{ color: "#e6edf3", fontWeight: 600 }}>B:</span>{" "}
              {result.scan_b_target} &mdash; {result.scan_b_date}
            </div>
            <div style={{ marginLeft: "auto", display: "flex", gap: 20 }}>
              <span style={{ color: "#00ff88" }}>+{result.new_ports.length} new</span>
              <span style={{ color: "#f85149" }}>&minus;{result.closed_ports.length} closed</span>
              <span style={{ color: "#8b949e" }}>{result.unchanged_ports.length} unchanged</span>
            </div>
          </div>

          {/* New Ports */}
          <div style={{ ...card, borderLeftWidth: 3, borderLeftColor: "#00ff88" }}>
            <h3 style={{ color: "#00ff88", fontSize: 14, marginBottom: 12 }}>
              New Ports ({result.new_ports.length})
            </h3>
            <PortTable ports={result.new_ports} borderColor="#00ff88" />
          </div>

          {/* Closed Ports */}
          <div style={{ ...card, borderLeftWidth: 3, borderLeftColor: "#f85149" }}>
            <h3 style={{ color: "#f85149", fontSize: 14, marginBottom: 12 }}>
              Closed Ports ({result.closed_ports.length})
            </h3>
            <PortTable ports={result.closed_ports} borderColor="#f85149" />
          </div>

          {/* Unchanged Ports */}
          <div style={{ ...card, borderLeftWidth: 3, borderLeftColor: "#30363d" }}>
            <h3 style={{ color: "#8b949e", fontSize: 14, marginBottom: 12 }}>
              Unchanged Ports ({result.unchanged_ports.length})
            </h3>
            <PortTable ports={result.unchanged_ports} borderColor="#30363d" />
          </div>

          {/* Vulns */}
          <VulnTable vulns={result.new_vulns} label={`New Vulnerabilities (${result.new_vulns.length})`} />
          <VulnTable
            vulns={result.resolved_vulns}
            label={`Resolved Vulnerabilities (${result.resolved_vulns.length})`}
          />
        </>
      )}
    </div>
  );
}
