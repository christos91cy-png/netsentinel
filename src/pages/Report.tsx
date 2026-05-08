// Route: add <Route path="/report" element={<ReportPage />} /> to App.tsx
// and: const ReportPage = React.lazy(() => import("./pages/Report"));

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import "../print.css";

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

interface ScanResult {
  target: string;
  scan_type: string;
  started_at: string;
  ports: Port[];
  vulns: Vuln[];
}

export default function Report() {
  const [searchParams] = useSearchParams();
  const id = searchParams.get("id");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      setError("No scan ID provided.");
      return;
    }
    invoke<ScanResult>("get_scan_detail", { id: Number(id) })
      .then((data) => {
        setScan(data);
        setTimeout(() => window.print(), 300);
      })
      .catch((err) => {
        setError(String(err));
      });
  }, [id]);

  if (error) {
    return (
      <div style={{ padding: "2rem", fontFamily: "monospace", color: "#f85149" }}>
        <p>Error loading report: {error}</p>
      </div>
    );
  }

  if (!scan) {
    return (
      <div style={{ padding: "2rem", fontFamily: "monospace", color: "#555" }}>
        <p>Loading report...</p>
      </div>
    );
  }

  const openPorts = scan.ports.filter((p) => p.state === "open");
  const generatedAt = new Date().toLocaleString();

  return (
    <div
      style={{
        background: "white",
        color: "black",
        fontFamily: "monospace",
        padding: "2rem",
        maxWidth: "794px",
        margin: "0 auto",
      }}
    >
      {/* Print button — hidden when printing */}
      <div className="no-print" style={{ marginBottom: "1.5rem" }}>
        <button
          onClick={() => window.print()}
          style={{
            padding: "6px 16px",
            fontSize: "13px",
            border: "1px solid #ccc",
            borderRadius: "4px",
            background: "#f0f0f0",
            cursor: "pointer",
          }}
        >
          Print
        </button>
      </div>

      {/* Report header */}
      <h1 style={{ fontSize: "22px", fontWeight: "bold", marginBottom: "4px" }}>
        NetSentinel Security Report
      </h1>
      <div
        className="report-meta"
        style={{ fontSize: "12px", color: "#555", marginBottom: "20px" }}
      >
        {scan.started_at} &nbsp;|&nbsp; Target: {scan.target} &nbsp;|&nbsp; Scan type:{" "}
        {scan.scan_type}
      </div>

      {/* Open Ports section */}
      <div
        className="section-title"
        style={{
          fontSize: "14px",
          fontWeight: "bold",
          margin: "16px 0 6px",
          borderBottom: "2px solid #333",
          paddingBottom: "2px",
        }}
      >
        OPEN PORTS
      </div>

      {openPorts.length === 0 ? (
        <p style={{ fontSize: "12px", color: "#555" }}>No open ports found.</p>
      ) : (
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th
                style={{
                  border: "1px solid #ccc",
                  padding: "4px 8px",
                  textAlign: "left",
                  fontSize: "11px",
                  background: "#f0f0f0",
                  fontWeight: "bold",
                }}
              >
                PORT
              </th>
              <th
                style={{
                  border: "1px solid #ccc",
                  padding: "4px 8px",
                  textAlign: "left",
                  fontSize: "11px",
                  background: "#f0f0f0",
                  fontWeight: "bold",
                }}
              >
                PROTOCOL
              </th>
              <th
                style={{
                  border: "1px solid #ccc",
                  padding: "4px 8px",
                  textAlign: "left",
                  fontSize: "11px",
                  background: "#f0f0f0",
                  fontWeight: "bold",
                }}
              >
                SERVICE
              </th>
              <th
                style={{
                  border: "1px solid #ccc",
                  padding: "4px 8px",
                  textAlign: "left",
                  fontSize: "11px",
                  background: "#f0f0f0",
                  fontWeight: "bold",
                }}
              >
                VERSION
              </th>
            </tr>
          </thead>
          <tbody>
            {openPorts.map((p) => (
              <tr key={`${p.port}/${p.protocol}`}>
                <td
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    fontSize: "11px",
                  }}
                >
                  {p.port}/{p.protocol}
                </td>
                <td
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    fontSize: "11px",
                  }}
                >
                  {p.protocol}
                </td>
                <td
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    fontSize: "11px",
                  }}
                >
                  {p.service ?? "—"}
                </td>
                <td
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    fontSize: "11px",
                  }}
                >
                  {p.version ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Vulnerabilities section */}
      {scan.vulns.length > 0 && (
        <>
          <div
            className="section-title"
            style={{
              fontSize: "14px",
              fontWeight: "bold",
              margin: "24px 0 6px",
              borderBottom: "2px solid #333",
              paddingBottom: "2px",
            }}
          >
            VULNERABILITIES
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    textAlign: "left",
                    fontSize: "11px",
                    background: "#f0f0f0",
                    fontWeight: "bold",
                  }}
                >
                  PORT
                </th>
                <th
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    textAlign: "left",
                    fontSize: "11px",
                    background: "#f0f0f0",
                    fontWeight: "bold",
                  }}
                >
                  SCRIPT ID
                </th>
                <th
                  style={{
                    border: "1px solid #ccc",
                    padding: "4px 8px",
                    textAlign: "left",
                    fontSize: "11px",
                    background: "#f0f0f0",
                    fontWeight: "bold",
                  }}
                >
                  OUTPUT
                </th>
              </tr>
            </thead>
            <tbody>
              {scan.vulns.map((v, i) => (
                <tr key={i}>
                  <td
                    style={{
                      border: "1px solid #ccc",
                      padding: "4px 8px",
                      fontSize: "11px",
                    }}
                  >
                    {v.port ?? "—"}
                  </td>
                  <td
                    style={{
                      border: "1px solid #ccc",
                      padding: "4px 8px",
                      fontSize: "11px",
                    }}
                  >
                    {v.script_id}
                  </td>
                  <td
                    style={{
                      border: "1px solid #ccc",
                      padding: "4px 8px",
                      fontSize: "11px",
                      wordBreak: "break-word",
                    }}
                  >
                    {v.output.length > 200 ? v.output.slice(0, 200) + "…" : v.output}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {/* Footer */}
      <div
        style={{
          marginTop: "32px",
          fontSize: "11px",
          color: "#888",
          borderTop: "1px solid #ddd",
          paddingTop: "8px",
        }}
      >
        Generated by NetSentinel — {generatedAt}
      </div>
    </div>
  );
}
