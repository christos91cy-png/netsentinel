import { useState } from "react";

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

interface Props {
  ports: Port[];
  vulns: Vuln[];
  os_guess?: string;
  scan_type?: string;
}

function VulnCard({ v }: { v: Vuln }) {
  const [expanded, setExpanded] = useState(false);
  const lines = v.output.split("\n").map((l) => l.trimEnd()).filter(Boolean);
  const preview = lines.slice(0, 4);
  const hasMore = lines.length > 4;
  return (
    <div className="rounded border p-3" style={{ borderColor: "#f8514940", background: "#f8514910" }}>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-bold" style={{ color: "#f85149" }}>{v.script_id}</span>
          {v.port && <span className="text-xs" style={{ color: "#8b949e" }}>port {v.port}</span>}
        </div>
        {hasMore && (
          <button
            className="text-xs px-2 py-0.5 rounded border"
            style={{ borderColor: "#30363d", color: "#8b949e" }}
            onClick={() => setExpanded((e) => !e)}
          >
            {expanded ? "Collapse" : `+${lines.length - 4} more`}
          </button>
        )}
      </div>
      <pre className="text-xs whitespace-pre-wrap break-words" style={{ color: "#e6edf3" }}>
        {(expanded ? lines : preview).join("\n")}
      </pre>
    </div>
  );
}

export default function ScanResultsTable({ ports, vulns, os_guess, scan_type }: Props) {
  const isDiscover = scan_type === "discover";
  return (
    <div className="space-y-6">
      {os_guess && (
        <div className="mb-3 flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "#8b949e" }}>OS</span>
          <span className="text-sm font-mono" style={{ color: "#00bcd4" }}>{os_guess}</span>
        </div>
      )}
      <section>
        <h3 className="text-sm font-semibold mb-2" style={{ color: "#00ff88" }}>
          {isDiscover ? `Live Hosts (${ports.length})` : `Open Ports (${ports.length})`}
        </h3>
        {ports.length === 0 ? (
          <p className="text-sm" style={{ color: "#8b949e" }}>No open ports found.</p>
        ) : (
          <div className="overflow-x-auto rounded border" style={{ borderColor: "#30363d" }}>
            <table className="w-full text-sm" aria-label="Scan results">
              <thead style={{ background: "#161b22" }}>
                <tr>
                  {(isDiscover ? ["#", "IP Address", "State", "Hostname", ""] : ["Port", "Protocol", "State", "Service", "Version"]).map((h) => (
                    <th key={h} className="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wide" style={{ color: "#8b949e" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ports.map((p, i) => (
                  <tr
                    key={i}
                    className="border-t"
                    style={{ borderColor: "#30363d", background: i % 2 === 0 ? "transparent" : "#161b2240" }}
                  >
                    <td className="px-4 py-2 font-mono font-bold" style={{ color: "#00bcd4" }}>
                      {isDiscover ? p.port : p.port}
                    </td>
                    <td className="px-4 py-2 font-mono text-sm" style={{ color: isDiscover ? "#00bcd4" : "#8b949e" }}>
                      {isDiscover ? (p.service ?? "—") : p.protocol.toUpperCase()}
                    </td>
                    <td className="px-4 py-2">
                      <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "#3fb95020", color: "#3fb950" }}>
                        {p.state}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm" style={{ color: "#e6edf3" }}>
                      {isDiscover ? (p.version ?? "—") : (p.service ?? "—")}
                    </td>
                    <td className="px-4 py-2 text-xs" style={{ color: "#8b949e" }}>
                      {isDiscover ? "" : (p.version ?? "—")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {vulns.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold mb-2" style={{ color: "#f85149" }}>
            Vulnerabilities Found ({vulns.length})
          </h3>
          <div className="space-y-2">
            {vulns.map((v, i) => (
              <VulnCard key={i} v={v} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
