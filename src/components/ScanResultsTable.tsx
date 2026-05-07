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
}

export default function ScanResultsTable({ ports, vulns }: Props) {
  return (
    <div className="space-y-6">
      <section>
        <h3 className="text-sm font-semibold mb-2" style={{ color: "#00ff88" }}>
          Open Ports ({ports.length})
        </h3>
        {ports.length === 0 ? (
          <p className="text-sm" style={{ color: "#8b949e" }}>No open ports found.</p>
        ) : (
          <div className="overflow-x-auto rounded border" style={{ borderColor: "#30363d" }}>
            <table className="w-full text-sm">
              <thead style={{ background: "#161b22" }}>
                <tr>
                  {["Port", "Protocol", "State", "Service", "Version"].map((h) => (
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
                    <td className="px-4 py-2 font-mono font-bold" style={{ color: "#00bcd4" }}>{p.port}</td>
                    <td className="px-4 py-2 text-xs uppercase" style={{ color: "#8b949e" }}>{p.protocol}</td>
                    <td className="px-4 py-2">
                      <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: "#3fb95020", color: "#3fb950" }}>
                        {p.state}
                      </span>
                    </td>
                    <td className="px-4 py-2">{p.service ?? "—"}</td>
                    <td className="px-4 py-2 text-xs" style={{ color: "#8b949e" }}>{p.version ?? "—"}</td>
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
              <div key={i} className="rounded border p-3" style={{ borderColor: "#f8514940", background: "#f8514910" }}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold" style={{ color: "#f85149" }}>{v.script_id}</span>
                  {v.port && (
                    <span className="text-xs" style={{ color: "#8b949e" }}>port {v.port}</span>
                  )}
                </div>
                <pre className="text-xs whitespace-pre-wrap break-words" style={{ color: "#e6edf3" }}>{v.output}</pre>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
