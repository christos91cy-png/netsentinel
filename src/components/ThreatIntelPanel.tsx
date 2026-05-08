import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface KevEntry {
  cve_id: string;
  vulnerability_name: string;
  date_added: string;
  short_description: string;
}

interface EpssEntry {
  cve: string;
  epss: string;
  percentile: string;
}

interface Props {
  cveIds: string[];
}

function epssColor(score: number): string {
  if (score >= 0.7) return "#f85149";
  if (score >= 0.3) return "#e3b341";
  return "#3fb950";
}

export default function ThreatIntelPanel({ cveIds }: Props) {
  const [kevResults, setKevResults] = useState<KevEntry[]>([]);
  const [epssResults, setEpssResults] = useState<EpssEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (cveIds.length === 0) {
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    Promise.all([
      invoke<KevEntry[]>("check_kev", { cveIds }),
      invoke<EpssEntry[]>("lookup_epss", { cveIds }),
    ])
      .then(([kev, epss]) => {
        setKevResults(kev);
        setEpssResults(epss);
      })
      .catch((err) => {
        setError(String(err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, [cveIds.join(",")]);

  const kevMap = new Map<string, KevEntry>(
    kevResults.map((e) => [e.cve_id, e])
  );
  const epssMap = new Map<string, EpssEntry>(
    epssResults.map((e) => [e.cve, e])
  );

  const hasData = kevResults.length > 0 || epssResults.length > 0;

  return (
    <div
      className="rounded border mt-3 p-4"
      style={{ background: "#161b22", borderColor: "#30363d" }}
    >
      <h3
        className="text-xs font-semibold uppercase tracking-wide mb-3"
        style={{ color: "#8b949e" }}
      >
        Threat Intelligence
      </h3>

      {loading && (
        <p className="text-xs animate-pulse" style={{ color: "#00ff88" }}>
          Fetching threat intel…
        </p>
      )}

      {!loading && error && (
        <p className="text-xs" style={{ color: "#f85149" }}>
          Error: {error}
        </p>
      )}

      {!loading && !error && cveIds.length === 0 && (
        <p className="text-xs" style={{ color: "#8b949e" }}>
          No CVE IDs found in this scan.
        </p>
      )}

      {!loading && !error && cveIds.length > 0 && !hasData && (
        <p className="text-xs" style={{ color: "#8b949e" }}>
          No KEV entries or EPSS scores found for these CVEs.
        </p>
      )}

      {!loading && !error && cveIds.length > 0 && hasData && (
        <div className="space-y-3">
          {cveIds.map((cve) => {
            const kev = kevMap.get(cve);
            const epss = epssMap.get(cve);
            if (!kev && !epss) return null;

            const epssScore = epss ? parseFloat(epss.epss) : null;
            const epssPercent =
              epssScore !== null ? Math.round(epssScore * 100) : null;

            return (
              <div
                key={cve}
                className="rounded border p-3"
                style={{ borderColor: "#30363d", background: "#0d1117" }}
              >
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span
                    className="font-mono text-xs font-bold"
                    style={{ color: "#e6edf3" }}
                  >
                    {cve}
                  </span>

                  {kev && (
                    <span
                      className="text-xs font-bold px-1.5 py-0.5 rounded"
                      style={{
                        background: "#f85149",
                        color: "#ffffff",
                      }}
                      title={`${kev.vulnerability_name} — Added ${kev.date_added}`}
                    >
                      KEV
                    </span>
                  )}
                </div>

                {kev && (
                  <p
                    className="text-xs mb-2"
                    style={{ color: "#8b949e" }}
                  >
                    {kev.vulnerability_name}
                  </p>
                )}

                {epss && epssScore !== null && epssPercent !== null && (
                  <div>
                    <div
                      className="flex items-center justify-between text-xs mb-1"
                      style={{ color: "#8b949e" }}
                    >
                      <span>EPSS Score</span>
                      <span
                        className="font-mono font-bold"
                        style={{ color: epssColor(epssScore) }}
                      >
                        {epssPercent}%
                      </span>
                    </div>
                    <div
                      className="w-full rounded-full h-1.5"
                      style={{ background: "#30363d" }}
                    >
                      <div
                        className="h-1.5 rounded-full transition-all"
                        style={{
                          width: `${epssPercent}%`,
                          background: epssColor(epssScore),
                        }}
                      />
                    </div>
                    <p
                      className="text-xs mt-1"
                      style={{ color: "#484f58" }}
                    >
                      {parseFloat(epss.percentile) > 0
                        ? `${Math.round(parseFloat(epss.percentile) * 100)}th percentile`
                        : ""}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
