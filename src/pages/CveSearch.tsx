import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import CveCard from "../components/CveCard";
import SeverityBadge from "../components/SeverityBadge";

interface CveItem {
  id: string;
  description: string;
  cvss_score?: number | null;
  severity?: string | null;
  published: string;
  last_modified: string;
}

interface CveSearchResult {
  total: number;
  page: number;
  items: CveItem[];
}

export default function CveSearch() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<CveSearchResult | null>(null);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<CveItem | null>(null);

  async function search(p = 0) {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setDetail(null);
    try {
      const res = await invoke<CveSearchResult>("search_cves", { keyword: query.trim(), page: p });
      setResult(res);
      setPage(p);
    } catch (e: unknown) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(cveId: string) {
    setLoading(true);
    try {
      const item = await invoke<CveItem>("get_cve", { cveId });
      setDetail(item);
    } catch {
      // keep list view
    } finally {
      setLoading(false);
    }
  }

  const totalPages = result ? Math.ceil(result.total / 20) : 0;

  return (
    <div className="w-full">
      <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>CVE Search</h1>
      <p className="text-sm mb-4" style={{ color: "#8b949e" }}>
        Search the NVD (National Vulnerability Database) in real time.
      </p>

      <div className="flex gap-2 mb-6">
        <input
          className="flex-1 rounded px-3 py-2 text-sm font-mono border outline-none focus:border-cyan-500"
          style={{ background: "#0f1117", borderColor: "#30363d", color: "#e6edf3" }}
          placeholder="Search CVEs... (e.g. apache, log4j, openssh)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search(0)}
        />
        <button
          className="px-5 py-2 rounded font-semibold text-sm disabled:opacity-50"
          style={{ background: "#00bcd420", color: "#00bcd4", border: "1px solid #00bcd440" }}
          onClick={() => search(0)}
          disabled={loading || !query.trim()}
        >
          Search
        </button>
      </div>

      {loading && (
        <p className="text-sm animate-pulse" style={{ color: "#00bcd4" }}>Querying NVD...</p>
      )}

      {error && (
        <div className="rounded border px-4 py-3 mb-4" style={{ borderColor: "#f8514940", background: "#f8514910", color: "#f85149" }}>
          {error}
        </div>
      )}

      {detail && (
        <div className="rounded border p-5 mb-4" style={{ borderColor: "#30363d", background: "#161b22" }}>
          <button className="text-xs mb-3" style={{ color: "#8b949e" }} onClick={() => setDetail(null)}>
            ← Back to results
          </button>
          <div className="flex items-start justify-between gap-3 mb-3">
            <h2 className="font-mono font-bold text-lg" style={{ color: "#00bcd4" }}>{detail.id}</h2>
            <SeverityBadge severity={detail.severity} score={detail.cvss_score} />
          </div>
          <p className="text-sm leading-relaxed mb-4" style={{ color: "#e6edf3" }}>{detail.description}</p>
          <div className="flex gap-6 text-xs" style={{ color: "#8b949e" }}>
            <span>Published: {detail.published.slice(0, 10)}</span>
            <span>Modified: {detail.last_modified.slice(0, 10)}</span>
          </div>
        </div>
      )}

      {!detail && result && (
        <>
          <p className="text-xs mb-3" style={{ color: "#8b949e" }}>
            {result.total.toLocaleString()} results — page {page + 1} of {totalPages}
          </p>
          <div className="space-y-3 mb-4">
            {result.items.map((cve) => (
              <CveCard key={cve.id} cve={cve} onClick={() => loadDetail(cve.id)} />
            ))}
          </div>
          <div className="flex gap-2">
            <button
              className="px-4 py-1.5 rounded text-sm disabled:opacity-40"
              style={{ background: "#161b22", border: "1px solid #30363d", color: "#e6edf3" }}
              disabled={page === 0}
              onClick={() => search(page - 1)}
            >
              Previous
            </button>
            <button
              className="px-4 py-1.5 rounded text-sm disabled:opacity-40"
              style={{ background: "#161b22", border: "1px solid #30363d", color: "#e6edf3" }}
              disabled={page + 1 >= totalPages}
              onClick={() => search(page + 1)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}
