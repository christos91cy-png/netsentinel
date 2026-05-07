import SeverityBadge from "./SeverityBadge";

interface CveItem {
  id: string;
  description: string;
  cvss_score?: number | null;
  severity?: string | null;
  published: string;
  last_modified: string;
}

interface Props {
  cve: CveItem;
  onClick?: () => void;
}

export default function CveCard({ cve, onClick }: Props) {
  return (
    <div
      className="rounded border p-4 cursor-pointer transition-colors hover:border-gray-500"
      style={{ borderColor: "#30363d", background: "#161b22" }}
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <span className="font-mono font-bold text-sm" style={{ color: "#00bcd4" }}>{cve.id}</span>
        <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
      </div>
      <p className="text-sm line-clamp-3 mb-3" style={{ color: "#8b949e" }}>{cve.description}</p>
      <div className="flex gap-4 text-xs" style={{ color: "#8b949e" }}>
        <span>Published: {cve.published.slice(0, 10)}</span>
        <span>Modified: {cve.last_modified.slice(0, 10)}</span>
      </div>
    </div>
  );
}
