interface Props {
  severity?: string | null;
  score?: number | null;
}

const colorMap: Record<string, string> = {
  CRITICAL: "#f85149",
  HIGH: "#ff7b72",
  MEDIUM: "#e3b341",
  LOW: "#3fb950",
  NONE: "#8b949e",
};

export default function SeverityBadge({ severity, score }: Props) {
  const label = severity?.toUpperCase() ?? "N/A";
  const color = colorMap[label] ?? "#8b949e";
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase tracking-wide"
      style={{ color, border: `1px solid ${color}`, background: `${color}18` }}
    >
      {score != null && <span>{score}</span>}
      {label}
    </span>
  );
}
