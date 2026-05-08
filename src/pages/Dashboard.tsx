import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { Radar, Globe, ShieldAlert, Clock } from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface ScanSummary {
  id: number;
  target: string;
  scan_type: string;
  started_at: string;
  port_count: number;
  vuln_count: number;
}

function relativeTime(dateStr: string | undefined): string {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} minute${mins === 1 ? "" : "s"} ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hour${hrs === 1 ? "" : "s"} ago`;
  const days = Math.floor(hrs / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function buildChartData(history: ScanSummary[]) {
  const days: { date: string; label: string; count: number }[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateKey = d.toISOString().slice(0, 10);
    const label = d.toLocaleDateString("en-US", { weekday: "short" });
    days.push({ date: dateKey, label, count: 0 });
  }
  for (const s of history) {
    const dateKey = s.started_at.slice(0, 10);
    const day = days.find((d) => d.date === dateKey);
    if (day) day.count += 1;
  }
  return days;
}

export default function Dashboard() {
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    invoke<ScanSummary[]>("get_scan_history")
      .then(setHistory)
      .catch((err) => console.error("Failed to load history:", err));
  }, []);

  const totalPorts = history.reduce((sum, s) => sum + s.port_count, 0);
  const totalVulns = history.reduce((sum, s) => sum + s.vuln_count, 0);
  const lastScan = relativeTime(history[0]?.started_at);
  const chartData = buildChartData(history);

  const kpiCards = [
    {
      Icon: Radar,
      label: "Total Scans",
      value: history.length,
      subtitle: "all time",
    },
    {
      Icon: Globe,
      label: "Open Ports",
      value: totalPorts,
      subtitle: "across all scans",
    },
    {
      Icon: ShieldAlert,
      label: "Vulnerabilities",
      value: totalVulns,
      subtitle: "found total",
    },
    {
      Icon: Clock,
      label: "Last Scan",
      value: lastScan,
      subtitle: "",
      large: false,
    },
  ];

  return (
    <div className="w-full space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1" style={{ color: "#00ff88" }}>
          Dashboard
        </h1>
        <p className="text-sm" style={{ color: "#8b949e" }}>
          Network vulnerability scanner, CVE tracker, and security reference.
        </p>
      </div>

      {/* Section 1 — KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        {kpiCards.map(({ Icon, label, value, subtitle, large = true }) => (
          <div
            key={label}
            className="bg-[#161b22] border border-[#30363d] rounded-lg p-5 flex flex-col gap-2"
          >
            <div className="flex items-center gap-2">
              <Icon size={16} strokeWidth={1.5} style={{ color: "#8b949e" }} />
              <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: "#8b949e" }}>
                {label}
              </span>
            </div>
            <span
              className={`font-bold text-white leading-none ${large ? "text-3xl" : "text-xl"}`}
            >
              {value}
            </span>
            {subtitle && (
              <span className="text-xs" style={{ color: "#8b949e" }}>
                {subtitle}
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Section 2 — Scan Activity Chart */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5">
        <p className="text-sm font-semibold mb-4" style={{ color: "#8b949e" }}>
          Scan Activity (14 days)
        </p>
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={chartData} barCategoryGap="30%">
            <XAxis
              dataKey="label"
              stroke="#8b949e"
              tick={{ fill: "#8b949e", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis hide />
            <Tooltip
              cursor={{ fill: "#ffffff08" }}
              contentStyle={{
                background: "#161b22",
                border: "1px solid #30363d",
                color: "#e6edf3",
                borderRadius: 6,
                fontSize: 12,
              }}
              formatter={(val) => [val ?? 0, "Scans"]}
              labelFormatter={(label) => String(label)}
            />
            <Bar dataKey="count" fill="#00e676" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Section 3 — Recent Scans timeline */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-lg p-5">
        <p className="text-sm font-semibold mb-4" style={{ color: "#e6edf3" }}>
          Recent Scans
        </p>
        {history.length === 0 ? (
          <p className="text-sm" style={{ color: "#8b949e" }}>
            No scans yet. Run your first scan from the Scanner page.
          </p>
        ) : (
          <div className="space-y-1">
            {history.slice(0, 5).map((s) => (
              <button
                key={s.id}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded hover:bg-white/5 transition-colors text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00ff88]"
                onClick={() => navigate("/history")}
              >
                {/* Colored dot */}
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{
                    background: s.vuln_count === 0 ? "#00e676" : "#f85149",
                  }}
                />
                {/* Target */}
                <span
                  className="font-mono text-sm flex-1 truncate"
                  style={{ color: "#00bcd4" }}
                >
                  {s.target}
                </span>
                {/* Scan type badge */}
                <span
                  className="text-xs uppercase bg-[#21262d] px-2 py-0.5 rounded shrink-0"
                  style={{ color: "#8b949e" }}
                >
                  {s.scan_type}
                </span>
                {/* Counts */}
                <span className="text-xs shrink-0" style={{ color: "#8b949e" }}>
                  {s.port_count} ports
                </span>
                {s.vuln_count > 0 && (
                  <span className="text-xs shrink-0" style={{ color: "#f85149" }}>
                    {s.vuln_count} vulns
                  </span>
                )}
                {/* Relative time */}
                <span
                  className="text-xs shrink-0 ml-auto"
                  style={{ color: "#8b949e" }}
                >
                  {relativeTime(s.started_at)}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Section 4 — System Health Bar */}
      <div
        className="bg-[#161b22] border border-[#30363d] rounded-lg px-5 py-3 flex items-center gap-8 text-xs"
        style={{ color: "#8b949e" }}
      >
        <div className="flex items-center gap-1.5">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "#00e676" }}
          />
          <span>nmap</span>
          <span style={{ color: "#00e676" }}>ready</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "#00e676" }}
          />
          <span>Database</span>
          <span className="font-mono" style={{ color: "#e6edf3" }}>
            ~/.local/share/netsentinel/netsentinel.db
          </span>
        </div>
        <div className="flex items-center gap-1.5 ml-auto">
          <span style={{ color: "#8b949e" }}>v0.1.0</span>
        </div>
      </div>
    </div>
  );
}
