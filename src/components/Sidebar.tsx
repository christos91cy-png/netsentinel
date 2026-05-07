import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Dashboard", icon: "⬡" },
  { to: "/scanner", label: "Scanner", icon: "◎" },
  { to: "/history", label: "History", icon: "≡" },
  { to: "/cve", label: "CVE Search", icon: "⚠" },
  { to: "/learn", label: "Learn", icon: "◈" },
];

export default function Sidebar() {
  return (
    <aside
      className="w-52 flex flex-col shrink-0 border-r"
      style={{ background: "#161b22", borderColor: "#30363d" }}
    >
      <div className="px-5 py-5 border-b" style={{ borderColor: "#30363d" }}>
        <span className="text-lg font-bold tracking-widest" style={{ color: "#00ff88" }}>
          NET<span style={{ color: "#00bcd4" }}>SENTINEL</span>
        </span>
        <p className="text-xs mt-0.5" style={{ color: "#8b949e" }}>v0.1.0</p>
      </div>

      <nav className="flex flex-col gap-1 px-3 py-4 flex-1">
        {links.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            end={l.to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ${
                isActive
                  ? "text-white font-semibold"
                  : "text-gray-400 hover:text-white hover:bg-white/5"
              }`
            }
            style={({ isActive }) =>
              isActive ? { background: "#1f2937", color: "#00ff88" } : {}
            }
          >
            <span className="w-4 text-center">{l.icon}</span>
            {l.label}
          </NavLink>
        ))}
      </nav>

      <div className="px-4 py-3 text-xs border-t" style={{ borderColor: "#30363d", color: "#8b949e" }}>
        Linux Desktop
      </div>
    </aside>
  );
}
