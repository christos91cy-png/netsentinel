import { NavLink } from "react-router-dom";
import { LayoutDashboard, Radar, History, GitCompare, ShieldAlert, BookOpen, Settings } from "lucide-react";

const links = [
  { to: "/",        label: "Dashboard",  Icon: LayoutDashboard },
  { to: "/scanner", label: "Scanner",    Icon: Radar           },
  { to: "/history", label: "History",    Icon: History         },
  { to: "/diff",    label: "Diff",       Icon: GitCompare      },
  { to: "/cve",     label: "CVE Search", Icon: ShieldAlert     },
  { to: "/learn",   label: "Learn",      Icon: BookOpen        },
];

const bottomLinks = [
  { to: "/settings", label: "Settings", Icon: Settings },
];

export default function Sidebar() {
  return (
    <aside
      className="w-52 flex flex-col shrink-0 border-r"
      style={{ background: "#161b22", borderColor: "#30363d" }}
    >
      <div className="px-5 py-5 border-b flex flex-col items-center" style={{ borderColor: "#30363d" }}>
        <img src="/logo.png" alt="NetSentinel logo" aria-hidden="true" className="w-14 h-14 mb-2" />
        <span className="text-lg font-bold tracking-widest" style={{ color: "#00ff88" }}>
          NET<span style={{ color: "#00bcd4" }}>SENTINEL</span>
        </span>
        <p className="text-xs mt-0.5" style={{ color: "#8b949e" }}>v0.1.0</p>
      </div>

      <nav aria-label="Main navigation" className="flex flex-col gap-1 px-3 py-4 flex-1">
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
            <l.Icon size={16} strokeWidth={1.5} />
            {l.label}
          </NavLink>
        ))}
      </nav>

      <div className="px-3 pb-2 flex flex-col gap-1">
        {bottomLinks.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
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
            <l.Icon size={16} strokeWidth={1.5} />
            {l.label}
          </NavLink>
        ))}
      </div>
      <div className="px-4 py-3 text-xs border-t" style={{ borderColor: "#30363d", color: "#8b949e" }}>
        Linux Desktop
      </div>
    </aside>
  );
}
