import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import History from "./pages/History";
import CveSearch from "./pages/CveSearch";
import Learn from "./pages/Learn";

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#0f1117" }}>
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/history" element={<History />} />
          <Route path="/cve" element={<CveSearch />} />
          <Route path="/learn" element={<Learn />} />
        </Routes>
      </main>
    </div>
  );
}
