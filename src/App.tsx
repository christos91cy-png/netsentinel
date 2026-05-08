import React from "react";
import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import History from "./pages/History";
import CveSearch from "./pages/CveSearch";
import Learn from "./pages/Learn";
import { ToastProvider } from "./components/Toast";

const SettingsPage = React.lazy(() => import("./pages/Settings"));
const DiffPage = React.lazy(() => import("./pages/Diff"));
const ReportPage = React.lazy(() => import("./pages/Report"));

export default function App() {
  return (
    <ToastProvider>
      <div className="flex h-screen overflow-hidden" style={{ background: "#0f1117" }}>
        <nav role="navigation" aria-label="Main navigation">
          <Sidebar />
        </nav>
        <main role="main" className="flex-1 overflow-y-auto p-6">
          <React.Suspense fallback={null}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/history" element={<History />} />
              <Route path="/cve" element={<CveSearch />} />
              <Route path="/learn" element={<Learn />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/diff" element={<DiffPage />} />
              <Route path="/report" element={<ReportPage />} />
            </Routes>
          </React.Suspense>
        </main>
      </div>
    </ToastProvider>
  );
}
