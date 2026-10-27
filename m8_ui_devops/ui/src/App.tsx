import React, { useState, useEffect } from "react";
import { AnalysisDocument } from "./types/contract";
import { ALL_SAMPLES } from "./mock/sampleData";
import { checkApiHealth, ApiHealthStatus } from "./api/client";
import { Navbar } from "./components/Navbar";
import { VerdictBanner } from "./components/VerdictBanner";
import { UploadModal } from "./components/UploadModal";
import { OverviewTab } from "./components/tabs/OverviewTab";
import { StaticTab } from "./components/tabs/StaticTab";
import { DynamicTab } from "./components/tabs/DynamicTab";
import { NetworkTab } from "./components/tabs/NetworkTab";
import { IocTab } from "./components/tabs/IocTab";
import { AttackTab } from "./components/tabs/AttackTab";
import { ResponseTab } from "./components/tabs/ResponseTab";
import { AuditTab } from "./components/tabs/AuditTab";

type TabId = "overview" | "static" | "dynamic" | "network" | "iocs" | "attack" | "response" | "audit";

export function App() {
  const [samples, setSamples] = useState<AnalysisDocument[]>(ALL_SAMPLES);
  const [selectedId, setSelectedId] = useState<string>(ALL_SAMPLES[0].analysis_id);
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [currentRole, setCurrentRole] = useState<"analyst" | "approver" | "auditor">("analyst");
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [apiHealth, setApiHealth] = useState<ApiHealthStatus>({ online: false, latencyMs: 0 });
  const [toast, setToast] = useState<string | null>(null);

  const activeAnalysis = samples.find((s) => s.analysis_id === selectedId) || samples[0];

  useEffect(() => {
    checkApiHealth().then(setApiHealth);
    const interval = setInterval(() => {
      checkApiHealth().then(setApiHealth);
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handleUploadSuccess = (analysisId: string, vaultId: string) => {
    const newDoc: AnalysisDocument = {
      contract_version: "1.0.0",
      analysis_id: analysisId,
      sample: {
        vault_id: vaultId,
        sha256: "f".repeat(64),
        md5: "e".repeat(32),
        size_bytes: 65536,
        file_type: "pe",
        original_name: "uploaded_sample.exe",
        received_at: new Date().toISOString(),
        submitter: "analyst1",
        stored_defanged: true,
        stored_encrypted: true,
        clamav_result: "not_run",
      },
      pipeline: {
        status: "received",
        stages: { ingest: "done", static: "running", dynamic: "pending" },
      },
      verdict: {
        label: "suspicious",
        severity: "medium",
        confidence: 0.5,
        family_guess: "pending_triage",
        explanation: ["Sample safely accepted into vault", "Pipeline static analysis in progress"],
      },
      score: {
        value: 45,
        method: "weighted_rules_v1",
        components: [{ name: "intake_heuristics", weight: 1.0, contribution: 45 }],
      },
    };

    setSamples([newDoc, ...samples]);
    setSelectedId(analysisId);
    showToast(`Sample uploaded & vault registered: ${vaultId.slice(0, 8)}...`);
  };

  const handleExportPdf = () => {
    window.open(`/api/reports/${activeAnalysis.analysis_id}/pdf`, "_blank");
    showToast("Generating forensic PDF report...");
  };

  const handleExportHtml = () => {
    window.open(`/api/reports/${activeAnalysis.analysis_id}/html`, "_blank");
    showToast("Opening standalone HTML dossier...");
  };

  const tabs: Array<{ id: TabId; label: string; badge?: string | number }> = [
    { id: "overview", label: "Overview" },
    { id: "static", label: "Static Analysis", badge: activeAnalysis.static?.entropy ? `H:${activeAnalysis.static.entropy.toFixed(1)}` : undefined },
    { id: "dynamic", label: "Dynamic Telemetry", badge: activeAnalysis.dynamic?.process_tree?.length },
    { id: "network", label: "Network & C2", badge: activeAnalysis.iocs?.beacons?.length ? "C2 Active" : undefined },
    { id: "iocs", label: "Indicators (Defanged)", badge: activeAnalysis.iocs?.items?.length },
    { id: "attack", label: "MITRE ATT&CK", badge: activeAnalysis.iocs?.attack_techniques?.length },
    {
      id: "response",
      label: "Response & Containment",
      badge: activeAnalysis.response_actions?.filter((a) => a.status === "awaiting_approval").length || undefined,
    },
    { id: "audit", label: "Pipeline & Audit" },
  ];

  return (
    <div className="min-h-screen bg-[#06090e] text-slate-100 flex flex-col font-sans selection:bg-[#1565c0] selection:text-white">
      {/* Top SOC Navbar - Layer 1 */}
      <Navbar
        currentRole={currentRole}
        onRoleChange={setCurrentRole}
        apiHealth={apiHealth}
        onOpenUpload={() => setIsUploadOpen(true)}
        onRefresh={() => {
          checkApiHealth().then(setApiHealth);
          showToast("Telemetry refreshed from M7.");
        }}
      />

      {/* Main Command Workspace */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto p-4 lg:p-6 space-y-4">
        {/* Sample Switcher Ribbon - Layer 2 */}
        <div className="bg-[#0b1017] border border-[#1c2636] rounded p-2.5 flex items-center justify-between gap-3 overflow-x-auto text-xs font-mono anim-layer-2">
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-slate-500 font-bold uppercase text-[10px] tracking-wider">
              Investigation Target:
            </span>
            <div className="flex gap-1.5">
              {samples.map((s) => {
                const isSelected = s.analysis_id === selectedId;
                const isMal = s.verdict?.label === "malicious";
                const isBen = s.verdict?.label === "benign";
                const dotColor = isMal ? "bg-red-500" : isBen ? "bg-emerald-500" : "bg-amber-500";

                return (
                  <button
                    key={s.analysis_id}
                    type="button"
                    onClick={() => setSelectedId(s.analysis_id)}
                    className={`px-3 py-1.5 rounded flex items-center gap-2 border transition ${
                      isSelected
                        ? "bg-[#121924] border-[#1565c0] text-white font-bold shadow-sm"
                        : "bg-[#080c14] border-[#1c2636] text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span className={`w-2 h-2 rounded-full ${dotColor}`} />
                    <span className="truncate max-w-[150px]">{s.sample.original_name}</span>
                    <span className="text-[10px] opacity-60">
                      ({s.verdict?.label || "unknown"})
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="text-xs text-slate-500 shrink-0 hidden md:block">
            Vault ID: <span className="text-slate-400 font-semibold">{activeAnalysis.sample.vault_id.slice(0, 13)}...</span>
          </div>
        </div>

        {/* Threat Verdict & Executive Summary Banner - Layer 3 */}
        <VerdictBanner
          analysis={activeAnalysis}
          onExportPdf={handleExportPdf}
          onExportHtml={handleExportHtml}
        />

        {/* Tab Navigation - Layer 4 */}
        <div className="border-b border-[#1c2636] flex items-center gap-1 overflow-x-auto anim-layer-4">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-xs font-mono font-bold uppercase tracking-wider border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
                  isActive
                    ? "border-[#1565c0] text-sky-400 bg-[#0b1017]"
                    : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-[#0b1017]/40"
                }`}
              >
                <span>{tab.label}</span>
                {tab.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                      tab.id === "response"
                        ? "bg-[#2d0a0a] text-red-300 border border-[#b71c1c] animate-pulse font-black"
                        : "bg-[#151d2a] text-slate-400 border border-[#1c2636]"
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Active Tab Content Area - Layer 5 */}
        <div className="pt-1 anim-layer-5">
          {activeTab === "overview" && <OverviewTab analysis={activeAnalysis} />}
          {activeTab === "static" && <StaticTab analysis={activeAnalysis} />}
          {activeTab === "dynamic" && <DynamicTab analysis={activeAnalysis} />}
          {activeTab === "network" && <NetworkTab analysis={activeAnalysis} />}
          {activeTab === "iocs" && <IocTab analysis={activeAnalysis} />}
          {activeTab === "attack" && <AttackTab analysis={activeAnalysis} />}
          {activeTab === "response" && (
            <ResponseTab
              analysis={activeAnalysis}
              currentRole={currentRole}
              onActionUpdated={() => showToast("Response action status updated.")}
            />
          )}
          {activeTab === "audit" && <AuditTab analysis={activeAnalysis} />}
        </div>
      </main>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={handleUploadSuccess}
      />

      {/* Floating Notification Toast */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 bg-[#0b1017] border border-[#1565c0] text-sky-300 px-4 py-2.5 rounded shadow-2xl text-xs font-mono flex items-center gap-2 anim-layer-1">
          <span className="text-sky-400 font-bold">[NOTIFY]</span>
          <span>{toast}</span>
        </div>
      )}
    </div>
  );
}
export default App;
