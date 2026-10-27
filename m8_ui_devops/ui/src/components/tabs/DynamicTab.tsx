import React from "react";
import { AnalysisDocument } from "../../types/contract";

export function DynamicTab({ analysis }: { analysis: AnalysisDocument }) {
  const { dynamic } = analysis;

  if (!dynamic || dynamic.status === "skipped") {
    return (
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-8 text-center space-y-2 anim-layer-5">
        <div className="text-amber-400 font-mono text-xs font-bold uppercase tracking-wider">
          Dynamic Analysis Skipped / Non-Executable Class
        </div>
        <div className="text-slate-500 font-mono text-xs">
          Per contract state machine rules, dynamic execution is skipped for non-executable file types.
        </div>
      </div>
    );
  }

  const sb = dynamic.sandbox;

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* Sandbox Isolation & Execution Run Info */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 mb-3 flex items-center justify-between">
          <span>Sandbox Guest Environment & Containment Verification</span>
          <span className="text-emerald-400 font-semibold font-mono">
            {sb?.reverted ? "[SNAPSHOT REVERTED: OK]" : "[SNAPSHOT STATE: PENDING]"}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs font-mono">
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Engine</span>
            <span className="font-bold text-slate-200 uppercase">{sb?.engine || "N/A"}</span>
          </div>
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Guest OS</span>
            <span className="font-bold text-slate-200">{sb?.guest_os || "N/A"}</span>
          </div>
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Run ID</span>
            <span className="font-bold text-sky-400">{sb?.run_id || "N/A"}</span>
          </div>
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Duration / Timeout</span>
            <span className="font-bold text-slate-200">{sb?.duration_s ?? 0}s / {sb?.timeout_s ?? 0}s</span>
          </div>
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Network Isolation</span>
            <span className="font-bold text-emerald-400 uppercase">{sb?.network_mode || "isolated"}</span>
          </div>
          <div className="bg-[#080c14] p-2.5 rounded border border-[#1c2636]">
            <span className="text-slate-500 block text-[10px] uppercase">Trapped API Calls</span>
            <span className="font-bold text-slate-200">
              {dynamic.api_summary ? Object.values(dynamic.api_summary).reduce((a, b) => a + b, 0) : 0}
            </span>
          </div>
        </div>
      </div>

      {/* Process Tree Visualization */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4 space-y-3">
        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 flex items-center justify-between">
          <span>Process Hierarchy & Subprocess Lineage</span>
          <span className="text-slate-500 font-normal font-mono">
            Count: {dynamic.process_tree?.length ?? 0}
          </span>
        </div>

        {dynamic.process_tree && dynamic.process_tree.length > 0 ? (
          <div className="space-y-2 font-mono">
            {dynamic.process_tree.map((p, i) => {
              const isChild = (p.ppid && p.ppid !== 0) || i > 0;
              return (
                <div
                  key={i}
                  className={`p-3 rounded border text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 ${
                    isChild
                      ? "ml-0 sm:ml-8 bg-[#080c14] border-[#1c2636] border-l-2 border-l-sky-500"
                      : "bg-[#080c14] border-[#1c2636] border-l-4 border-l-[#c62828]"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <span className="px-2 py-0.5 rounded bg-[#06192e] text-sky-400 border border-[#1565c0] text-[11px] font-bold">
                      PID {p.pid}
                    </span>
                    {p.ppid && (
                      <span className="text-slate-500 text-[11px]">PPID {p.ppid}</span>
                    )}
                    <span className="font-bold text-slate-100">{p.name}</span>
                  </div>

                  {p.command_line && (
                    <div className="text-[11px] text-slate-400 bg-[#0b1017] px-2 py-0.5 rounded border border-[#1c2636] truncate max-w-xl">
                      {p.command_line}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-xs text-slate-500 italic font-mono">No process hierarchy telemetry captured.</div>
        )}
      </div>

      {/* Host System Operations: Files & Registry */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* File System Operations */}
        <div className="lg:col-span-6 bg-[#0b1017] border border-[#1c2636] rounded p-4 space-y-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2">
            Filesystem Mutations (Create, Modify, Delete)
          </div>

          {dynamic.file_events && dynamic.file_events.length > 0 ? (
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {dynamic.file_events.map((fe, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-[#080c14] border border-[#1c2636] text-xs font-mono flex items-center justify-between gap-2"
                >
                  <span className="truncate text-slate-300" title={fe.target}>
                    {fe.target}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ${
                      fe.action === "create"
                        ? "bg-[#2d0a0a] text-red-300 border border-[#b71c1c]"
                        : "bg-[#151d2a] text-slate-300 border border-[#2c3b52]"
                    }`}
                  >
                    {fe.action}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic font-mono">No filesystem mutations observed.</div>
          )}
        </div>

        {/* Registry Operations */}
        <div className="lg:col-span-6 bg-[#0b1017] border border-[#1c2636] rounded p-4 space-y-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2">
            Windows Registry Modifications (Persistence & Config)
          </div>

          {dynamic.registry_events && dynamic.registry_events.length > 0 ? (
            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {dynamic.registry_events.map((re, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-[#080c14] border border-[#1c2636] text-xs font-mono flex items-center justify-between gap-2"
                >
                  <span className="truncate text-amber-300" title={re.target}>
                    {re.target}
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 bg-[#2d1e04] text-amber-300 border border-[#e65100]">
                    {re.action}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic font-mono">No registry modifications observed.</div>
          )}
        </div>
      </div>

      {/* Mutexes & Dropped Files */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Mutexes */}
        <div className="lg:col-span-6 bg-[#0b1017] border border-[#1c2636] rounded p-4 space-y-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2">
            Infection Mutexes & Synchronization Objects
          </div>
          {dynamic.mutexes && dynamic.mutexes.length > 0 ? (
            <div className="space-y-1">
              {dynamic.mutexes.map((m, i) => (
                <div key={i} className="p-2 rounded bg-[#080c14] border border-[#1c2636] text-xs font-mono text-sky-400">
                  MUTEX: {m}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic font-mono">No synchronization mutexes created.</div>
          )}
        </div>

        {/* Dropped Files */}
        <div className="lg:col-span-6 bg-[#0b1017] border border-[#1c2636] rounded p-4 space-y-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2">
            Payloads & Dropped Binaries
          </div>
          {dynamic.dropped_files && dynamic.dropped_files.length > 0 ? (
            <div className="space-y-2">
              {dynamic.dropped_files.map((df, i) => (
                <div key={i} className="p-2.5 rounded bg-[#080c14] border border-[#1c2636] text-xs font-mono space-y-1">
                  <div className="flex justify-between font-bold text-slate-200">
                    <span>{df.name || "unnamed_drop.bin"}</span>
                    <span className="text-slate-400">{df.size_bytes ? `${df.size_bytes} B` : "-"}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 break-all">
                    SHA-256: <span className="text-sky-300">{df.sha256}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic font-mono">No secondary payloads dropped.</div>
          )}
        </div>
      </div>
    </div>
  );
}
