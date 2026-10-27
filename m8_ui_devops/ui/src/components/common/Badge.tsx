import React from "react";
import { SeverityLevel, VerdictLabel, StageStatus } from "../../types/contract";

export function SeverityBadge({ severity }: { severity: SeverityLevel | string }) {
  const sev = severity.toLowerCase();
  const styles: Record<string, string> = {
    critical: "bg-[#2d0a0a] text-red-400 border-[#b71c1c]",
    high: "bg-[#2d1204] text-orange-400 border-[#bf360c]",
    medium: "bg-[#2d1e04] text-amber-300 border-[#e65100]",
    low: "bg-[#06192e] text-blue-300 border-[#1565c0]",
    info: "bg-[#0f172a] text-slate-300 border-[#334155]",
    clean: "bg-[#06240d] text-emerald-400 border-[#1b5e20]",
  };
  const cls = styles[sev] || styles.info;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider border ${cls}`}>
      {severity}
    </span>
  );
}

export function VerdictPill({ verdict }: { verdict: VerdictLabel | string }) {
  const v = verdict.toLowerCase();
  const styles: Record<string, string> = {
    malicious: "bg-[#b71c1c] text-white border-[#d32f2f] shadow-sm",
    suspicious: "bg-[#e65100] text-white border-[#f57c00] shadow-sm",
    benign: "bg-[#1b5e20] text-white border-[#2e7d32]",
    unknown: "bg-[#1e293b] text-slate-200 border-[#334155]",
  };
  const cls = styles[v] || styles.unknown;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-mono font-black uppercase tracking-wider border ${cls}`}>
      {verdict}
    </span>
  );
}

export function StageBadge({ status }: { status?: StageStatus | string }) {
  const s = (status || "pending").toLowerCase();
  const styles: Record<string, string> = {
    done: "bg-[#06240d] text-emerald-400 border-[#1b5e20]",
    running: "bg-[#06192e] text-sky-400 border-[#1565c0] animate-pulse",
    failed: "bg-[#2d0a0a] text-red-400 border-[#b71c1c]",
    skipped: "bg-[#111827] text-slate-400 border-[#1f2937]",
    pending: "bg-[#0a0f17] text-slate-500 border-[#151d2a]",
  };
  const cls = styles[s] || styles.pending;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono uppercase tracking-wider border ${cls}`}>
      {status || "pending"}
    </span>
  );
}
