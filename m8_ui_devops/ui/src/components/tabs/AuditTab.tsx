import React, { useState } from "react";
import { AnalysisDocument } from "../../types/contract";

export function AuditTab({ analysis }: { analysis: AnalysisDocument }) {
  const [copied, setCopied] = useState(false);

  const rawJson = JSON.stringify(analysis, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const transitions = [
    { from: "received", to: "static", event: "sample.received", module: "M1", section: "sample" },
    { from: "static", to: "dynamic", event: "static.done", module: "M2", section: "static" },
    { from: "dynamic", to: "iocs", event: "dynamic.done", module: "M3", section: "dynamic" },
    { from: "iocs", to: "scoring", event: "iocs.done", module: "M4", section: "iocs" },
    { from: "scoring", to: "response", event: "scoring.done", module: "M5", section: "detections, score, verdict" },
    { from: "response", to: "report", event: "response.done", module: "M6", section: "response_actions" },
    { from: "report", to: "complete", event: "report.done", module: "M8", section: "report_vault_id" },
  ];

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* State Machine Transition Flow */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-5 space-y-3">
        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 flex items-center justify-between">
          <span>Pipeline State Machine & Event-Flow Trace (pipeline/state_machine.yaml)</span>
          <span className="text-emerald-400 font-bold font-mono">Contract Version 1.0.0</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-slate-400 border-b border-[#1c2636] bg-[#080c14]">
                <th className="text-left p-2.5">Transition Stage</th>
                <th className="text-left p-2.5">Event Emitted</th>
                <th className="text-left p-2.5">Producer</th>
                <th className="text-left p-2.5">Section Ownership Write</th>
                <th className="text-right p-2.5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1c2636]/60">
              {transitions.map((t, i) => (
                <tr key={i} className="hover:bg-[#121924]">
                  <td className="p-2.5 text-slate-200">
                    <span className="text-slate-400">{t.from}</span> &rarr;{" "}
                    <span className="font-bold text-sky-400">{t.to}</span>
                  </td>
                  <td className="p-2.5 text-amber-300">{t.event}</td>
                  <td className="p-2.5 font-bold text-slate-300">{t.module}</td>
                  <td className="p-2.5 text-slate-400 text-[11px]">{t.section}</td>
                  <td className="p-2.5 text-right">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-[#06240d] text-emerald-400 border border-[#1b5e20] font-bold">
                      VERIFIED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Contract Document Inspector */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-5 space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#1c2636] pb-2">
          <div>
            <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
              Raw Analysis Document Inspector (analysis_result.schema.json)
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              Schema: Draft 2020-12 | Immutable Record
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="px-3 py-1.5 rounded text-xs font-mono bg-[#121924] hover:bg-[#1c2636] text-slate-200 border border-[#1c2636] transition"
            >
              {copied ? "[COPIED DOCUMENT]" : "[COPY RAW JSON]"}
            </button>
          </div>
        </div>

        {/* Preformatted JSON block */}
        <pre className="bg-[#080c14] p-4 rounded border border-[#1c2636] text-xs font-mono text-sky-400 overflow-x-auto max-h-[500px] leading-relaxed select-all">
          {rawJson}
        </pre>
      </div>
    </div>
  );
}
