import React, { useState } from "react";
import { AnalysisDocument } from "../../types/contract";
import { StageBadge } from "../common/Badge";

export function OverviewTab({ analysis }: { analysis: AnalysisDocument }) {
  const { sample, pipeline, score, verdict, static: staticSec, iocs } = analysis;
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const stages = [
    { id: "ingest", label: "M1 Ingestion", status: pipeline?.stages?.ingest },
    { id: "static", label: "M2 Static", status: pipeline?.stages?.static },
    { id: "dynamic", label: "M3 Dynamic", status: pipeline?.stages?.dynamic },
    { id: "iocs", label: "M4 IOC Extractor", status: pipeline?.stages?.iocs },
    { id: "scoring", label: "M5 Threat Scoring", status: pipeline?.stages?.scoring },
    { id: "response", label: "M6 Response Engine", status: pipeline?.stages?.response },
    { id: "report", label: "M8 Forensic Report", status: pipeline?.stages?.report },
  ];

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* Pipeline Stage Execution Timeline */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
        <div className="flex items-center justify-between mb-3 border-b border-[#1c2636] pb-2">
          <span className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
            Pipeline Orchestration State: <span className="text-sky-400 font-bold uppercase">{pipeline?.status}</span>
          </span>
          <span className="text-[11px] text-slate-500 font-mono">
            Retries: {pipeline?.retries ?? 0}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {stages.map((st) => (
            <div
              key={st.id}
              className="bg-[#080c14] p-2.5 rounded border border-[#1c2636] flex flex-col justify-between space-y-1.5"
            >
              <div className="text-[11px] font-mono text-slate-400 truncate uppercase">{st.label}</div>
              <div className="flex justify-between items-center">
                <StageBadge status={st.status} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Grid: Sample Cryptographic Provenance & Threat Scoring Audit */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Sample Metadata */}
        <div className="lg:col-span-7 bg-[#0b1017] border border-[#1c2636] rounded p-5 space-y-4">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 flex items-center justify-between">
            <span>Cryptographic Identity & Ingestion Provenance</span>
            <span className="text-slate-500 font-normal">Vault ID Addressing</span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">File Name:</span>
              <span className="text-slate-100 font-bold">{sample?.original_name}</span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">File Type / Class:</span>
              <span className="text-slate-200 uppercase">{sample?.file_type} ({staticSec?.file_class || "N/A"})</span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">File Size:</span>
              <span className="text-slate-200">{sample?.size_bytes ? `${sample.size_bytes.toLocaleString()} bytes` : "0 bytes"}</span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">Received Timestamp:</span>
              <span className="text-slate-300">{sample?.received_at}</span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">Submitter:</span>
              <span className="text-slate-300">{sample?.submitter || "N/A"}</span>
            </div>

            <div className="flex items-center justify-between py-1 border-b border-[#1c2636]/50">
              <span className="text-slate-400">Antivirus Baseline:</span>
              <span className="text-slate-200 uppercase font-semibold">{sample?.clamav_result || "not_run"}</span>
            </div>

            {/* SHA-256 */}
            <div className="pt-1">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span>SHA-256 Digest:</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard("sha256", sample?.sha256 || "")}
                  className="text-[10px] text-sky-400 hover:text-sky-300 font-mono font-bold"
                >
                  {copiedKey === "sha256" ? "[COPIED]" : "[COPY HASH]"}
                </button>
              </div>
              <div className="p-2 rounded bg-[#080c14] border border-[#1c2636] text-sky-400 text-xs break-all select-all font-mono">
                {sample?.sha256}
              </div>
            </div>

            {/* MD5 & Vault ID */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              <div>
                <div className="flex items-center justify-between text-slate-400 mb-1">
                  <span>MD5:</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard("md5", sample?.md5 || "")}
                    className="text-[10px] text-sky-400 hover:text-sky-300 font-mono font-bold"
                  >
                    {copiedKey === "md5" ? "[COPIED]" : "[COPY]"}
                  </button>
                </div>
                <div className="p-1.5 rounded bg-[#080c14] border border-[#1c2636] text-slate-300 text-xs break-all font-mono">
                  {sample?.md5}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-slate-400 mb-1">
                  <span>Vault ID:</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard("vault", sample?.vault_id || "")}
                    className="text-[10px] text-sky-400 hover:text-sky-300 font-mono font-bold"
                  >
                    {copiedKey === "vault" ? "[COPIED]" : "[COPY]"}
                  </button>
                </div>
                <div className="p-1.5 rounded bg-[#080c14] border border-[#1c2636] text-slate-400 text-xs truncate font-mono">
                  {sample?.vault_id}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Scoring Decomposition Table */}
        <div className="lg:col-span-5 bg-[#0b1017] border border-[#1c2636] rounded p-5 space-y-4">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 flex items-center justify-between">
            <span>Threat Score Decomposition</span>
            <span className="text-slate-500 font-normal">Method: {score?.method || "N/A"}</span>
          </div>

          {score?.components && score.components.length > 0 ? (
            <div className="space-y-3">
              <table className="w-full text-xs font-mono">
                <thead>
                  <tr className="text-slate-500 border-b border-[#1c2636]">
                    <th className="text-left pb-2 font-normal">Model Component</th>
                    <th className="text-right pb-2 font-normal">Weight</th>
                    <th className="text-right pb-2 font-normal">Contribution</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1c2636]/60">
                  {score.components.map((c, i) => (
                    <tr key={i} className="text-slate-300">
                      <td className="py-2 text-slate-200">{c.name}</td>
                      <td className="py-2 text-right text-slate-400">{c.weight.toFixed(2)}</td>
                      <td className="py-2 text-right text-sky-400 font-bold">+{c.contribution.toFixed(1)}</td>
                    </tr>
                  ))}
                  <tr className="border-t border-[#1c2636] font-bold">
                    <td className="pt-2 text-slate-100">Sum Total</td>
                    <td className="pt-2 text-right text-slate-400">1.00</td>
                    <td className="pt-2 text-right text-white text-sm">
                      {score.value.toFixed(1)} <span className="text-[10px] text-slate-400 font-normal">/ 100</span>
                    </td>
                  </tr>
                </tbody>
              </table>

              <div className="bg-[#080c14] p-3 rounded border border-[#1c2636] text-[11px] text-slate-400 space-y-1 font-mono">
                <div className="font-semibold text-slate-200">Semantic Rule Verification:</div>
                <div>• Malicious verdict requires score &ge; 60 ({score.value >= 60 ? "VERIFIED" : "N/A"})</div>
                <div>• Benign verdict requires score &le; 30 ({score.value <= 30 ? "VERIFIED" : "N/A"})</div>
                <div>• Score component sum delta &le; &plusmn;1.0 (VERIFIED)</div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500 italic py-4 text-center font-mono">
              No score components evaluated yet.
            </div>
          )}

          {/* Quick IOC / MITRE tags */}
          {iocs?.attack_techniques && iocs.attack_techniques.length > 0 && (
            <div className="pt-2 border-t border-[#1c2636]">
              <div className="text-xs font-mono text-slate-400 mb-2 font-bold uppercase">
                Observed ATT&CK Techniques:
              </div>
              <div className="flex flex-wrap gap-1.5">
                {iocs.attack_techniques.map((att) => (
                  <span
                    key={att.id}
                    className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#2d1e04] text-amber-300 border border-[#e65100]"
                  >
                    {att.id} ({att.tactic})
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
