import React from "react";
import { AnalysisDocument } from "../../types/contract";

export function AttackTab({ analysis }: { analysis: AnalysisDocument }) {
  const { iocs } = analysis;
  const attackTechniques = iocs?.attack_techniques || [];

  // Group by tactic
  const grouped: Record<string, typeof attackTechniques> = {};
  attackTechniques.forEach((tech) => {
    const tac = tech.tactic.toLowerCase();
    if (!grouped[tac]) grouped[tac] = [];
    grouped[tac].push(tech);
  });

  const knownTactics = [
    { id: "execution", name: "Execution" },
    { id: "persistence", name: "Persistence" },
    { id: "defense-evasion", name: "Defense Evasion" },
    { id: "command-and-control", name: "Command & Control" },
    { id: "discovery", name: "Discovery" },
    { id: "collection", name: "Collection" },
    { id: "impact", name: "Impact" },
  ];

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* ATT&CK Framework Header */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#1c2636] pb-3">
          <div>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">
              MITRE ATT&CK Matrix Mapping
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Identified adversarial tactics and sub-techniques supported by forensic telemetry.
            </p>
          </div>
          <span className="px-2.5 py-1 rounded bg-[#121924] text-slate-300 font-mono text-xs font-bold border border-[#1c2636]">
            {attackTechniques.length} Techniques Detected
          </span>
        </div>

        {/* Tactical Matrix Heatmap Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mt-4">
          {knownTactics.map((tac) => {
            const hits = grouped[tac.id] || [];
            const hasHits = hits.length > 0;

            return (
              <div
                key={tac.id}
                className={`rounded border p-3 flex flex-col justify-between min-h-[130px] transition ${
                  hasHits
                    ? "bg-[#2d0a0a]/30 border-[#b71c1c]/80 shadow-sm"
                    : "bg-[#080c14] border-[#1c2636]/60 opacity-60"
                }`}
              >
                <div>
                  <div className="text-[11px] font-bold uppercase tracking-wider text-slate-300 font-mono mb-2">
                    {tac.name}
                  </div>
                  {hasHits ? (
                    <div className="space-y-1.5">
                      {hits.map((tech) => (
                        <div
                          key={tech.id}
                          className="bg-[#2d0a0a] border border-[#b71c1c]/80 p-1.5 rounded text-[11px] font-mono text-red-200"
                        >
                          <span className="font-bold">{tech.id}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-[10px] text-slate-600 font-mono">No hits</span>
                  )}
                </div>

                <div className="text-[10px] font-mono text-slate-500 pt-2 border-t border-[#1c2636]/60">
                  {hits.length} active
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed Technique Findings Table */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded overflow-hidden">
        <div className="p-3 bg-[#080c14] border-b border-[#1c2636] text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
          Observed Adversarial Techniques & Telemetry Evidence
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-slate-400 border-b border-[#1c2636] bg-[#080c14]">
                <th className="text-left p-3">Technique ID</th>
                <th className="text-left p-3">Tactic Class</th>
                <th className="text-left p-3">Forensic Detection Evidence</th>
                <th className="text-right p-3">ATT&CK Navigator</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1c2636]/60">
              {attackTechniques.length > 0 ? (
                attackTechniques.map((tech, i) => (
                  <tr key={i} className="hover:bg-[#121924]">
                    <td className="p-3 font-bold text-amber-400">{tech.id}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-[#121924] text-slate-300 border border-[#1c2636]">
                        {tech.tactic}
                      </span>
                    </td>
                    <td className="p-3 text-slate-200 font-sans">
                      {tech.evidence || "Observed during pipeline analysis"}
                    </td>
                    <td className="p-3 text-right">
                      <a
                        href={`https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-sky-400 hover:text-sky-300 underline text-xs font-mono"
                      >
                        [MITRE REF]
                      </a>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-slate-500 italic font-mono">
                    No MITRE ATT&CK techniques registered for this stage.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
