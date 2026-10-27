import React from "react";
import { ScoreSection } from "../../types/contract";

export function ScoreGauge({ score }: { score?: ScoreSection }) {
  if (!score || score.value === undefined) {
    return (
      <div className="flex flex-col items-center justify-center p-4 bg-[#080c14] rounded border border-[#1c2636]">
        <span className="text-[11px] text-slate-500 uppercase tracking-widest font-mono">Threat Score</span>
        <span className="text-xl font-mono text-slate-400 mt-1">N/A</span>
        <span className="text-[11px] text-slate-600 mt-1 font-mono">Unscored / Staged</span>
      </div>
    );
  }

  const val = Math.min(100, Math.max(0, score.value));
  let color = "text-emerald-400 border-[#1b5e20] bg-[#06240d]/40";
  let barColor = "bg-[#2e7d32]";
  let label = "BENIGN / LOW RISK";

  if (val >= 60) {
    color = "text-red-400 border-[#b71c1c] bg-[#2d0a0a]/40";
    barColor = "bg-[#c62828]";
    label = "MALICIOUS / HIGH RISK";
  } else if (val > 30) {
    color = "text-amber-400 border-[#e65100] bg-[#2d1e04]/40";
    barColor = "bg-[#f57f17]";
    label = "SUSPICIOUS";
  }

  return (
    <div className={`flex flex-col p-4 rounded border ${color}`}>
      <div className="flex items-baseline justify-between font-mono">
        <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Threat Score ({score.method})
        </span>
        <span className="text-2xl font-black tracking-tight">{val.toFixed(0)} <span className="text-xs font-normal text-slate-400">/ 100</span></span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-[#080c14] rounded-full h-2 mt-2 overflow-hidden border border-[#1c2636]">
        <div
          className={`h-full ${barColor} transition-all duration-500`}
          style={{ width: `${val}%` }}
        />
      </div>

      <div className="flex justify-between items-center mt-2 text-[11px] font-mono">
        <span className="font-semibold">{label}</span>
        <span className="text-slate-400">Model: {score.model_version || "default"}</span>
      </div>
    </div>
  );
}
