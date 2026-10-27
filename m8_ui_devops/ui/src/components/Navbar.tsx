import React from "react";
import { ApiHealthStatus } from "../api/client";

interface NavbarProps {
  currentRole: "analyst" | "approver" | "auditor";
  onRoleChange: (role: "analyst" | "approver" | "auditor") => void;
  apiHealth: ApiHealthStatus;
  onOpenUpload: () => void;
  onRefresh: () => void;
}

export function Navbar({ currentRole, onRoleChange, apiHealth, onOpenUpload, onRefresh }: NavbarProps) {
  return (
    <header className="bg-[#080c14] border-b border-[#1c2636] sticky top-0 z-40 px-4 lg:px-6 py-2.5 anim-layer-1">
      <div className="flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 bg-[#b71c1c] border border-[#ef5350] rounded-sm transform rotate-45 inline-block" />
            <span className="font-mono font-black text-slate-100 text-sm tracking-widest uppercase">
              TRAC <span className="text-slate-600 font-light">//</span> COMMAND
            </span>
          </div>
          <span className="hidden sm:inline-block text-[11px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-[#2d0a0a] text-red-400 border border-[#b71c1c] font-bold">
            TLP:AMBER
          </span>
          <span className="hidden md:inline-block text-[11px] font-mono text-slate-500">
            CONTRACT V1.0.0
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* API Health indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#0b1017] border border-[#1c2636] text-xs font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                apiHealth.online ? "bg-emerald-500 animate-pulse" : "bg-amber-500"
              }`}
            />
            <span className={apiHealth.online ? "text-emerald-400 font-semibold" : "text-amber-400 font-semibold"}>
              {apiHealth.online ? `M7 LIVE (${apiHealth.latencyMs}ms)` : "OFFLINE LAB"}
            </span>
          </div>

          {/* Role selector */}
          <div className="flex items-center gap-1.5 bg-[#0b1017] px-2.5 py-1 rounded border border-[#1c2636] text-xs font-mono">
            <span className="text-slate-500 hidden sm:inline">ROLE:</span>
            <select
              value={currentRole}
              onChange={(e) => onRoleChange(e.target.value as any)}
              className="bg-transparent text-slate-200 font-semibold focus:outline-none cursor-pointer"
            >
              <option value="analyst" className="bg-[#0b1017] text-slate-200">Analyst (Tier 2)</option>
              <option value="approver" className="bg-[#0b1017] text-slate-200">Approver / Admin</option>
              <option value="auditor" className="bg-[#0b1017] text-slate-200">Compliance Auditor</option>
            </select>
          </div>

          {/* Quick Upload Button */}
          <button
            type="button"
            onClick={onOpenUpload}
            className="px-3 py-1 rounded text-xs font-bold font-mono bg-[#b71c1c] hover:bg-[#c62828] text-white border border-[#d32f2f] transition flex items-center gap-1.5"
          >
            <span>+</span> <span>INTAKE SAMPLE</span>
          </button>

          {/* Refresh */}
          <button
            type="button"
            onClick={onRefresh}
            title="Refresh current state"
            className="px-2.5 py-1 rounded text-xs font-mono bg-[#0b1017] hover:bg-[#151d2a] text-slate-400 hover:text-slate-200 border border-[#1c2636] transition"
          >
            REFRESH
          </button>
        </div>
      </div>
    </header>
  );
}
