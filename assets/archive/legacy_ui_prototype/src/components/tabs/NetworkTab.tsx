import React from "react";
import { AnalysisDocument } from "../../types/contract";
import { DefangedText } from "../common/DefangedText";

export function NetworkTab({ analysis }: { analysis: AnalysisDocument }) {
  const { dynamic, iocs } = analysis;
  const net = dynamic?.network_summary;
  const beacons = iocs?.beacons;

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* Network Traffic Volume KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">DNS Queries</div>
          <div className="text-2xl font-bold font-mono text-sky-400 mt-1">{net?.dns_queries ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Resolution attempts</div>
        </div>

        <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">HTTP Requests</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{net?.http_requests ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Simulated outbound GET/POST</div>
        </div>

        <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">TCP Handshakes</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{net?.tcp_connections ?? 0}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">SYN/ACK socket sessions</div>
        </div>

        <div className="bg-[#0b1017] border border-[#1c2636] rounded p-4">
          <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">PCAP Packet Capture</div>
          <div className="text-xs font-bold font-mono text-slate-200 mt-2 truncate">
            {net?.pcap_vault_id ? "Stored in Vault" : "Simulated Pcap"}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Wireshark packet stream</div>
        </div>
      </div>

      {/* C2 Beaconing Periodic Analysis */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-5 space-y-4">
        <div className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono border-b border-[#1c2636] pb-2 flex items-center justify-between">
          <span>Command & Control (C2) Periodic Heartbeat Analysis (M4)</span>
          <span className="text-xs text-red-400 font-bold font-mono">
            {beacons && beacons.length > 0 ? "[CONFIRMED C2 BEACONING]" : "[NO PERIODIC SIGNALS]"}
          </span>
        </div>

        {beacons && beacons.length > 0 ? (
          <div className="space-y-3 font-mono">
            {beacons.map((b, i) => (
              <div
                key={i}
                className="bg-[#080c14] p-4 rounded border border-[#b71c1c]/60 flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Target C2 Host:</span>
                    <DefangedText value={b.destination} type="domain" />
                  </div>
                  <div className="text-xs text-slate-400 font-sans">
                    Calculated Periodicity:{" "}
                    <span className="text-red-300 font-semibold font-mono">
                      Every ~{b.interval_s} seconds (&plusmn;{Math.round((b.jitter ?? 0) * 100)}% jitter)
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono">
                  <div className="text-right">
                    <div className="text-slate-500 text-[10px] uppercase">Interval</div>
                    <div className="font-bold text-slate-100">{b.interval_s}s</div>
                  </div>
                  <div className="text-right">
                    <div className="text-slate-500 text-[10px] uppercase">Jitter Delta</div>
                    <div className="font-bold text-amber-400">{Math.round((b.jitter ?? 0) * 100)}%</div>
                  </div>
                  <div className="text-right">
                    <div className="text-slate-500 text-[10px] uppercase">Pulse Count</div>
                    <div className="font-bold text-sky-400">{b.count ?? 2} hits</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-[#2d0a0a] text-red-300 border border-[#b71c1c] font-bold text-[11px] uppercase">
                    C2 ACTIVE
                  </span>
                </div>
              </div>
            ))}

            <div className="p-3 rounded bg-[#080c14] border border-[#1c2636] text-xs text-slate-400 font-sans">
              <strong className="text-slate-200">Analyst Remediation Notice:</strong> Periodic callback heartbeat indicates automated C2 check-in.
              Recommended response: Authorize host isolation and DNS/IP sinkhole containment in Response tab.
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-500 italic py-4 text-center font-mono">
            No periodic network beacons or automated interval heartbeats detected during analysis window.
          </div>
        )}
      </div>
    </div>
  );
}
