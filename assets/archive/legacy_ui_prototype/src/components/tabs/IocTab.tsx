import React, { useState, useMemo } from "react";
import { AnalysisDocument, IOCItem } from "../../types/contract";
import { DefangedText } from "../common/DefangedText";

export function IocTab({ analysis }: { analysis: AnalysisDocument }) {
  const { iocs, sample } = analysis;
  const items = iocs?.items || [];

  const [filterType, setFilterType] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [copiedAll, setCopiedAll] = useState(false);

  const types = useMemo(() => {
    const set = new Set<string>();
    items.forEach((i) => set.add(i.type));
    return ["ALL", ...Array.from(set)];
  }, [items]);

  const filtered = useMemo(() => {
    return items.filter((item) => {
      if (filterType !== "ALL" && item.type !== filterType) return false;
      if (search) {
        const q = search.toLowerCase();
        return item.value.toLowerCase().includes(q) || item.source.toLowerCase().includes(q);
      }
      return true;
    });
  }, [items, filterType, search]);

  const handleCopyAll = () => {
    const list = items.map((i) => `${i.type.toUpperCase()}: ${i.value}`).join("\n");
    navigator.clipboard.writeText(list);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const handleExportCsv = () => {
    const rows = [
      "type,value,source,confidence",
      ...items.map((i) => `"${i.type}","${i.value}","${i.source}",${i.confidence}`),
    ];
    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `iocs_${sample.original_name}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportStix = () => {
    const stix = {
      type: "bundle",
      id: `bundle--${analysis.analysis_id}`,
      spec_version: "2.1",
      objects: items.map((i, idx) => ({
        type: "indicator",
        id: `indicator--${analysis.analysis_id}-${idx}`,
        pattern_type: "stix",
        pattern: `[${i.type}:value = '${i.value}']`,
        confidence: Math.round(i.confidence * 100),
      })),
    };
    const blob = new Blob([JSON.stringify(stix, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `stix_bundle_${sample.original_name}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4 anim-layer-5 font-sans">
      {/* Defanged Safety Alert Bar */}
      <div className="bg-[#0b1017] border border-[#1c2636] p-3.5 rounded flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-slate-300">
        <div>
          <strong className="font-mono text-white tracking-wider">DEFANGING PROTOCOL:</strong> All threat indicators are
          sanitized with safe tokens (<code className="text-sky-400">hxxp://</code>, <code className="text-sky-400">[.]</code>) to eliminate accidental live network resolution.
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleCopyAll}
            className="px-2.5 py-1 rounded bg-[#121924] hover:bg-[#1c2636] text-slate-200 border border-[#1c2636] font-mono text-xs transition"
          >
            {copiedAll ? "[COPIED ALL]" : "[COPY ALL DEFANGED]"}
          </button>
          <button
            type="button"
            onClick={handleExportCsv}
            className="px-2.5 py-1 rounded bg-[#121924] hover:bg-[#1c2636] text-slate-200 border border-[#1c2636] font-mono text-xs transition"
          >
            [EXPORT CSV]
          </button>
          <button
            type="button"
            onClick={handleExportStix}
            className="px-2.5 py-1 rounded bg-[#1565c0] hover:bg-[#1976d2] text-white font-mono text-xs font-bold border border-[#1e88e5] transition"
          >
            [STIX 2.1 BUNDLE]
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded p-3 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Type Filter Buttons */}
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
          {types.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setFilterType(t)}
              className={`px-3 py-1 rounded text-xs font-mono uppercase tracking-wider transition ${
                filterType === t
                  ? "bg-[#1565c0] text-white font-bold border border-[#1e88e5]"
                  : "bg-[#080c14] text-slate-400 hover:text-slate-200 border border-[#1c2636]"
              }`}
            >
              {t} {t !== "ALL" && `(${items.filter((i) => i.type === t).length})`}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="w-full md:w-64">
          <input
            type="text"
            placeholder="Search indicators / source..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#080c14] border border-[#1c2636] rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* IOC Table */}
      <div className="bg-[#0b1017] border border-[#1c2636] rounded overflow-hidden">
        <div className="p-3 bg-[#080c14] border-b border-[#1c2636] flex justify-between items-center text-xs font-mono">
          <span className="text-slate-400">
            Showing <strong className="text-slate-100">{filtered.length}</strong> of {items.length} indicators
          </span>
          <span className="text-slate-500">Extraction Stage: M4 IOC Done</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-slate-400 border-b border-[#1c2636] bg-[#080c14]">
                <th className="text-left p-3">Indicator Type</th>
                <th className="text-left p-3">Defanged Value (Hover for Raw)</th>
                <th className="text-left p-3">Telemetry Source</th>
                <th className="text-right p-3">Confidence Rating</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1c2636]/60">
              {filtered.length > 0 ? (
                filtered.map((item, idx) => {
                  const conf = Math.round(item.confidence * 100);
                  return (
                    <tr key={idx} className="hover:bg-[#121924]">
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase bg-[#121924] text-slate-300 border border-[#1c2636]">
                          {item.type}
                        </span>
                      </td>
                      <td className="p-3">
                        <DefangedText value={item.value} type={item.type} />
                      </td>
                      <td className="p-3">
                        <span className="text-slate-400">{item.source}</span>
                      </td>
                      <td className="p-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <div className="w-16 bg-[#080c14] rounded-full h-1.5 overflow-hidden border border-[#1c2636]">
                            <div
                              className={`h-full ${
                                conf >= 80 ? "bg-emerald-400" : conf >= 60 ? "bg-amber-400" : "bg-sky-400"
                              }`}
                              style={{ width: `${conf}%` }}
                            />
                          </div>
                          <span className="font-bold text-slate-200">{conf}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-slate-500 italic font-mono">
                    No matching indicators found for current query.
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
