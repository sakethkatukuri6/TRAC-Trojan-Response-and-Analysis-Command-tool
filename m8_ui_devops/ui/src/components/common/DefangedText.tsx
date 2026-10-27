import React, { useState } from "react";

export function DefangedText({ value, type }: { value: string; type?: string }) {
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);

  // Un-defang helper
  const rawValue = value
    .replace(/\[\.\]/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/hxxp/gi, "http");

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="inline-flex items-center gap-2 group max-w-full font-mono">
      <span className="text-xs text-sky-400 break-all bg-[#080c14] px-1.5 py-0.5 rounded border border-[#1c2636]">
        {showRaw ? rawValue : value}
      </span>

      <div className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1">
        <button
          type="button"
          onClick={() => handleCopy(showRaw ? rawValue : value)}
          title="Copy indicator value"
          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#151d2a] hover:bg-[#1e293b] text-slate-300 border border-[#2c3b52]"
        >
          {copied ? "COPIED" : "COPY"}
        </button>

        {value !== rawValue && (
          <button
            type="button"
            onClick={() => setShowRaw(!showRaw)}
            title={showRaw ? "Display defanged" : "Reveal active raw indicator"}
            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
              showRaw
                ? "bg-[#2d0a0a] text-red-300 border-[#b71c1c]"
                : "bg-[#151d2a] text-slate-400 border-[#2c3b52] hover:text-slate-200"
            }`}
          >
            {showRaw ? "RAW" : "DEFANGED"}
          </button>
        )}
      </div>
    </div>
  );
}
