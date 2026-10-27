import React, { useEffect } from "react";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  maxWidth?: string;
}

export function Modal({ isOpen, onClose, title, children, maxWidth = "max-w-2xl" }: ModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div
        className={`w-full ${maxWidth} bg-[#0b1017] border border-[#1c2636] rounded shadow-2xl overflow-hidden flex flex-col max-h-[90vh] anim-layer-1`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-[#1c2636] bg-[#06090e]">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200 font-mono">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-xs font-mono px-2 py-0.5 rounded border border-slate-700 hover:border-slate-500 transition"
            aria-label="Close"
          >
            CLOSE
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs text-slate-300 font-sans">
          {children}
        </div>
      </div>
    </div>
  );
}
