"""Interactive and print-ready HTML incident report generator for TRAC Platform."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict

from m8_ui_devops.evidence import build_presentation
from m8_ui_devops.reporting.models import ReportData


def generate_html_report(doc: Dict[str, Any], output_path: str | Path | None = None) -> str:
    """Compile a self-contained, responsive HTML report from analysis document."""
    d = ReportData.from_doc(doc)
    sandbox = build_presentation(doc)["sandbox"]

    # Severity styling
    sev = d.verdict_severity.lower()
    sev_colors = {
        "critical": {"bg": "#7f1d1d", "text": "#fecaca", "border": "#dc2626"},
        "high": {"bg": "#7c2d12", "text": "#fed7aa", "border": "#ea580c"},
        "medium": {"bg": "#78350f", "text": "#fef3c7", "border": "#d97706"},
        "low": {"bg": "#1e3a8a", "text": "#bfdbfe", "border": "#2563eb"},
        "info": {"bg": "#064e3b", "text": "#a7f3d0", "border": "#059669"},
        "benign": {"bg": "#064e3b", "text": "#a7f3d0", "border": "#059669"},
    }.get(sev, {"bg": "#334155", "text": "#e2e8f0", "border": "#64748b"})

    score_val = f"{d.score_value:.0f}" if d.score_value is not None else "N/A"

    # Explanations
    expl_items = "".join([f"<li>{html.escape(e)}</li>" for e in d.explanation]) or "<li>No automated reasoning available.</li>"

    # Score components
    score_rows = ""
    for c in d.score_components:
        score_rows += f"""
        <tr>
            <td class="font-medium">{html.escape(c.get('name', 'N/A'))}</td>
            <td class="text-right font-mono">{c.get('weight', 0):.2f}</td>
            <td class="text-right font-mono font-bold text-accent">{c.get('contribution', 0):.1f}</td>
        </tr>
        """
    if d.score_components:
        score_rows += f"""
        <tr class="total-row">
            <td><strong>Total Score ({html.escape(d.score_method)})</strong></td>
            <td class="text-right font-mono">1.00</td>
            <td class="text-right font-mono font-bold">{score_val} / 100</td>
        </tr>
        """

    # ATT&CK rows
    attack_rows = ""
    for a in d.attack_techniques:
        attack_rows += f"""
        <tr>
            <td class="font-mono text-amber">{html.escape(a.get('id', 'N/A'))}</td>
            <td class="font-semibold">{html.escape(a.get('tactic', 'N/A').upper())}</td>
            <td>{html.escape(a.get('evidence') or 'No evidence recorded')}</td>
        </tr>
        """

    # IOC rows
    ioc_rows = ""
    for ioc in d.iocs:
        conf = int(ioc.get("confidence", 0) * 100)
        ioc_rows += f"""
        <tr>
            <td><span class="badge badge-subtle">{html.escape(ioc.get('type', 'N/A').upper())}</span></td>
            <td class="font-mono text-cyan">{html.escape(ioc.get('value', 'N/A'))}</td>
            <td>{html.escape(ioc.get('source', 'N/A'))}</td>
            <td class="font-mono">{conf}%</td>
        </tr>
        """

    # Process tree
    proc_list = ""
    for p in d.process_tree:
        cmd = f" <span class='text-dim font-mono text-xs'>({html.escape(p.get('command_line'))})</span>" if p.get('command_line') else ""
        proc_list += f"""
        <div class="tree-item">
            <span class="pid-badge">PID {p.get('pid')}</span>
            <span class="ppid-label">PPID {p.get('ppid', '-')}</span>
            <strong class="font-mono">{html.escape(p.get('name', 'unnamed'))}</strong>
            {cmd}
        </div>
        """

    # Sandbox block: runtime facts appear only when the sandbox actually ran.
    if sandbox["observed"]:
        sb = sandbox["telemetry"].get("sandbox") or {}
        sandbox_block = f"""
            <div style="margin-bottom: 12px; font-size: 12px; color: var(--text-dim);">
                Engine: <span class="font-bold text-white">{html.escape(str(sb.get('engine', '')).upper())}</span> |
                Guest: <span class="font-bold text-white">{html.escape(str(sb.get('guest_os', '')))}</span> |
                Network Mode: <span class="font-bold text-white">{html.escape(str(sb.get('network_mode', '')).upper())}</span>
            </div>
            {proc_list or '<div class="text-muted">The sandbox observed no spawned processes.</div>'}
        """
    else:
        sandbox_block = f"""
            <div style="font-size: 12px; color: var(--text-dim);">{html.escape(sandbox['detail'])}</div>
            <div class="text-muted" style="margin-top: 10px; font-size: 12px;">
                No process tree, file drop, registry change, mutex, beacon or timing is reported for this analysis
                because none was observed.
            </div>
        """
        if sandbox["error"]:
            sandbox_block += f"""
            <div style="margin-top: 10px; padding: 8px; border: 1px solid var(--danger); border-radius: 4px; color: #fca5a5; font-size: 12px;">
                Operator error: {html.escape(sandbox['error'])}
            </div>
        """

    # Static evidence recovered by M2 from the submitted binary.
    entropy_str = f"{d.entropy:.2f} / 8.00" if d.entropy is not None else "N/A"
    packers_str = ", ".join(d.packers) if d.packers else "None detected"
    imphash_str = html.escape(d.imphash) if d.imphash else "Not recovered"
    section_rows = ""
    for sec in d.sections:
        section_rows += f"""
        <tr>
            <td class="font-mono text-cyan">{html.escape(str(sec.get('name', 'N/A')))}</td>
            <td class="text-right font-mono">{float(sec.get('entropy') or 0.0):.2f}</td>
            <td class="text-right font-mono">{int(sec.get('raw_size') or 0):,}</td>
        </tr>
        """
    import_items = "".join(f"<li>{html.escape(name)}</li>" for name in d.imports[:60])
    static_block = f"""
            <div class="grid-2">
                <table class="table">
                    <tr><td class="text-dim">File Class:</td><td class="font-bold">{html.escape(d.file_class.upper())}</td></tr>
                    <tr><td class="text-dim">Entropy:</td><td class="font-mono">{entropy_str}</td></tr>
                    <tr><td class="text-dim">Packers:</td><td>{html.escape(packers_str)}</td></tr>
                    <tr><td class="text-dim">Imphash:</td><td class="font-mono text-dim">{imphash_str}</td></tr>
                </table>
                <table class="table">
                    <thead><tr><th>PE Section</th><th class="text-right">Entropy</th><th class="text-right">Raw Size</th></tr></thead>
                    <tbody>{section_rows or '<tr><td colspan="3" class="text-muted">No PE section table (file class is not PE).</td></tr>'}</tbody>
                </table>
            </div>
            <div style="margin-top: 10px;">
                <div class="text-dim" style="font-size: 11px; margin-bottom: 4px;">
                    Imported functions ({len(d.imports)}) recovered from the import directory:
                </div>
                <ul class="font-mono" style="font-size: 11px; margin: 0; padding-left: 18px;">{import_items or '<li>No imports recovered.</li>'}</ul>
            </div>
    """

    # Actions rows
    act_rows = ""
    for act in d.response_actions:
        st = act.get("status", "unknown").lower()
        st_badge = "badge-danger" if st in ("awaiting_approval", "rejected") else ("badge-success" if st == "executed" else "badge-subtle")
        act_rows += f"""
        <tr>
            <td class="font-semibold">{html.escape(act.get('type', 'N/A'))}</td>
            <td class="font-mono">{html.escape(act.get('target', 'N/A'))}</td>
            <td><span class="badge badge-outline">{html.escape(act.get('mode', 'dry_run').upper())}</span></td>
            <td><span class="badge {st_badge}">{html.escape(act.get('status', 'N/A').upper())}</span></td>
            <td class="font-mono text-xs">{html.escape(act.get('audit_ref') or 'N/A')}</td>
        </tr>
        """

    # Full HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRAC Forensic Report - {html.escape(d.sample_name)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-raised: #1f2937;
            --border: #374151;
            --border-light: #4b5563;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
            --text-muted: #6b7280;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 32px 16px;
            font-size: 14px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        .header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .classification-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 16px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
        }}
        .tlp-badge {{
            color: #f87171;
            background: rgba(239, 68, 68, 0.12);
            padding: 4px 8px;
            border-radius: 4px;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .title-row {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .title-row h1 {{
            font-size: 20px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.01em;
        }}
        .verdict-banner {{
            display: grid;
            grid-template-columns: 280px 1fr;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        .verdict-left {{
            background: {sev_colors['bg']};
            border-right: 1px solid {sev_colors['border']};
            padding: 24px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .verdict-tag {{
            font-size: 20px;
            font-weight: 800;
            letter-spacing: 0.05em;
            color: {sev_colors['text']};
            margin-bottom: 4px;
        }}
        .verdict-right {{
            padding: 20px 24px;
            background: var(--surface);
        }}
        .verdict-right h3 {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            margin-bottom: 8px;
        }}
        .verdict-right ul {{
            padding-left: 20px;
            color: var(--text);
            font-size: 13px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 20px 24px;
            margin-bottom: 24px;
        }}
        .card-header {{
            font-size: 14px;
            font-weight: 700;
            color: #fff;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
        }}
        .table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .table th {{
            text-align: left;
            padding: 8px 12px;
            background: var(--surface-raised);
            color: var(--text-dim);
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
        }}
        .table td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
        }}
        .table tr:last-child td {{
            border-bottom: none;
        }}
        .total-row td {{
            background: rgba(255, 255, 255, 0.03);
            border-top: 1px solid var(--border-light);
            border-bottom: none;
        }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }}
        .text-dim {{ color: var(--text-dim); }}
        .text-muted {{ color: var(--text-muted); }}
        .text-cyan {{ color: #38bdf8; }}
        .text-amber {{ color: #fbbf24; }}
        .text-right {{ text-align: right; }}
        .font-semibold {{ font-weight: 600; }}
        .font-bold {{ font-weight: 700; }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .badge-subtle {{ background: rgba(255, 255, 255, 0.08); color: var(--text-dim); }}
        .badge-outline {{ border: 1px solid var(--border-light); color: var(--text-dim); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #86efac; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .tree-item {{
            padding: 8px 12px;
            background: var(--surface-raised);
            border-radius: 4px;
            margin-bottom: 6px;
            border-left: 3px solid var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .pid-badge {{
            background: rgba(56, 189, 248, 0.2);
            color: #7dd3fc;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 11px;
            font-weight: bold;
        }}
        .ppid-label {{
            color: var(--text-muted);
            font-size: 11px;
            font-family: monospace;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        .footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 11px;
            margin-top: 32px;
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .container {{ max-width: 100%; }}
            .card, .header, .verdict-banner {{ border-color: #ccc; background: #fff; color: #000; }}
            .table th {{ background: #f0f0f0; color: #000; }}
            .table td {{ border-color: #ddd; color: #000; }}
            .verdict-left {{ background: #eee !important; color: #000 !important; }}
            .verdict-tag {{ color: #000 !important; }}
            .text-cyan, .text-amber {{ color: #000 !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Classification Bar & Header -->
        <div class="header">
            <div class="classification-bar">
                <span>TRAC // THREAT RESPONSE & ANALYSIS COMMAND</span>
                <span class="tlp-badge">TLP:AMBER | RESTRICTED // SOC-IR ONLY</span>
                <span>CONTRACT V{html.escape(d.contract_version)}</span>
            </div>
            <div class="title-row">
                <div>
                    <h1>Malware Analysis Forensic Dossier: {html.escape(d.sample_name)}</h1>
                    <div class="text-dim" style="font-size: 12px; margin-top: 4px;">
                        Analysis ID: <span class="font-mono">{html.escape(d.analysis_id)}</span> | Received: {html.escape(d.received_at)}
                    </div>
                </div>
            </div>
        </div>

        <!-- Verdict Banner -->
        <div class="verdict-banner">
            <div class="verdict-left">
                <div class="verdict-tag">{html.escape(d.verdict_label.upper())}</div>
                <div style="font-size: 12px; font-weight: 600; opacity: 0.9; margin-bottom: 8px;">
                    Severity: {html.escape(d.verdict_severity.upper())} | Score: {score_val} / 100
                </div>
                <div style="font-size: 11px; opacity: 0.85;">
                    Confidence: {int(d.verdict_confidence * 100)}%<br/>
                    Classification: {html.escape(d.family_guess)}
                </div>
            </div>
            <div class="verdict-right">
                <h3>Executive Findings & Detection Rationale</h3>
                <ul>{expl_items}</ul>
            </div>
        </div>

        <!-- Metadata Section -->
        <div class="card">
            <div class="card-header">1. Sample Cryptographic Identity</div>
            <div class="grid-2">
                <table class="table">
                    <tr><td class="text-dim">File Name:</td><td class="font-bold">{html.escape(d.sample_name)}</td></tr>
                    <tr><td class="text-dim">File Type:</td><td>{html.escape(d.file_type.upper())}</td></tr>
                    <tr><td class="text-dim">File Size:</td><td>{d.size_bytes:,} bytes</td></tr>
                    <tr><td class="text-dim">Submitter:</td><td>{html.escape(d.submitter)}</td></tr>
                </table>
                <table class="table">
                    <tr><td class="text-dim">SHA-256:</td><td class="font-mono text-cyan" style="font-size: 11px;">{html.escape(d.sha256)}</td></tr>
                    <tr><td class="text-dim">MD5:</td><td class="font-mono text-dim">{html.escape(d.md5)}</td></tr>
                    <tr><td class="text-dim">Vault ID:</td><td class="font-mono text-dim">{html.escape(d.sample_vault_id)}</td></tr>
                    <tr><td class="text-dim">AV Result:</td><td>{html.escape(d.clamav_result.upper())}</td></tr>
                </table>
            </div>
        </div>

        <!-- Static Analysis Evidence -->
        <div class="card">
            <div class="card-header">2. Static Analysis Evidence (Parsed By M2)</div>
            {static_block}
        </div>

        <!-- Threat Score Audit -->
        <div class="card">
            <div class="card-header">3. Weighted Threat Score Decomposition</div>
            <table class="table">
                <thead>
                    <tr><th>Component Model</th><th class="text-right">Weight</th><th class="text-right">Contribution</th></tr>
                </thead>
                <tbody>{score_rows}</tbody>
            </table>
        </div>

        <!-- MITRE ATT&CK Matrix -->
        {f'''
        <div class="card">
            <div class="card-header">4. MITRE ATT&CK Capability Mapping (Static Evidence)</div>
            <table class="table">
                <thead><tr><th>Technique ID</th><th>Tactic</th><th>Evidence</th></tr></thead>
                <tbody>{attack_rows}</tbody>
            </table>
        </div>
        ''' if attack_rows else ''}

        <!-- Indicators of Compromise -->
        <div class="card">
            <div class="card-header">5. Indicators of Compromise (Defanged)</div>
            <table class="table">
                <thead><tr><th>Type</th><th>Defanged Value</th><th>Source</th><th>Confidence</th></tr></thead>
                <tbody>{ioc_rows or '<tr><td colspan="4" class="text-muted">No IOCs identified.</td></tr>'}</tbody>
            </table>
        </div>

        <!-- Sandbox Telemetry -->
        <div class="card">
            <div class="card-header">6. {html.escape(sandbox['label'])}</div>
            {sandbox_block}
        </div>

        <!-- Incident Response Actions -->
        <div class="card">
            <div class="card-header">7. Incident Containment & Response Log</div>
            <table class="table">
                <thead><tr><th>Action</th><th>Target</th><th>Mode</th><th>Status</th><th>Audit Ref</th></tr></thead>
                <tbody>{act_rows or '<tr><td colspan="5" class="text-muted">No response actions triggered.</td></tr>'}</tbody>
            </table>
        </div>

        <div class="footer">
            CONFIDENTIAL // GENERATED BY TRAC PLATFORM MODULE M8 (CONTRACT V1.0.0)<br/>
            Forensic analysis generated in isolated lab network. No live outbound connections established.
        </div>
    </div>
</body>
</html>"""

    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html_content, encoding="utf-8")

    return html_content
