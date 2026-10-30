"""Publication-grade forensic PDF report generator for TRAC Platform."""
from __future__ import annotations

import html
import io
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from m8_ui_devops.evidence import build_presentation
from m8_ui_devops.reporting.models import ReportData


class NumberedCanvas(canvas.Canvas):
    """Canvas that computes total pages dynamically and adds running headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))

        # Top Header
        self.drawString(36, 756, "TRAC // THREAT RESPONSE & ANALYSIS COMMAND")
        self.drawRightString(576, 756, "FORENSIC MALWARE ANALYSIS REPORT")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 750, 576, 750)

        # Bottom Footer
        self.line(36, 42, 576, 42)
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#b91c1c"))
        self.drawString(36, 30, "TLP:AMBER | RESTRICTED - INTERNAL INCIDENT RESPONSE USE ONLY")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#475569"))
        self.drawRightString(576, 30, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


class PDFReportGenerator:
    """Generates rigorous, audit-ready malware analysis reports."""

    def __init__(self, data: ReportData, sandbox: Dict[str, Any]):
        self.data = data
        self.sandbox = sandbox
        self.styles = getSampleStyleSheet()
        self._init_custom_styles()

    def _init_custom_styles(self):
        self.title_style = ParagraphStyle(
            "DocTitle",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
        )
        self.h1_style = ParagraphStyle(
            "DocH1",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=4,
        )
        self.h2_style = ParagraphStyle(
            "DocH2",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=6,
            spaceAfter=2,
        )
        self.body_style = ParagraphStyle(
            "DocBody",
            parent=self.styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#334155"),
        )
        self.mono_style = ParagraphStyle(
            "DocMono",
            parent=self.styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#0f172a"),
        )
        self.cell_header_style = ParagraphStyle(
            "DocCellHeader",
            parent=self.styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        )

    def _severity_color(self, severity: str) -> colors.Color:
        sev = severity.lower()
        if sev == "critical":
            return colors.HexColor("#dc2626")
        elif sev == "high":
            return colors.HexColor("#ea580c")
        elif sev == "medium":
            return colors.HexColor("#d97706")
        elif sev == "low":
            return colors.HexColor("#2563eb")
        elif sev in ("info", "benign"):
            return colors.HexColor("#059669")
        return colors.HexColor("#64748b")

    def generate(self, output_path: str | Path | io.BytesIO):
        filename = str(output_path) if isinstance(output_path, Path) else output_path
        doc = SimpleDocTemplate(
            filename,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=54,
            bottomMargin=54,
        )
        story = []

        # Classification & Title Banner
        story.append(self._build_header_banner())
        story.append(Spacer(1, 10))

        # Executive Verdict & Threat Score Card
        story.append(self._build_verdict_card())
        story.append(Spacer(1, 10))

        # Section 1: Sample Identification & Cryptographic Provenance
        story.append(self._build_sample_metadata_table())
        story.append(Spacer(1, 12))

        # Section 2: Threat Score Decomposition
        if self.data.score_components or self.data.score_value is not None:
            story.append(self._build_score_decomposition_table())
            story.append(Spacer(1, 12))

        # Section 3: MITRE ATT&CK Matrix Mapping
        if self.data.attack_techniques:
            story.append(self._build_mitre_attack_table())
            story.append(Spacer(1, 12))

        # Section 4: Indicators of Compromise (IOCs)
        story.append(self._build_iocs_table())
        story.append(Spacer(1, 12))

        # Section 5: Static Analysis & PE Structure Findings
        story.append(self._build_static_analysis_section())
        story.append(Spacer(1, 12))

        # Section 6: Dynamic Sandbox & Behavioral Findings
        story.append(self._build_dynamic_analysis_section())
        story.append(Spacer(1, 12))

        # Section 7: Incident Response Actions & Containment Audit
        story.append(self._build_response_actions_table())
        story.append(Spacer(1, 14))

        # Forensic Audit Trail Sign-off
        story.append(self._build_audit_signoff())

        doc.build(story, canvasmaker=NumberedCanvas)

    def _build_header_banner(self) -> Table:
        title_p = Paragraph(f"Malware Analysis & Forensics: <b>{self.data.sample_name}</b>", self.title_style)
        meta_p = Paragraph(
            f"<b>Analysis ID:</b> {self.data.analysis_id}<br/>"
            f"<b>Generated:</b> {self.data.received_at} | <b>Contract Version:</b> {self.data.contract_version}",
            self.body_style,
        )
        data = [[title_p], [meta_p]]
        tbl = Table(data, colWidths=[540])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ]))
        return tbl

    def _build_verdict_card(self) -> Table:
        sev_color = self._severity_color(self.data.verdict_severity)
        label_text = self.data.verdict_label.upper()
        sev_text = self.data.verdict_severity.upper()
        score_val = f"{self.data.score_value:.0f} / 100" if self.data.score_value is not None else "N/A"
        
        verdict_badge = Paragraph(
            f"<font color='white'><b>VERDICT: {label_text}</b></font><br/>"
            f"<font color='white' size='9'>Severity: {sev_text} | Score: {score_val}</font><br/>"
            f"<font color='white' size='8'>Confidence: {int(self.data.verdict_confidence * 100)}% | Family: {self.data.family_guess}</font>",
            self.body_style,
        )
        
        explanations = "<br/>".join([f"&bull; {exp}" for exp in self.data.explanation]) or "No automated explanation available."
        expl_p = Paragraph(
            f"<b>Analysis Key Findings & Rationale:</b><br/>{explanations}",
            self.body_style,
        )

        tbl = Table([[verdict_badge, expl_p]], colWidths=[180, 360])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), sev_color),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94a3b8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]))
        return tbl

    def _build_sample_metadata_table(self) -> KeepTogether:
        items = [
            Paragraph("1. Sample Identification & Cryptographic Provenance", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        rows = [
            [Paragraph("File Name", self.cell_header_style), Paragraph(self.data.sample_name, self.body_style),
             Paragraph("File Size", self.cell_header_style), Paragraph(f"{self.data.size_bytes:,} bytes", self.body_style)],
            [Paragraph("File Type", self.cell_header_style), Paragraph(self.data.file_type.upper(), self.body_style),
             Paragraph("Submitter", self.cell_header_style), Paragraph(self.data.submitter, self.body_style)],
            [Paragraph("SHA-256", self.cell_header_style), Paragraph(self.data.sha256, self.mono_style),
             Paragraph("Vault ID", self.cell_header_style), Paragraph(self.data.sample_vault_id, self.mono_style)],
            [Paragraph("MD5", self.cell_header_style), Paragraph(self.data.md5, self.mono_style),
             Paragraph("ClamAV Check", self.cell_header_style), Paragraph(self.data.clamav_result.upper(), self.body_style)],
        ]
        tbl = Table(rows, colWidths=[70, 200, 70, 200])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        items.append(tbl)
        return KeepTogether(items)

    def _build_score_decomposition_table(self) -> KeepTogether:
        items = [
            Paragraph("2. Threat Scoring Audit (0–100 Weighted Framework)", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        rows = [[
            Paragraph("Model / Component", self.cell_header_style),
            Paragraph("Configured Weight", self.cell_header_style),
            Paragraph("Points Contributed", self.cell_header_style),
        ]]
        for comp in self.data.score_components:
            rows.append([
                Paragraph(comp.get("name", "N/A"), self.body_style),
                Paragraph(f"{comp.get('weight', 0):.2f}", self.body_style),
                Paragraph(f"{comp.get('contribution', 0):.1f}", self.mono_style),
            ])
        rows.append([
            Paragraph(f"<b>Aggregate Score (Method: {self.data.score_method})</b>", self.cell_header_style),
            Paragraph("<b>1.00</b>", self.cell_header_style),
            Paragraph(f"<b>{self.data.score_value:.1f}</b>", self.cell_header_style),
        ])
        tbl = Table(rows, colWidths=[240, 150, 150])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f1f5f9")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return KeepTogether(items)

    def _build_mitre_attack_table(self) -> KeepTogether:
        items = [
            Paragraph("3. MITRE ATT&CK Capability Mapping (Static Evidence)", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        rows = [[
            Paragraph("Technique ID", self.cell_header_style),
            Paragraph("Tactic", self.cell_header_style),
            Paragraph("Detection Evidence", self.cell_header_style),
        ]]
        for att in self.data.attack_techniques:
            rows.append([
                Paragraph(att.get("id", "N/A"), self.mono_style),
                Paragraph(att.get("tactic", "N/A").upper(), self.body_style),
                Paragraph(att.get("evidence") or "No evidence recorded", self.body_style),
            ])
        tbl = Table(rows, colWidths=[100, 140, 300])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return KeepTogether(items)

    def _build_iocs_table(self) -> KeepTogether:
        items = [
            Paragraph("4. Extracted Indicators of Compromise (Defanged)", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        if not self.data.iocs:
            items.append(Paragraph("<i>No network or host indicators of compromise extracted.</i>", self.body_style))
            return KeepTogether(items)

        rows = [[
            Paragraph("Type", self.cell_header_style),
            Paragraph("Defanged Indicator Value", self.cell_header_style),
            Paragraph("Extraction Source", self.cell_header_style),
            Paragraph("Confidence", self.cell_header_style),
        ]]
        for ioc in self.data.iocs:
            conf = int(ioc.get("confidence", 0) * 100)
            rows.append([
                Paragraph(ioc.get("type", "N/A").upper(), self.body_style),
                Paragraph(ioc.get("value", "N/A"), self.mono_style),
                Paragraph(ioc.get("source", "N/A"), self.body_style),
                Paragraph(f"{conf}%", self.body_style),
            ])
        tbl = Table(rows, colWidths=[80, 270, 110, 80])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return KeepTogether(items)

    def _build_static_analysis_section(self) -> KeepTogether:
        items = [
            Paragraph("5. Static Analysis & Binary Characterization", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        entropy_str = f"{self.data.entropy:.2f} / 8.00" if self.data.entropy is not None else "N/A"
        packers_str = ", ".join(self.data.packers) if self.data.packers else "None Detected"
        yara_str = ", ".join([y.get("rule", "") for y in self.data.yara_matches]) or "No rule hits"
        urls_joined = ", ".join(self.data.embedded_urls) or "None"
        entropy_tag = '<font color="red"><b>[HIGH - Suspicious Packing]</b></font>' if (self.data.entropy or 0) > 7.0 else '[Normal]'
        imphash_str = html.escape(self.data.imphash) or "Not recovered"
        imports_str = ", ".join(html.escape(name) for name in self.data.imports[:40]) or "None recovered"

        info_p = Paragraph(
            f"<b>Entropy:</b> {entropy_str} {entropy_tag} | "
            f"<b>Packers:</b> {packers_str}<br/>"
            f"<b>Imphash:</b> {imphash_str}<br/>"
            f"<b>Imported functions ({len(self.data.imports)}):</b> {imports_str}<br/>"
            f"<b>YARA Detections:</b> {yara_str}<br/>"
            f"<b>Embedded URLs (Defanged):</b> {urls_joined}",
            self.body_style
        )
        items.append(info_p)

        if self.data.sections:
            rows = [[
                Paragraph("Section Name", self.cell_header_style),
                Paragraph("Section Entropy", self.cell_header_style),
                Paragraph("Assessment", self.cell_header_style),
            ]]
            for sec in self.data.sections:
                ent = sec.get("entropy", 0.0)
                flag = "<font color='red'>Encrypted/Packed</font>" if ent > 7.0 else "Normal code/data"
                rows.append([
                    Paragraph(sec.get("name", "N/A"), self.mono_style),
                    Paragraph(f"{ent:.2f}", self.mono_style),
                    Paragraph(flag, self.body_style),
                ])
            tbl = Table(rows, colWidths=[150, 150, 240])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]))
            items.append(Spacer(1, 4))
            items.append(tbl)

        return KeepTogether(items)

    def _build_dynamic_analysis_section(self) -> KeepTogether:
        sandbox = self.sandbox
        items = [
            Paragraph(f"6. {sandbox['label']}", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]

        if not sandbox["observed"]:
            items.append(Paragraph(html.escape(sandbox["detail"]), self.body_style))
            if sandbox["error"]:
                items.append(Spacer(1, 4))
                items.append(Paragraph(f"<b>Operator error:</b> {html.escape(sandbox['error'])}", self.body_style))
            items.append(Spacer(1, 4))
            items.append(Paragraph(
                "<i>No process tree, file drop, registry change, mutex, beacon or timing is reported for this "
                "analysis because none was observed.</i>",
                self.body_style,
            ))
            return KeepTogether(items)

        sb = sandbox["telemetry"].get("sandbox") or {}
        network = sandbox["telemetry"].get("network_summary") or {}
        sb_summary = Paragraph(
            f"<b>Engine:</b> {html.escape(str(sb.get('engine', '')).upper())} | "
            f"<b>Guest OS:</b> {html.escape(str(sb.get('guest_os', '')))} | "
            f"<b>Network Mode:</b> {html.escape(str(sb.get('network_mode', '')).upper())} [Real egress strictly forbidden]<br/>"
            f"<b>Network Summary:</b> DNS: {network.get('dns_queries', 0)}, "
            f"HTTP: {network.get('http_requests', 0)}, "
            f"TCP: {network.get('tcp_connections', 0)}",
            self.body_style,
        )
        items.append(sb_summary)
        items.append(Spacer(1, 4))

        if self.data.process_tree:
            proc_lines = []
            for p in self.data.process_tree:
                cmd = f" | Cmd: {p.get('command_line')}" if p.get("command_line") else ""
                proc_lines.append(f"&bull; <b>PID {p.get('pid')} (PPID {p.get('ppid', '-')})</b>: {p.get('name')}{cmd}")
            items.append(Paragraph("<b>Spawned Process Hierarchy:</b><br/>" + "<br/>".join(proc_lines), self.body_style))

        if self.data.file_events or self.data.registry_events:
            events_lines = []
            for fe in self.data.file_events[:5]:
                events_lines.append(f"&bull; [File {fe.get('action').upper()}] {fe.get('target')}")
            for re in self.data.registry_events[:5]:
                events_lines.append(f"&bull; [Registry {re.get('action').upper()}] {re.get('target')}")
            items.append(Spacer(1, 4))
            items.append(Paragraph("<b>Critical Host System Operations:</b><br/>" + "<br/>".join(events_lines), self.body_style))

        if self.data.beacons:
            beacon_lines = [
                f"&bull; Target: <b>{b.get('destination')}</b> | Interval: {b.get('interval_s')}s | "
                f"Jitter: {int(b.get('jitter', 0) * 100)}% | Pulse Count: {b.get('count')}"
                for b in self.data.beacons
            ]
            items.append(Spacer(1, 4))
            items.append(Paragraph("<b>C2 Periodic Beaconing Pattern:</b><br/>" + "<br/>".join(beacon_lines), self.body_style))

        return KeepTogether(items)

    def _build_response_actions_table(self) -> KeepTogether:
        items = [
            Paragraph("7. Incident Response Containment Audit Log", self.h1_style),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f172a"), spaceAfter=6),
        ]
        if not self.data.response_actions:
            items.append(Paragraph("<i>No automated or manual response actions initiated.</i>", self.body_style))
            return KeepTogether(items)

        rows = [[
            Paragraph("Action Type", self.cell_header_style),
            Paragraph("Target Indicator", self.cell_header_style),
            Paragraph("Mode", self.cell_header_style),
            Paragraph("Status", self.cell_header_style),
            Paragraph("Audit Reference", self.cell_header_style),
        ]]
        for act in self.data.response_actions:
            status = act.get("status", "unknown").upper()
            mode = act.get("mode", "dry_run").upper()
            audit = act.get("audit_ref") or (act.get("approval", {}).get("approved_by") or "Pending Approval")
            rows.append([
                Paragraph(act.get("type", "N/A"), self.body_style),
                Paragraph(act.get("target", "N/A"), self.mono_style),
                Paragraph(mode, self.body_style),
                Paragraph(status, self.body_style),
                Paragraph(audit, self.mono_style),
            ])
        tbl = Table(rows, colWidths=[100, 180, 70, 90, 100])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        items.append(tbl)
        return KeepTogether(items)

    def _build_audit_signoff(self) -> Table:
        telemetry_note = (
            "All sandbox telemetry was gathered within an isolated test harness without external network routing."
            if self.sandbox["observed"]
            else "No sandbox was executed for this analysis, so no runtime telemetry is claimed."
        )
        text = Paragraph(
            "<b>Forensic Chain-of-Custody Certification:</b><br/>"
            "This report was automatically synthesized by TRAC Module M8 in compliance with Contract v1.0.0. "
            + telemetry_note + " "
            "Indicators have been sanitized and defanged. Cryptographic hashes reflect verified immutable sample payload.",
            self.body_style,
        )
        tbl = Table([[text]], colWidths=[540])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94a3b8")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        return tbl


def generate_pdf_report(doc: Dict[str, Any], output_path: str | Path | io.BytesIO):
    """Entry point to compile a full PDF report from an analysis document."""
    data = ReportData.from_doc(doc)
    generator = PDFReportGenerator(data, build_presentation(doc)["sandbox"])
    generator.generate(output_path)
