"""Data models and normalization for TRAC analysis reporting."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ReportData:
    contract_version: str
    analysis_id: str
    sample_vault_id: str
    sample_name: str
    sha256: str
    md5: str
    size_bytes: int
    file_type: str
    received_at: str
    submitter: str
    clamav_result: str
    
    # Verdict & Score
    verdict_label: str
    verdict_severity: str
    verdict_confidence: float
    family_guess: str
    behavior_tags: List[str]
    explanation: List[str]
    score_value: Optional[float]
    score_method: str
    score_components: List[Dict[str, Any]]
    
    # Static
    static_status: str
    file_class: str
    entropy: Optional[float]
    packers: List[str]
    yara_matches: List[Dict[str, Any]]
    imports: List[str]
    imphash: str
    sections: List[Dict[str, Any]]
    embedded_urls: List[str]
    
    # Dynamic
    dynamic_status: str
    sandbox_engine: str
    guest_os: str
    network_mode: str
    process_tree: List[Dict[str, Any]]
    file_events: List[Dict[str, Any]]
    registry_events: List[Dict[str, Any]]
    mutexes: List[str]
    dropped_files: List[Dict[str, Any]]
    network_summary: Dict[str, Any]
    
    # IOCs & Beacons
    iocs: List[Dict[str, Any]]
    attack_techniques: List[Dict[str, Any]]
    beacons: List[Dict[str, Any]]
    
    # Detections
    detection_items: List[Dict[str, Any]]
    intel_hits: List[Dict[str, Any]]
    
    # Response actions
    response_actions: List[Dict[str, Any]]
    
    # Pipeline status
    pipeline_status: str
    pipeline_stages: Dict[str, str]

    @classmethod
    def from_doc(cls, doc: Dict[str, Any]) -> ReportData:
        sample = doc.get("sample", {})
        verdict = doc.get("verdict", {})
        score = doc.get("score", {})
        static = doc.get("static", {})
        pe = static.get("pe", {})
        dynamic = doc.get("dynamic", {})
        sb = dynamic.get("sandbox", {})
        iocs_sec = doc.get("iocs", {})
        detections = doc.get("detections", {})
        pipeline = doc.get("pipeline", {})

        return cls(
            contract_version=doc.get("contract_version", "1.0.0"),
            analysis_id=doc.get("analysis_id", "unknown"),
            sample_vault_id=sample.get("vault_id", doc.get("analysis_id", "unknown")),
            sample_name=sample.get("original_name", "unnamed_sample"),
            sha256=sample.get("sha256", "N/A"),
            md5=sample.get("md5", "N/A"),
            size_bytes=sample.get("size_bytes", 0),
            file_type=sample.get("file_type", "unknown"),
            received_at=sample.get("received_at", datetime.now(timezone.utc).isoformat()),
            submitter=sample.get("submitter", "system"),
            clamav_result=sample.get("clamav_result", "not_run"),
            
            verdict_label=verdict.get("label", "unknown"),
            verdict_severity=verdict.get("severity", "info"),
            verdict_confidence=verdict.get("confidence", 0.0),
            family_guess=verdict.get("family_guess", "N/A"),
            behavior_tags=verdict.get("behavior_tags", []),
            explanation=verdict.get("explanation", []),
            score_value=score.get("value") if score else None,
            score_method=score.get("method", "N/A") if score else "N/A",
            score_components=score.get("components", []) if score else [],
            
            static_status=static.get("status", "skipped"),
            file_class=static.get("file_class", "unknown"),
            entropy=static.get("entropy"),
            packers=static.get("packers", []),
            yara_matches=static.get("yara_matches", []),
            imports=pe.get("imports", []),
            imphash=pe.get("imphash", ""),
            sections=pe.get("sections", []),
            embedded_urls=static.get("embedded_urls", []),
            
            dynamic_status=dynamic.get("status", "skipped"),
            sandbox_engine=sb.get("engine", "N/A"),
            guest_os=sb.get("guest_os", "N/A"),
            network_mode=sb.get("network_mode", "isolated"),
            process_tree=dynamic.get("process_tree", []),
            file_events=dynamic.get("file_events", []),
            registry_events=dynamic.get("registry_events", []),
            mutexes=dynamic.get("mutexes", []),
            dropped_files=dynamic.get("dropped_files", []),
            network_summary=dynamic.get("network_summary", {}),
            
            iocs=iocs_sec.get("items", []),
            attack_techniques=iocs_sec.get("attack_techniques", []),
            beacons=iocs_sec.get("beacons", []),
            
            detection_items=detections.get("items", []),
            intel_hits=detections.get("intel_hits", []),
            
            response_actions=doc.get("response_actions", []),
            pipeline_status=pipeline.get("status", "unknown"),
            pipeline_stages=pipeline.get("stages", {}),
        )
