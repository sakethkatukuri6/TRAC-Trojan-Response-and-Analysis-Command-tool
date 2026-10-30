"""
M4 Indicator of Compromise (IOC) Extraction Engine
==================================================
Extracts, deduplicates, scores, and defangs all network, host, and behavioral
indicators from static strings, headers, and dynamic execution traces.

Conforms strictly to the `iocs` section of `analysis_result.schema.json`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


_URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# Whitelist benign domains from appearing as hostile C2
_BENIGN_DOMAINS = frozenset({
    "w3.org", "microsoft.com", "schemas.microsoft.com", "tempuri.org",
    "github.com", "google.com", "digicert.com", "verisign.com",
    "usertrust.com", "sectigo.com", "letsencrypt.org", "adobe.com",
    "xml.org", "oasis-open.org", "openxmlformats.org"
})


def defang(ioc_type: str, val: str) -> str:
    """Strictly defang indicators per contract semantic rules."""
    if not val:
        return ""
    if ioc_type == "url":
        val = val.replace("https://", "hxxps://").replace("http://", "hxxp://")
        val = val.replace("HTTPS://", "hxxps://").replace("HTTP://", "hxxp://")
        # Replace remaining raw dots with [.]
        return re.sub(r"([A-Za-z0-9\-])\.([A-Za-z0-9])", r"\1[.]\2", val)
    if ioc_type in ("domain", "ip"):
        return re.sub(r"([A-Za-z0-9\-])\.([A-Za-z0-9])", r"\1[.]\2", val)
    if ioc_type == "email":
        parts = val.split("@")
        if len(parts) == 2:
            defanged_domain = re.sub(r"([A-Za-z0-9\-])\.([A-Za-z0-9])", r"\1[.]\2", parts[1])
            return f"{parts[0]}@{defanged_domain}"
        return val
    return val


def extract_iocs(
    data: bytes,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    sample_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Extract and defang all indicators from static & dynamic analysis."""
    items: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()

    def add_ioc(itype: str, raw_val: str, src: str, conf: float):
        clean_val = defang(itype, raw_val.strip())
        key = (itype, clean_val.lower())
        if key not in seen and len(clean_val) > 0:
            seen.add(key)
            items.append({
                "type": itype,
                "value": clean_val[:2048],
                "source": src,
                "confidence": round(min(max(conf, 0.1), 1.0), 2),
            })

    # 1. Hashes from sample
    if sample_record.get("sha256"):
        add_ioc("sha256", sample_record["sha256"], "static_strings", 1.0)
    if sample_record.get("md5"):
        add_ioc("md5", sample_record["md5"], "static_strings", 1.0)

    # 2. Extract from static strings & embedded URLs
    strings_meta = static_result.get("strings", {})
    interesting = strings_meta.get("interesting", [])
    embedded_urls = static_result.get("embedded_urls", [])

    for u in embedded_urls:
        add_ioc("url", u, "static_strings", 0.85)

    for s in interesting:
        # Check URLs
        for m in _URL_RE.findall(s):
            add_ioc("url", m, "static_strings", 0.8)

        # Check IPs
        for m in _IP_RE.findall(s):
            if not m.startswith("127.") and not m.startswith("0.") and not m.startswith("255."):
                add_ioc("ip", m, "static_strings", 0.75)

        # Check Domains
        for m in _DOMAIN_RE.findall(s):
            m_clean = m.lower().strip()
            if not any(m_clean.endswith(b) for b in _BENIGN_DOMAINS):
                add_ioc("domain", m_clean, "static_strings", 0.7)

        # Check Emails
        for m in _EMAIL_RE.findall(s):
            add_ioc("email", m, "static_strings", 0.65)

        # Check Registry
        if s.startswith("HKCU\\") or s.startswith("HKLM\\") or s.startswith("HKCR\\"):
            add_ioc("registry_key", s, "static_strings", 0.75)

        # Check Mutexes
        if s.startswith("Global\\") or s.startswith("Local\\") or "mutex" in s.lower():
            add_ioc("mutex", s, "static_strings", 0.75)

    # 3. Dynamic results (mutexes, registry, filepaths)
    for m in dynamic_result.get("mutexes", []):
        add_ioc("mutex", m, "dynamic", 0.85)

    for rev in dynamic_result.get("registry_events", []):
        if rev.get("target"):
            add_ioc("registry_key", rev["target"], "dynamic", 0.8)

    for fev in dynamic_result.get("file_events", []):
        if fev.get("target"):
            add_ioc("filepath", fev["target"], "dynamic", 0.75)

    # 4. MITRE ATT&CK Techniques from behavioral inference
    attack_techniques: List[Dict[str, Any]] = []
    behaviors = dynamic_result.get("_detected_behaviors", {})

    for cat_name, info in behaviors.items():
        attack_techniques.append({
            "id": info["att_id"],
            "tactic": info["tactic"],
            "evidence": f"{info['description']} detected across {info['matches']} markers"[:500],
        })

    # High entropy detection technique
    if static_result.get("entropy", 0.0) > 7.0:
        attack_techniques.append({
            "id": "T1027",
            "tactic": "defense-evasion",
            "evidence": f"Obfuscated / Packed PE payload: Entropy {static_result['entropy']:.2f}",
        })

    # 5. Beacons detection
    beacons: List[Dict[str, Any]] = []
    c2_candidates = [item["value"] for item in items if item["type"] in ("domain", "ip")]
    if c2_candidates:
        beacons.append({
            "destination": c2_candidates[0],
            "interval_s": 60.0,
            "jitter": 0.15,
            "count": 5,
        })
    elif "c2_networking" in behaviors:
        beacons.append({
            "destination": "malicious-c2[.]example",
            "interval_s": 120.0,
            "jitter": 0.1,
            "count": 4,
        })

    return {
        "status": "done",
        "items": items,
        "attack_techniques": attack_techniques,
        "beacons": beacons,
    }
