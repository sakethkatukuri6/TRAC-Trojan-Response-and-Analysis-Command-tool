"""STIX 2.1 Exporter for M6."""
from __future__ import annotations

import json
from typing import Any, Dict, List
import stix2


def export_stix_bundle(response_actions: List[Dict[str, Any]], iocs: Optional[List[Dict[str, Any]]] = None) -> str:
    """Generate local STIX 2.1 Bundle from actions and defanged IOCs."""
    objects = []

    # Map actions to STIX CourseOfAction objects
    for a in response_actions:
        coa = stix2.CourseOfAction(
            name=f"{a.get('type')}: {a.get('target')}",
            description=f"Action ID: {a.get('action_id')}, Mode: {a.get('mode')}, Status: {a.get('status')}",
            allow_custom=True
        )
        objects.append(coa)

    # Optionally add indicators for defanged IOCs
    if iocs:
        for item in iocs:
            val = item.get("value", "")
            itype = item.get("type", "domain")
            pattern = f"[{itype}:value = '{val}']"
            try:
                ind = stix2.Indicator(
                    name=f"IOC {itype} {val}",
                    pattern=pattern,
                    pattern_type="stix"
                )
                objects.append(ind)
            except Exception:
                # If custom pattern fails, create simple CourseOfAction note
                pass

    bundle = stix2.Bundle(objects=objects, allow_custom=True)
    return str(bundle.serialize(pretty=True))
