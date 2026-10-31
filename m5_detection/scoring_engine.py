"""
M5 Detection & Threat Scoring Engine
====================================
Evaluates security heuristics, behavioral signatures, and static indicators
to calculate weighted threat scores and derive contract-valid verdicts.

Conforms strictly to `detections`, `score`, and `verdict` in `analysis_result.schema.json`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from m5_detection.intel import corpus_provider, lookup_known_bad

# Threat-score model. A factor contributes a fixed number of points when its
# evidence is present. The contract's `weight` is that factor's ceiling share of
# the 100-point score (max points / 100), so the weights reported are the numbers
# the score is built from. Ceilings overlap deliberately: several factors can fire
# on one sample, and `allocate_components` shares the 100-point budget between them.
FACTOR_MAX_POINTS = {
    "entropy_heuristics": 18.0,
    "process_injection": 20.0,
    "c2_network_activity": 18.0,
    "persistence_routines": 12.0,
    "evasion_techniques": 10.0,
    "surveillance_modules": 10.0,
    "signature_match": 88.0,
    # A hash named by a reputation corpus is as strong an assertion as a signature
    # engine match, so it is weighted the same and shares the same 100-point ceiling.
    "threat_intel_match": 88.0,
}

# Elevated-but-not-extreme entropy is half as alarming as a packed payload.
ENTROPY_ELEVATED_POINTS = 10.0

# Verdict bands are set by the contract's semantic gate (`malicious` needs score
# >= 60, `benign` needs score <= 30), so the suspicious band starts where the
# contract's benign ceiling ends. A wider gap would label a 31-point sample benign
# and the validator would reject the document.
MALICIOUS_MIN_SCORE = 60.0
CRITICAL_MIN_SCORE = 80.0
BENIGN_MAX_SCORE = 30.0

# The identity of this scoring model, reported in every score section so a verdict
# can be attributed to the weights that produced it. `method` is one of the three
# values `analysis_result.schema.json` allows, so a factor or band change is carried
# by `model_version` instead of a new method name.
SCORE_METHOD = "weighted_rules_v1"
SCORE_MODEL_VERSION = "1.1.0"


def allocate_components(points: Dict[str, float]) -> Tuple[float, List[Dict[str, Any]]]:
    """Turn the points claimed by fired factors into the score and its components.

    The contract requires the components to sum to the published value, so a sample
    whose factors together claim more than 100 points shares the budget out
    proportionally. Clamping only the total would leave components reporting 176
    against a value of 100, which the validator rejects.
    """
    raw_total = sum(points.values())
    score_val = round(min(raw_total, 100.0), 1)
    share = 100.0 / raw_total if raw_total > 100.0 else 1.0

    components = [
        {"name": name, "weight": FACTOR_MAX_POINTS[name] / 100.0, "contribution": round(pts * share, 1)}
        for name, pts in points.items()
    ]

    # Keep the rounded components summing exactly to the published value.
    drift = round(score_val - sum(c["contribution"] for c in components), 1)
    if drift:
        largest = max(components, key=lambda c: c["contribution"])
        largest["contribution"] = round(largest["contribution"] + drift, 1)

    return score_val, components


def derive_confidence(
    label: str,
    *,
    signature_hit: bool,
    av_ran: bool,
    yara_ran: bool,
    runtime_observed: bool,
    intel_hit: bool = False,
) -> float:
    """State how much of the evidence base can actually support this verdict.

    A score band on its own says nothing about certainty: the same 62 points earned
    from four corroborating engines is stronger evidence than 62 points from static
    heuristics alone, and a "benign" answer is only worth as much as the scanners
    that ran to rule things out.
    """
    if label == "benign":
        # Nothing negative can be certified by engines that did not run.
        return 0.6 if (av_ran and yara_ran) else 0.3

    if signature_hit:
        # A signature engine named the threat; heuristics only corroborate it.
        return 0.95
    if intel_hit:
        # A reputation corpus named this exact digest, but it is a cached local
        # assertion rather than a live engine, so it stops short of 0.95.
        return 0.9
    if runtime_observed or yara_ran:
        # An independent engine or live telemetry backs the heuristics.
        return 0.8
    # Static heuristics are the only source.
    return 0.6


def score_analysis(
    data: bytes,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    iocs_result: Dict[str, Any],
    sample_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Calculate rule detections, weighted threat score, and final verdict."""

    detection_items: List[Dict[str, Any]] = []
    behavior_tags: Set[str] = set()
    explanations: List[str] = []

    # 1. Evaluate Entropy and Packing
    entropy = static_result.get("entropy", 0.0)
    packers = static_result.get("packers", [])

    entropy_contrib = 0.0
    if entropy >= 7.2:
        entropy_contrib = FACTOR_MAX_POINTS["entropy_heuristics"]
        detection_items.append({
            "rule_id": "HEUR_HIGH_ENTROPY_PACKED",
            "kind": "behavior",
            "severity": "high",
            "description": f"File exhibits very high Shannon entropy ({entropy:.2f}), indicative of packing or encryption",
            "attack_ids": ["T1027"],
            "tags": ["packer", "obfuscation"],
        })
        behavior_tags.add("packed")
        behavior_tags.add("obfuscated")
        explanations.append(f"High entropy ({entropy:.2f}) indicates an encrypted/packed executable payload.")
    elif entropy >= 6.5:
        entropy_contrib = ENTROPY_ELEVATED_POINTS
        explanations.append(f"Elevated section entropy ({entropy:.2f}) indicates compressed resources.")

    if packers:
        detection_items.append({
            "rule_id": "PACKER_DETECTED",
            "kind": "behavior",
            "severity": "medium",
            "description": f"Packer signature detected: {', '.join(packers)}",
            "attack_ids": ["T1027.002"],
            "tags": ["packer"],
        })
        behavior_tags.add("packer")

    # 2. Evaluate Behavioral Capabilities
    behaviors = dynamic_result.get("_static_capabilities", {})

    injection_contrib = 0.0
    if "injection" in behaviors:
        injection_contrib = FACTOR_MAX_POINTS["process_injection"]
        detection_items.append({
            "rule_id": "IMPORT_PROCESS_INJECTION",
            "kind": "behavior",
            "severity": "critical",
            "description": "Static imports or strings indicate process-injection capability",
            "attack_ids": ["T1055"],
            "tags": ["injection", "stealth"],
        })
        behavior_tags.add("process_injection")
        explanations.append("Static markers include process-memory or thread-manipulation APIs; runtime use was not observed.")

    c2_contrib = 0.0
    if "c2_networking" in behaviors:
        c2_contrib = FACTOR_MAX_POINTS["c2_network_activity"]
        detection_items.append({
            "rule_id": "NETWORK_C2_COMMUNICATION",
            "kind": "behavior",
            "severity": "high",
            "description": "Static imports or strings indicate application-layer network capability",
            "attack_ids": ["T1071.001"],
            "tags": ["c2", "networking"],
        })
        behavior_tags.add("c2_beaconing")
        explanations.append("Static markers include network APIs; no C2 connection is claimed without sandbox telemetry.")

    persistence_contrib = 0.0
    if "persistence" in behaviors:
        persistence_contrib = FACTOR_MAX_POINTS["persistence_routines"]
        detection_items.append({
            "rule_id": "PERSISTENCE_RUNKEY",
            "kind": "behavior",
            "severity": "high",
            "description": "Static imports or strings indicate Run-key or startup persistence capability",
            "attack_ids": ["T1547.001"],
            "tags": ["persistence"],
        })
        behavior_tags.add("persistence")
        explanations.append("Static markers reference persistence APIs or Run-key paths; runtime modification was not observed.")

    evasion_contrib = 0.0
    if "evasion" in behaviors:
        evasion_contrib = FACTOR_MAX_POINTS["evasion_techniques"]
        detection_items.append({
            "rule_id": "DEFENSE_EVASION_ANTIDEBUG",
            "kind": "behavior",
            "severity": "medium",
            "description": "Static imports or strings indicate anti-analysis capability",
            "attack_ids": ["T1497.001"],
            "tags": ["evasion", "anti_debug"],
        })
        behavior_tags.add("anti_analysis")
        explanations.append("Static markers reference debugger or virtual-environment checks; runtime evasion was not observed.")

    keylogger_contrib = 0.0
    if "keylogging" in behaviors:
        keylogger_contrib = FACTOR_MAX_POINTS["surveillance_modules"]
        detection_items.append({
            "rule_id": "SURVEILLANCE_KEYLOGGING",
            "kind": "behavior",
            "severity": "high",
            "description": "Static imports or strings indicate input-capture capability",
            "attack_ids": ["T1056.001"],
            "tags": ["keylogger", "spyware"],
        })
        behavior_tags.add("keylogger")
        explanations.append("Static markers include input-capture APIs; keylogging was not observed at runtime.")

    # 3. Check for specific Trojan family identifiers
    family_guess = "unknown"
    raw_lower = data[:100000].lower()

    if b"asyncrat" in raw_lower:
        family_guess = "asyncrat"
        behavior_tags.add("rat")
        behavior_tags.add("trojan")
        explanations.append("An AsyncRAT family marker is present in the submitted binary.")
    elif b"valleyrat" in raw_lower:
        family_guess = "valleyrat"
        behavior_tags.add("rat")
        behavior_tags.add("trojan")
        explanations.append("A ValleyRAT family marker is present in the submitted binary.")

    # 4. ClamAV / EICAR check from M1
    clamav = sample_record.get("clamav_result", "")
    signature_contrib = 0.0
    if clamav == "detected" or b"EICAR" in data:
        detection_items.append({
            "rule_id": "SIGNATURE_ANTIVIRUS_MATCH",
            "kind": "yara",
            "severity": "critical",
            "description": "Antivirus signature scanner match detected known threat",
            "attack_ids": ["T1027"],
            "tags": ["signature_match"],
        })
        explanations.append("First-pass signature engine flagged known malicious signature.")
        signature_contrib = FACTOR_MAX_POINTS["signature_match"]

    # 5. Threat-intel hash reputation against the locally held known-bad corpus
    intel_contrib = 0.0
    intel_hits: List[Dict[str, Any]] = []
    provider = corpus_provider()
    if provider:
        digest = str(sample_record.get("sha256") or "").strip().lower()
        entry = lookup_known_bad(digest)
        if entry:
            result = entry.get("result", "unknown")
            intel_hits.append({
                "provider": provider,
                "indicator": digest,
                "result": result,
                "cached": True,
            })
            if result == "known_malicious":
                intel_contrib = FACTOR_MAX_POINTS["threat_intel_match"]
                family = str(entry.get("family") or "").strip()
                detected_as = family or "an unclassified threat"
                detection_items.append({
                    "rule_id": "INTEL_HASH_KNOWN_BAD",
                    "kind": "intel",
                    "severity": "critical",
                    "description": (
                        f"SHA256 {digest} is listed as malicious by the local "
                        f"{provider} reputation corpus ({detected_as})."
                    ),
                    "attack_ids": ["T1027"],
                    "tags": ["known_bad_hash", detected_as],
                })
                behavior_tags.add("known_bad_hash")
                if family and family_guess == "unknown":
                    family_guess = re.sub(r"[^a-z0-9_]", "_", family.lower())
                explanations.append(
                    f"Hash reputation: the local {provider} corpus lists this exact digest "
                    f"as malicious ({detected_as})."
                )

    factor_points = {
        "entropy_heuristics": entropy_contrib,
        "process_injection": injection_contrib,
        "c2_network_activity": c2_contrib,
        "persistence_routines": persistence_contrib,
        "evasion_techniques": evasion_contrib,
        "surveillance_modules": keylogger_contrib,
        "signature_match": signature_contrib,
        "threat_intel_match": intel_contrib,
    }
    score_val, components = allocate_components(factor_points)

    # Verdict derivation
    if score_val >= MALICIOUS_MIN_SCORE:
        verdict_label = "malicious"
        verdict_severity = "critical" if score_val >= CRITICAL_MIN_SCORE else "high"
    elif score_val > BENIGN_MAX_SCORE:
        verdict_label = "suspicious"
        verdict_severity = "medium"
    else:
        verdict_label = "benign"
        verdict_severity = "low"

    if not explanations:
        explanations.append("File analyzed without actionable malicious indicators.")

    av_ran = clamav in ("clean", "detected")
    yara_ran = "yara_matches" in static_result
    runtime_observed = dynamic_result.get("status") == "done"
    confidence = derive_confidence(
        verdict_label,
        signature_hit=signature_contrib > 0.0,
        av_ran=av_ran,
        yara_ran=yara_ran,
        runtime_observed=runtime_observed,
        intel_hit=intel_contrib > 0.0,
    )
    ran_sources = [
        name
        for name, ran in (
            ("ClamAV", av_ran),
            ("YARA rules", yara_ran),
            ("sandbox telemetry", runtime_observed),
            ("signature match", signature_contrib > 0.0),
            ("hash reputation", intel_contrib > 0.0),
        )
        if ran
    ]
    if ran_sources:
        explanations.append(
            f"Confidence {confidence:.2f}: corroborated by {' and '.join(ran_sources)}."
        )
    else:
        explanations.append(
            f"Confidence {confidence:.2f}: no corroborating engine ran, "
            "so this rests on static heuristics alone."
        )

    clean_tags = [re.sub(r"[^a-z0-9_]", "_", t.lower()) for t in sorted(behavior_tags) if t]

    return {
        "detections": {
            "status": "done",
            "items": detection_items,
            # `intel_hits` is omitted rather than left empty: an entry is only added
            # when the reputation corpus actually holds the digest, so absence means
            # "no assertion was made", not "a provider cleared it".
            **({"intel_hits": intel_hits} if intel_hits else {}),
        },
        "score": {
            "value": score_val,
            "method": SCORE_METHOD,
            "model_version": SCORE_MODEL_VERSION,
            "components": components,
        },
        "verdict": {
            "label": verdict_label,
            "severity": verdict_severity,
            "confidence": confidence,
            "family_guess": family_guess,
            "behavior_tags": clean_tags,
            "explanation": explanations,
        },
    }
