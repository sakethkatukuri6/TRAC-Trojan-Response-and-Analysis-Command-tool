"""
M5 Detection & Threat Scoring Engine
====================================
Evaluates security heuristics, behavioral signatures, and static indicators
to calculate weighted threat scores and derive contract-valid verdicts.

Conforms strictly to `detections`, `score`, and `verdict` in `analysis_result.schema.json`.

The one rule this module is built around
----------------------------------------
A score contribution may only exist where a detection item was emitted for it.
Points are never added by hand: :meth:`Scoreboard.claim` writes the detection and
the points from the same call, with the same evidence string, so an unaudited
contribution is not expressible. ``evaluate_evidence`` returns both the published
document and the claim ledger, and the regression suite asserts the two agree.

The second rule is about absence. Evidence that was not gathered must not be
scored, and it must not be scored *as though it were clean* either: a sample whose
PE header could not be read is ``unknown``, not ``benign``, and a verdict is only
as certain as the engines that actually ran to support it.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from m2_static import pe_evidence
from m2_static.yara_scan import asserts_malicious, family_assertion
from m5_detection.intel import corpus_provider, lookup_known_bad

# ---------------------------------------------------------------------------
# The score model
# ---------------------------------------------------------------------------

# Threat-score model. A factor contributes a fixed number of points when its
# evidence is present. The contract's `weight` is that factor's ceiling share of
# the 100-point score (max points / 100), so the weights reported are the numbers
# the score is built from. Ceilings overlap deliberately: several factors can fire
# on one sample, and `allocate_components` shares the 100-point budget between them.
FACTOR_MAX_POINTS: Dict[str, float] = {
    "entropy_heuristics": 18.0,
    "process_injection": 20.0,
    "c2_network_activity": 18.0,
    "persistence_routines": 12.0,
    "evasion_techniques": 10.0,
    "surveillance_modules": 10.0,
    # Packing and PE layout are corroborating context, not proof of malicious
    # intent: UPX is the most-used free packer in existence and a RWX section is
    # shipped by real debuggers. Both are bounded well below a signature hit.
    "packing_indicators": 12.0,
    "structural_anomalies": 14.0,
    # Capabilities M3's markers or M2's import groups name that the five behavioural
    # factors above do not already credit, so they are no longer invisible to the score.
    "advanced_capabilities": 16.0,
    "signature_match": 88.0,
    # A hash named by a reputation corpus is as strong an assertion as a signature
    # engine match, so it is weighted the same and shares the same 100-point ceiling.
    "threat_intel_match": 88.0,
}

# Elevated-but-not-extreme entropy is half as alarming as a packed payload.
ENTROPY_ELEVATED_POINTS = 10.0

# One tool signature is stronger evidence than one derived heuristic: a named packer
# is a byte pattern the tool wrote, while `sign:overlay_data` only says "bytes exist".
PACKER_TOOL_POINTS = 12.0
PACKER_SIGN_POINTS = 6.0

# Structural findings that move the score, and by how much. Anything absent here is
# still reported to the analyst but earns nothing, because "unusual" is not "malicious".
STRUCTURAL_POINTS: Dict[str, float] = {
    "SECTION_RWX": 6.0,
    "ENTRYPOINT_IN_WRITABLE_SECTION": 6.0,
    "ENTRYPOINT_OUTSIDE_SECTIONS": 5.0,
    "SECTION_RAW_OVERLAP": 6.0,
    "ENTRYPOINT_IN_DATA_SECTION": 4.0,
    "OVERLAY_DATA": 4.0,
    "EXECUTABLE_SECTION_HIGH_ENTROPY": 5.0,
    "NO_IMPORT_DIRECTORY": 4.0,
    "RESOURCE_TREE_UNREADABLE": 3.0,
    "IMPORT_COUNT_MINIMAL": 3.0,
    "ENTRYPOINT_MISSING": 3.0,
    "EMPTY_RESOURCE_DIRECTORY": 2.0,
    "NONSTANDARD_EXECUTABLE_SECTION": 2.0,
    "DLL_WITHOUT_RELOCATIONS": 2.0,
    "SECTION_COUNT_HIGH": 1.0,
}
# Report-only findings: worth an analyst's attention, worthless as a threat signal.
STRUCTURAL_REPORT_ONLY = ("NO_ASLR", "NO_NX_COMPAT", "PACKER_TOOL_SIGNATURE")

# How many structural detections one sample may publish. A deliberately malformed
# header can raise twenty; a wall of near-identical findings buries the score just as
# surely as an inflated one, so the highest-value findings are kept.
MAX_STRUCTURAL_DETECTIONS = 10

# The only rule tags a match may echo into `verdict.behavior_tags`.
#
# A repository rule is free to carry any tag it likes, including `family` or a product
# name. Those belong to the rule author, and re-publishing them as TRAC's own behaviour
# classification would let one line of YARA relabel a sample. `meta.family` has its own
# audited path through family_assertion() into verdict.family_guess.
CURATED_RULE_TAGS = frozenset({"malicious", "packer", "protector", "test_signature"})

# Capability clusters that the five behavioural factors do not already credit.
# Keyed by M3's `_static_capabilities` name and by M2's import-group name, so a
# capability seen through either channel is credited exactly once.
EXTRA_CAPABILITY_POINTS = 8.0
EXTRA_CAPABILITIES: Dict[str, Tuple[str, str]] = {
    "credentials": ("T1555", "credential-access"),
    "credential_access": ("T1555", "credential-access"),
    "screen_capture": ("T1113", "collection"),
    "input_capture": ("T1056.001", "collection"),
    "service_control": ("T1543.003", "persistence"),
    "lateral_movement": ("T1021.002", "lateral-movement"),
}

# Behavioural factor, keyed by the capability name M3 reports.
BEHAVIOURAL_FACTORS: Dict[str, Tuple[str, float, str, str, Sequence[str]]] = {
    "injection": ("process_injection", 20.0, "critical", "T1055", ("injection", "stealth")),
    "c2_networking": ("c2_network_activity", 18.0, "high", "T1071.001", ("c2", "networking")),
    "persistence": ("persistence_routines", 12.0, "high", "T1547.001", ("persistence",)),
    "evasion": ("evasion_techniques", 10.0, "medium", "T1497.001", ("evasion", "anti_debug")),
    "keylogging": ("surveillance_modules", 10.0, "high", "T1056.001", ("keylogger", "spyware")),
}

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
SCORE_MODEL_VERSION = "1.2.0"


class Contribution(NamedTuple):
    """One scored detection: the points, the factor they land in, and why."""

    factor: str
    points: float
    rule_id: str
    evidence: str


class Scoreboard:
    """Detection items and score points written together, never separately.

    Every path to a non-zero contribution goes through :meth:`claim`, so a score can
    not contain a term that the analyst cannot find in ``detections.items``.
    """

    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []
        self.points: Dict[str, float] = {name: 0.0 for name in FACTOR_MAX_POINTS}
        self.ledger: List[Contribution] = []
        self.tags: Set[str] = set()
        self.explanations: List[str] = []
        self.credit: Set[str] = set()

    def claim(
        self,
        factor: Optional[str],
        points: float,
        rule_id: str,
        *,
        kind: str,
        severity: str,
        description: str,
        evidence: str,
        attack_ids: Sequence[str] = (),
        tags: Sequence[str] = (),
        tag: Optional[str] = None,
        explanation: Optional[str] = None,
    ) -> None:
        self.items.append({
            "rule_id": rule_id,
            "kind": kind,
            "severity": severity,
            "description": description[:500],
            "attack_ids": list(attack_ids),
            "tags": list(tags),
        })
        if tag:
            self.tags.add(tag)
        if explanation:
            self.explanations.append(explanation)
        if factor and points > 0:
            self.points[factor] += points
            self.ledger.append(Contribution(factor, points, rule_id, evidence))
            for attack_id in attack_ids:
                self.credit.add(attack_id)

    def credit_for(self, attack_id: str) -> bool:
        return attack_id in self.credit

    def note(self, text: str) -> None:
        self.explanations.append(text)


def allocate_components(points: Dict[str, float]) -> Tuple[float, List[Dict[str, Any]]]:
    """Turn the points claimed by fired factors into the score and its components.

    Three invariants hold for every input:

    * no factor contributes more than its declared ceiling;
    * the published components sum to exactly ``value`` - the contract's semantic gate
      rejects a document whose components disagree with its score;
    * nothing contributes a negative amount.

    A sample whose factors together claim more than 100 points shares the budget out
    proportionally rather than clamping only the total, because clamping the total
    would leave components reporting 176 against a value of 100.
    """
    clamped = {
        name: max(0.0, min(float(pts), FACTOR_MAX_POINTS[name]))
        for name, pts in points.items()
        if name in FACTOR_MAX_POINTS
    }
    raw_total = sum(clamped.values())
    score_val = round(min(raw_total, 100.0), 1)
    share = 100.0 / raw_total if raw_total > 100.0 else 1.0

    components = [
        {
            "name": name,
            "weight": FACTOR_MAX_POINTS[name] / 100.0,
            "contribution": round(clamped[name] * share, 1),
        }
        for name in points
        if name in FACTOR_MAX_POINTS
    ]

    # Absorb the rounding drift into a component that can take it without breaking
    # its own ceiling; a fixed 0.1 on the largest term could push it over the weight
    # the model just published for it.
    drift = round(score_val - sum(c["contribution"] for c in components), 1)
    if drift:
        ordered = sorted(components, key=lambda c: c["contribution"], reverse=True)
        step = 0.1 if drift > 0 else -0.1
        remaining = abs(drift)
        while remaining > 1e-9:
            moved = False
            for component in ordered:
                ceiling = FACTOR_MAX_POINTS[component["name"]]
                candidate = round(component["contribution"] + step, 1)
                if 0.0 <= candidate <= ceiling + 1e-9:
                    component["contribution"] = candidate
                    remaining = round(remaining - 0.1, 1)
                    moved = True
                    if remaining <= 1e-9:
                        break
            if not moved:
                break
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
    if label == "unknown":
        # The reading itself is unreliable; nothing downstream can be trusted further.
        return 0.2
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


def _claim_entropy(board: Scoreboard, entropy: Any) -> None:
    if not isinstance(entropy, (int, float)):
        return
    if entropy >= 7.2:
        board.claim(
            "entropy_heuristics",
            FACTOR_MAX_POINTS["entropy_heuristics"],
            "HEUR_HIGH_ENTROPY_PACKED",
            kind="behavior",
            severity="high",
            description=(
                f"File exhibits very high Shannon entropy ({entropy:.2f}), indicative of "
                "packing or encryption"
            ),
            evidence=f"static.entropy = {entropy:.2f}",
            attack_ids=["T1027"],
            tags=["packer", "obfuscation"],
            tag="obfuscated",
            explanation=f"High entropy ({entropy:.2f}) indicates an encrypted/packed executable payload.",
        )
        board.tags.add("packed")
    elif entropy >= 6.5:
        # Scored, so it has to say so out loud: an unlisted contribution is exactly the
        # unaudited term the rest of this module refuses to produce.
        board.claim(
            "entropy_heuristics",
            ENTROPY_ELEVATED_POINTS,
            "HEUR_ENTROPY_ELEVATED",
            kind="behavior",
            severity="medium",
            description=f"Section entropy is elevated ({entropy:.2f}) without reaching a packing threshold",
            evidence=f"static.entropy = {entropy:.2f}",
            attack_ids=["T1027"],
            tags=["obfuscation"],
            explanation=f"Elevated section entropy ({entropy:.2f}) indicates compressed resources.",
        )


def _claim_packing(board: Scoreboard, packers: Sequence[str]) -> None:
    if not packers:
        return
    tools = sorted({token.split(":", 1)[1] for token in packers if token.startswith("tool:")})
    signs = sorted({token for token in packers if not token.startswith("tool:")})
    points = PACKER_TOOL_POINTS if tools else (PACKER_SIGN_POINTS if signs else 0.0)
    board.claim(
        "packing_indicators",
        points,
        "PACKER_DETECTED",
        kind="behavior",
        severity="medium" if not tools else "high",
        description=(
            f"Packer evidence: {', '.join(packers)}"
            + (f" - named tool(s): {', '.join(tools)}" if tools else " - derived signs only")
        ),
        evidence=f"static.packers = {', '.join(packers)}",
        attack_ids=["T1027.002"],
        # The tool name belongs in the description, where the bytes that justify it are
        # quoted. `behavior_tags` is a consumer-facing classification, and a section
        # called ".upx0" is evidence of a packer, not a name to publish as a label.
        tags=["packer"],
        tag="packer",
        explanation=(
            f"{tools[0]} wrote a signature this file carries." if tools
            else "Packing heuristics fired, but no tool signature identified a packer."
        ),
    )
    board.tags.add("packed")


def _claim_behaviours(board: Scoreboard, behaviors: Dict[str, Any]) -> None:
    for name, (factor, ceiling, severity, attack, tags) in BEHAVIOURAL_FACTORS.items():
        info = behaviors.get(name)
        if not info:
            continue
        matches = list(info.get("matches", []))
        board.claim(
            factor,
            ceiling,
            f"IMPORT_{name.upper()}",
            kind="behavior",
            severity=severity,
            description=f"Static imports or strings indicate {info.get('description', name).lower()}",
            evidence=f"Static markers: {', '.join(matches)}"[:500],
            attack_ids=[attack],
            tags=list(tags),
            tag=_behaviour_tag(name),
            explanation=_behaviour_explanation(name),
        )


_BEHAVIOUR_TAGS = {
    "injection": "process_injection",
    "c2_networking": "c2_beaconing",
    "persistence": "persistence",
    "evasion": "anti_analysis",
    "keylogging": "keylogger",
    "credentials": "credential_access",
    "screen_capture": "screen_capture",
    "input_capture": "keylogger",
    "service_control": "service_control",
    "lateral_movement": "lateral_movement",
}


def _behaviour_tag(name: str) -> str:
    return _BEHAVIOUR_TAGS.get(name, name)


_BEHAVIOUR_EXPLANATIONS = {
    "injection": "Static markers include process-memory or thread-manipulation APIs; runtime use was not observed.",
    "c2_networking": "Static markers include network APIs; no C2 connection is claimed without sandbox telemetry.",
    "persistence": "Static markers reference persistence APIs or Run-key paths; runtime modification was not observed.",
    "evasion": "Static markers reference debugger or virtual-environment checks; runtime evasion was not observed.",
    "keylogging": "Static markers include input-capture APIs; keylogging was not observed at runtime.",
}


def _behaviour_explanation(name: str) -> str:
    return _BEHAVIOUR_EXPLANATIONS.get(
        name, f"{name} is claimed by a static marker, not by observed execution."
    )


def _claim_extra_capabilities(board: Scoreboard, behaviors: Dict[str, Any],
                              import_groups: Dict[str, List[str]]) -> None:
    """Credit capabilities the five behavioural factors leave uncounted.

    M3 reports credentials and screen-capture markers, and M2's import groups name
    service control and lateral movement, but none of them reached the score before:
    evidence that changes what a sample can do should change what it scores, once each.
    """
    sources: List[Tuple[str, str, str]] = []
    for name, info in behaviors.items():
        if name in EXTRA_CAPABILITIES and name not in BEHAVIOURAL_FACTORS:
            attack, _tactic = EXTRA_CAPABILITIES[name]
            matches = ", ".join(info.get("matches", []))
            sources.append((name, attack, f"Static markers: {matches}"))
    for group, members in import_groups.items():
        if group in EXTRA_CAPABILITIES and group not in behaviors:
            attack, _tactic = EXTRA_CAPABILITIES[group]
            sources.append((group, attack, f"Imported APIs: {', '.join(members)}"))

    fired = 0
    for name, attack_id, evidence in sources:
        if board.credit_for(attack_id) or fired >= 2:
            continue
        board.claim(
            "advanced_capabilities",
            EXTRA_CAPABILITY_POINTS,
            f"CAPABILITY_{name.upper()}",
            kind="behavior",
            severity="medium",
            description=f"Static evidence of {name.replace('_', ' ')} capability",
            evidence=evidence[:500],
            attack_ids=[attack_id],
            tags=[name],
            tag=_behaviour_tag(name),
            explanation=_behaviour_explanation(name),
        )
        fired += 1


def _claim_structural(board: Scoreboard, evidence: pe_evidence.PeEvidence) -> None:
    # The cap protects the score from a wall of near-identical findings, so it applies
    # to the findings that *move* the score. Report-only findings cost nothing and are
    # few (one per flag), so dropping them would only hide what the analyst was told
    # the module read.
    scored = sorted(
        (f for f in evidence.findings if f["code"] not in STRUCTURAL_REPORT_ONLY),
        key=lambda finding: (STRUCTURAL_POINTS.get(finding["code"], 0.0), finding["code"]),
        reverse=True,
    )[:MAX_STRUCTURAL_DETECTIONS]
    ranked = scored + [f for f in evidence.findings if f["code"] in STRUCTURAL_REPORT_ONLY]

    for finding in ranked:
        code = finding["code"]
        if code in STRUCTURAL_REPORT_ONLY:
            board.claim(
                None,
                0.0,
                f"PE_{code}",
                kind="behavior",
                severity="info",
                description=finding["detail"],
                evidence="",
                tags=["pe_layout"],
            )
            continue
        points = STRUCTURAL_POINTS.get(code, 0.0)
        severity = "high" if points >= 6.0 else "medium" if points >= 4.0 else "low"
        board.claim(
            "structural_anomalies" if points else None,
            points,
            f"PE_{code}",
            kind="behavior",
            severity=severity if points else "info",
            description=finding["detail"],
            evidence=finding["detail"],
            attack_ids=["T1027"] if points >= 5.0 else [],
            tags=["pe_layout", code.lower()],
            tag="suspicious_layout" if points else None,
        )


def _claim_yara(board: Scoreboard, matches: Sequence[Dict[str, Any]], ran: bool) -> None:
    for match in matches:
        rule = str(match.get("rule", "unknown_rule"))
        declared = asserts_malicious(match)
        meta = match.get("meta") or {}
        detail = ", ".join(f"{key}={value}" for key, value in sorted(meta.items()))
        matched = f"Repository YARA rule {rule} matched" + (f" ({detail})" if detail else "")
        board.claim(
            "signature_match" if declared else None,
            FACTOR_MAX_POINTS["signature_match"] if declared else 0.0,
            f"YARA_{rule}",
            kind="yara",
            severity="critical" if declared else "info",
            description=matched + " and declares a malicious verdict" if declared else matched,
            evidence=f"rule={rule}; namespace={match.get('namespace', '-')}; tags={match.get('tags', [])}"[:500],
            attack_ids=["T1027"] if declared else [],
            # Only a rule's own classification tags travel into `behavior_tags`. A
            # curated rule may carry `family = "AsyncRAT"` in its metadata, and echoing
            # that back as a behaviour tag would publish an identification TRAC itself
            # did not make; `family_assertion()` is the one channel into `family_guess`.
            tags=["yara"] + [tag for tag in map(str, match.get("tags") or [])
                             if tag in CURATED_RULE_TAGS],
            tag="signature_match" if declared else None,
            explanation=(
                f"YARA rule {rule} both matched and declared a verdict, which is what a "
                "signature contribution requires." if declared else
                f"YARA rule {rule} matched but declared no verdict, so it scores nothing."
            ),
        )
    if ran:
        board.tags.add("yara_scanned")


def _claim_signature(board: Scoreboard, clamav: str, data: bytes) -> float:
    detected = clamav == "detected" or b"EICAR" in data
    if not detected:
        return 0.0
    board.claim(
        "signature_match",
        FACTOR_MAX_POINTS["signature_match"],
        "SIGNATURE_ANTIVIRUS_MATCH",
        kind="yara",
        severity="critical",
        description="Antivirus signature scanner match detected known threat",
        evidence=(
            f"sample.clamav_result = {clamav}" if clamav == "detected"
            else "EICAR test-file content present in the submitted bytes"
        ),
        attack_ids=["T1027"],
        tags=["signature_match"],
        tag="signature_match",
        explanation="First-pass signature engine flagged known malicious signature.",
    )
    return FACTOR_MAX_POINTS["signature_match"]


class Evaluation(NamedTuple):
    document: Dict[str, Any]
    contributions: List[Contribution]
    points: Dict[str, float]


def evaluate_evidence(
    data: bytes,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    iocs_result: Dict[str, Any],
    sample_record: Dict[str, Any],
) -> Evaluation:
    """Score what the other modules actually found, and return the audit trail."""
    board = Scoreboard()

    static_status = static_result.get("status")
    _claim_entropy(board, static_result.get("entropy", 0.0))
    _claim_packing(board, list(static_result.get("packers", []) or []))

    behaviors = dynamic_result.get("_static_capabilities", {}) or {}
    _claim_behaviours(board, behaviors)

    import_groups: Dict[str, List[str]] = {}
    if static_status == "done" and static_result.get("file_class") == "pe":
        import_groups = pe_evidence.group_imports((static_result.get("pe") or {}).get("imports") or [])
        _claim_structural(board, pe_evidence.collect_pe_evidence(data))
    _claim_extra_capabilities(board, behaviors, import_groups)

    # A family is a claim TRAC makes about what this binary *is*, so it is only ever
    # taken from a source that states one: a reputation corpus that identified this
    # exact digest, or a repository YARA rule with meta.family. Not a filename, not a
    # substring of the payload, not a rule's name.
    family_guess = "unknown"

    clamav = str(sample_record.get("clamav_result", "") or "")
    _claim_signature(board, clamav, data)

    matches = list(static_result.get("yara_matches") or []) if "yara_matches" in static_result else []
    _claim_yara(board, matches, ran="yara_matches" in static_result)
    # A rule may name a family only by also declaring a verdict. `meta.family` on a
    # rule that matched but asserted nothing would let a 0-point benign verdict carry
    # a threat identification, which is exactly the unsourced label this module is
    # built to refuse.
    rule_family = family_assertion([m for m in matches if asserts_malicious(m)])
    if rule_family:
        family_guess = _family_token(rule_family)

    # Threat-intel hash reputation against the locally held known-bad corpus.
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
                detected_as = str(entry.get("family") or "").strip()
                label = _family_token(detected_as) if detected_as else "an unclassified threat"
                if detected_as and family_guess == "unknown":
                    # The corpus names a digest, which is an identification.
                    family_guess = _family_token(detected_as)
                board.claim(
                    "threat_intel_match",
                    FACTOR_MAX_POINTS["threat_intel_match"],
                    "INTEL_HASH_KNOWN_BAD",
                    kind="intel",
                    severity="critical",
                    description=(
                        f"SHA256 {digest} is listed as malicious by the local "
                        f"{provider} reputation corpus ({label})."
                    ),
                    evidence=f"sha256={digest} in {provider} corpus",
                    attack_ids=["T1027"],
                    tags=["known_bad_hash", label],
                    tag="known_bad_hash",
                    explanation=(
                        f"Hash reputation: the local {provider} corpus lists this exact digest "
                        f"as malicious ({label})."
                    ),
                )

    score_val, components = allocate_components(board.points)

    unreadable = static_status not in (None, "done")
    hard_evidence = (
        board.points["signature_match"] > 0.0 or board.points["threat_intel_match"] > 0.0
    )
    if unreadable and not hard_evidence:
        verdict_label, verdict_severity = "unknown", "info" if score_val == 0 else "low"
        board.note(
            f"Static analysis reported status '{static_status}', so the image was never read. "
            "TRAC cannot rank a sample it could not parse, and an absent finding is not evidence "
            "of absence."
        )
    else:
        verdict_label, verdict_severity = _band(score_val)

    if verdict_label == "benign" and not board.items:
        board.note("File analyzed without actionable malicious indicators.")

    yara_ran = "yara_matches" in static_result
    av_ran = clamav in ("clean", "detected")
    runtime_observed = dynamic_result.get("status") == "done"
    confidence = derive_confidence(
        verdict_label,
        signature_hit=board.points["signature_match"] > 0.0,
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
            ("signature match", board.points["signature_match"] > 0.0),
            ("hash reputation", intel_contrib > 0.0),
        )
        if ran
    ]
    if ran_sources:
        board.note(
            f"Confidence {confidence:.2f}: corroborated by {' and '.join(ran_sources)}."
        )
    else:
        board.note(
            f"Confidence {confidence:.2f}: no corroborating engine ran, "
            "so this rests on static heuristics alone."
        )

    clean_tags = sorted({_family_token(t) for t in board.tags if t and _family_token(t)})

    document = {
        "detections": {
            "status": "done",
            "items": board.items,
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
            "explanation": [line[:500] for line in board.explanations],
        },
    }
    return Evaluation(document, list(board.ledger), dict(board.points))


def _band(score_val: float) -> Tuple[str, str]:
    if score_val >= MALICIOUS_MIN_SCORE:
        return "malicious", "critical" if score_val >= CRITICAL_MIN_SCORE else "high"
    if score_val > BENIGN_MAX_SCORE:
        return "suspicious", "medium"
    return "benign", "low"


_TAG_SAFE = re.compile(r"[^a-z0-9_]")


def _family_token(value: str) -> str:
    """Normalise a declared name to the contract's `^[a-z0-9_]+$` tag pattern."""
    return _TAG_SAFE.sub("_", str(value).lower()).strip("_")


def score_analysis(
    data: bytes,
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
    iocs_result: Dict[str, Any],
    sample_record: Dict[str, Any],
) -> Dict[str, Any]:
    """Calculate rule detections, weighted threat score, and final verdict.

    The published document only: :func:`evaluate_evidence` is the same call with the
    contribution ledger attached, for tests and for an operator auditing a score.
    """
    return evaluate_evidence(data, static_result, dynamic_result, iocs_result, sample_record).document
