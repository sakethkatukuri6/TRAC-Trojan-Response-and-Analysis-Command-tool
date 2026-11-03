"""
M2 optional local YARA scanning
===============================
Runs YARA over submitted bytes against a ruleset that lives in this repository,
and reports what the rules actually said. No network rule feeds, no third-party
module, no execution of the sample.

Three states, kept deliberately distinct
----------------------------------------
``yara_matches`` absent from the published ``static`` section
    The engine did not run. ``scan()`` returns ``status`` "disabled",
    "unavailable" (``yara-python`` is not installed), "no_rules" or "error".
    A consumer must read this as "not assessed", which is what M8's UI already
    labels it.
``yara_matches == []``
    The engine ran, the ruleset compiled, and no rule matched. This is a real
    (weak) negative and is what lifts M5's confidence in a clean verdict.
``yara_matches == [...]``
    Each entry carries the rule identifier, namespace, tags and metadata straight
    off the ``yara.Match`` object. Nothing is invented, renamed or summarised.

Opt-in by default
-----------------
Nothing is compiled until an operator turns it on with ``TRAC_YARA_ENABLED=1`` or
points ``TRAC_YARA_RULES_DIR`` at a directory. That keeps the platform's default
behaviour — "YARA was not assessed" — honest for deployments that have not curated
a ruleset, and it is why the rest of TRAC treats a missing key as the norm.

Rule sourcing is restricted on purpose
--------------------------------------
Only regular files ending in ``.yar``/``.yara`` inside the chosen rules directory
are compiled, the directory is resolved and re-checked so a symlink cannot walk
outside it, and YARA's ``include`` directive is switched off so a rule file cannot
pull in a path the operator did not curate.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILTIN_RULES_DIR = Path(__file__).resolve().parent / "rules"
ALLOWED_SUFFIXES = frozenset({".yar", ".yara"})
MAX_RULE_BYTES = 1 << 20  # 1 MiB per rule file; a curated local rule is far smaller
DEFAULT_TIMEOUT_S = 10.0

ENV_ENABLED = "TRAC_YARA_ENABLED"
ENV_RULES_DIR = "TRAC_YARA_RULES_DIR"
ENV_TIMEOUT = "TRAC_YARA_TIMEOUT_S"

_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: A rule may assert maliciousness only by declaring it. An empty default means a
#: rule that merely matches is evidence, not a verdict.
MALICIOUS_TAG = "malicious"

# status values reported by scan(); kept as constants so callers compare, not parse.
STATUS_OK = "ok"
STATUS_DISABLED = "disabled"
STATUS_UNAVAILABLE = "unavailable"
STATUS_NO_RULES = "no_rules"
STATUS_ERROR = "error"
STATUS_NOT_COMPILED = "not_compiled"


def _import_yara():
    """Import yara-python lazily; it is an optional native dependency."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    return yara


def engine_available() -> bool:
    """True when yara-python is importable in this interpreter."""
    return _import_yara() is not None


def is_enabled(environ: Optional[Dict[str, str]] = None) -> bool:
    """Whether the operator turned the engine on.

    Setting ``TRAC_YARA_RULES_DIR`` is itself an opt-in: pointing TRAC at a curated
    ruleset is an instruction to use it.
    """
    env = os.environ if environ is None else environ
    if str(env.get(ENV_RULES_DIR, "")).strip():
        return True
    return str(env.get(ENV_ENABLED, "")).strip().lower() in _TRUTHY


def rules_dir(environ: Optional[Dict[str, str]] = None) -> Path:
    """The repository-controlled directory the ruleset is read from."""
    env = os.environ if environ is None else environ
    configured = str(env.get(ENV_RULES_DIR, "")).strip()
    return Path(configured) if configured else BUILTIN_RULES_DIR


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def rule_files(root: Optional[Path] = None, environ: Optional[Dict[str, str]] = None) -> List[Path]:
    """Every compilable rule file, or [] when the ruleset is empty or unusable.

    Anything that is not a regular ``.yar``/``.yara`` file under ``root`` is skipped
    without raising: an unreadable or escaping entry is a missing rule, not a
    crashed analysis.
    """
    directory = root if root is not None else rules_dir(environ)
    try:
        resolved = directory.resolve()
    except OSError:
        return []
    if not resolved.is_dir():
        return []

    found: List[Path] = []
    for candidate in sorted(resolved.rglob("*")):
        if candidate.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        if not _within(resolved, candidate):
            continue
        try:
            if not candidate.is_file() or candidate.stat().st_size > MAX_RULE_BYTES:
                continue
        except OSError:
            continue
        found.append(candidate)
    return found


def timeout_s(environ: Optional[Dict[str, str]] = None) -> float:
    env = os.environ if environ is None else environ
    raw = str(env.get(ENV_TIMEOUT, "")).strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_S
    return value if value > 0 else DEFAULT_TIMEOUT_S


def _match_to_dict(match: Any) -> Dict[str, Any]:
    """Project a ``yara.Match`` onto the contract's ``static.yara_matches`` item."""
    meta: Dict[str, Any] = {}
    for key, value in (getattr(match, "meta", None) or {}).items():
        meta[str(key)] = value
    tags = [str(tag) for tag in (getattr(match, "tags", None) or [])]
    entry: Dict[str, Any] = {"rule": str(match.rule)}
    namespace = getattr(match, "namespace", None)
    if namespace:
        entry["namespace"] = str(namespace)
    if tags:
        entry["tags"] = tags
    if meta:
        entry["meta"] = meta
    return entry


def asserts_malicious(match: Dict[str, Any]) -> bool:
    """Whether a reported match is a rule that *declares* maliciousness.

    A rule named ``Some_Obscure_Tool`` matching is evidence about that rule, not a
    threat verdict. Only a repository rule that says so in its tags or its metadata
    is allowed to move a score, which keeps every point in the model traceable to a
    curatable statement in ``m2_static/rules``.
    """
    if MALICIOUS_TAG in (match.get("tags") or []):
        return True
    meta = match.get("meta") or {}
    verdict = str(meta.get("verdict", "")).strip().lower()
    if verdict == MALICIOUS_TAG:
        return True
    return str(meta.get("malicious", "")).strip().lower() in {"true", "1", "yes"}


def family_assertion(matches: List[Dict[str, Any]]) -> Optional[str]:
    """The family a matched rule explicitly names in metadata, if any.

    Only ``meta.family`` counts. Deriving a family from a rule *name*, a filename,
    or a matched string would be TRAC inventing a threat classification.
    """
    for match in matches:
        meta = match.get("meta") or {}
        family = str(meta.get("family", "")).strip()
        if family:
            return family
    return None


def _compile(yara, files: List[Path]):
    """Compile the curated files as one namespaced ruleset.

    ``includes=False`` is the security-relevant flag: it stops a rule file from
    reaching the filesystem for anything the operator did not add to the directory.
    """
    filepaths = {path.stem: str(path) for path in files}
    return yara.compile(filepaths=filepaths, includes=False)


class ScanResult:
    """What a YARA pass produced: a status, and matches only when the pass ran."""

    def __init__(self, status: str, matches: Optional[List[Dict[str, Any]]] = None,
                 detail: str = "", rules: int = 0) -> None:
        self.status = status
        self.matches = matches
        self.detail = detail
        self.rules = rules

    @property
    def ran(self) -> bool:
        return self.matches is not None

    def published(self) -> Optional[List[Dict[str, Any]]]:
        """The value for ``static.yara_matches``: a list when the engine ran, else None.

        Returning None rather than [] is the whole point — M2 omits the key so no
        consumer can read "not assessed" as "checked and clean".
        """
        return self.matches if self.ran else None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ScanResult(status={self.status!r}, matches={None if self.matches is None else len(self.matches)}, rules={self.rules})"


def scan(data: bytes, environ: Optional[Dict[str, str]] = None) -> ScanResult:
    """Run the repository ruleset over *data*. Never raises.

    A YARA compile or match failure is reported as ``status="error"`` with a
    sanitised one-line detail and *no* match list, because "the rules failed" is not
    the same claim as "the rules matched nothing".
    """
    if not is_enabled(environ):
        return ScanResult(STATUS_DISABLED, detail=f"{ENV_ENABLED} is unset; YARA is opt-in")

    yara = _import_yara()
    if yara is None:
        return ScanResult(STATUS_UNAVAILABLE, detail="yara-python is not installed in this interpreter")

    files = rule_files(environ=environ)
    if not files:
        return ScanResult(STATUS_NO_RULES, detail=f"no .yar/.yara rules under {rules_dir(environ)}")

    try:
        rules = _compile(yara, files)
    except Exception as exc:
        return ScanResult(STATUS_ERROR, detail=f"ruleset did not compile: {type(exc).__name__}: {str(exc)[:180]}")

    try:
        # `data=` is a keyword on purpose: yara-python reads a positional first
        # argument as a *filepath*, so a bare bytes argument raises
        # "argument 1 must be str, not bytes" before any rule is evaluated.
        raw = rules.match(data=data, timeout=int(timeout_s(environ)))
    except TypeError:
        # Older yara-python has no timeout kwarg; the scan still runs.
        try:
            raw = rules.match(data=data)
        except Exception as exc:
            return ScanResult(STATUS_ERROR, detail=f"scan failed: {type(exc).__name__}: {str(exc)[:180]}")
    except Exception as exc:
        return ScanResult(STATUS_ERROR, detail=f"scan failed: {type(exc).__name__}: {str(exc)[:180]}")

    matches = [_match_to_dict(match) for match in sorted(raw, key=lambda m: str(m.rule))]
    return ScanResult(STATUS_OK, matches=matches, rules=len(files), detail=f"{len(matches)} match(es)")


def scan_for_section(data: bytes, environ: Optional[Dict[str, str]] = None) -> Tuple[Optional[List[Dict[str, Any]]], ScanResult]:
    """Convenience for ``analyze_static``: the value to publish, plus why."""
    result = scan(data, environ)
    return result.published(), result
