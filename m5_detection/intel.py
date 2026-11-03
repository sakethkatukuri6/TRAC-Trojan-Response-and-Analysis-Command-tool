"""
M5 threat-intel hash reputation
===============================
Resolves a sample hash against a locally held known-bad corpus.

This is deliberately *not* a network client: the lookup is a cached, operator-seeded
list, so an entry asserting `known_malicious` means "this analyst's own corpus says
so", not "a live provider says so today". Pointing it at abuse.ch or VirusTotal means
feeding the same shape from a real query and letting the caller stamp the provider.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "corpus" / "known_bad_hashes.json"

#: Providers the contract's `detections.intel_hits[].provider` enum accepts.
ALLOWED_PROVIDERS = frozenset({"virustotal", "malwarebazaar", "otx", "misp"})

_ALLOWED_RESULTS = frozenset({"known_malicious", "known_clean", "unknown"})

_cache: Dict[Path, Dict[str, Any]] = {}


def _load(path: Path) -> Optional[Dict[str, Any]]:
    """Read and validate the corpus, returning None when it cannot be trusted."""
    if path in _cache:
        return _cache[path]
    loaded: Optional[Dict[str, Any]] = None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = None
    if isinstance(raw, dict) and isinstance(raw.get("entries"), list):
        digests: Dict[str, Dict[str, Any]] = {}
        for entry in raw["entries"]:
            if not isinstance(entry, dict):
                continue
            digest = str(entry.get("sha256") or "").strip().lower()
            result = entry.get("result", "unknown")
            if len(digest) != 64 or result not in _ALLOWED_RESULTS:
                continue
            digests[digest] = entry
        provider = str(raw.get("provider") or "").strip().lower()
        loaded = {
            "provider": provider if provider in ALLOWED_PROVIDERS else "misp",
            "updated_at": str(raw.get("updated_at") or ""),
            "digests": digests,
        }
    _cache[path] = loaded
    return loaded


def db_path() -> Path:
    override = os.getenv("TRAC_KNOWN_BAD_DB")
    return Path(override) if override else DEFAULT_DB_PATH


def lookup_known_bad(sha256: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the corpus entry for this digest, or None.

    None means "no assertion was made" — it covers an absent digest as well as a
    corpus that is missing or unreadable, so a broken file can never silently become
    a `known_clean` verdict.
    """
    if not sha256:
        return None
    corpus = _load(db_path())
    if not corpus:
        return None
    return corpus["digests"].get(str(sha256).strip().lower())


def corpus_provider() -> Optional[str]:
    corpus = _load(db_path())
    return corpus["provider"] if corpus else None
