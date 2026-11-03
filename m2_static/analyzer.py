"""
M2 Static Analysis Engine
==========================
Real PE / binary static analysis for the TRAC malware-analysis platform.

Produces the ``static`` section of the shared AnalysisResult contract
(see contract/schemas/analysis_result.schema.json).

Public API
----------
    analyze_static(data, file_type, filename) -> dict

Dependencies: stdlib + pefile (installed in .venv). YARA is optional and opt-in;
see ``m2_static/yara_scan.py``.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import pefile

from m2_static import pe_evidence, yara_scan

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard PE section names (case-insensitive comparison)
_STANDARD_SECTION_PREFIXES = frozenset({
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
    ".reloc", ".pdata", ".tls", ".debug", ".crt", ".sxdata",
    ".gfids", ".00cfg", ".voltbl",
})

# Regex for printable ASCII strings (>= 4 chars)
_ASCII_RE = re.compile(rb"[\x20-\x7E]{4,}")

# Regex for URL detection (used on decoded strings)
_URL_RE = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# Regex for IP addresses
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# Patterns that flag a string as "interesting"
_INTERESTING_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("url",       _URL_RE),
    ("ip",        _IP_RE),
    ("registry",  re.compile(r"HK(?:CU|LM|CR|CC|U)\\", re.IGNORECASE)),
    ("filepath",  re.compile(r"[A-Za-z]:\\[^\x00-\x1F]{3,}", re.IGNORECASE)),
    ("unc_path",  re.compile(r"\\\\[A-Za-z0-9_.\\-]+\\", re.IGNORECASE)),
    ("http_hdr",  re.compile(r"(?:User-Agent|Content-Type|Accept|Host|Referer):", re.IGNORECASE)),
    ("crypto",    re.compile(r"(?:AES|RSA|RC4|DES|SHA[0-9]*|MD5|HMAC|BEGIN (?:RSA |PUBLIC |PRIVATE )?KEY)", re.IGNORECASE)),
    ("mutex",     re.compile(r"(?:Global|Local)\\[A-Za-z0-9_\-{}.]+", re.IGNORECASE)),
    ("base64",    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")),
]

# Max interesting strings to keep, and per category.
#
# A flat cap on the first matches wins the race to a noisy binary: one PE with a
# few hundred base64-shaped identifier strings would fill the budget before the
# registry key or mutex that M4 needs ever got published. So each category gets its
# own quota and the global cap only bounds the total.
_MAX_INTERESTING = 250
_CATEGORY_QUOTA: Dict[str, int] = {
    "url": 60,
    "ip": 60,
    "registry": 60,
    "mutex": 60,
    "http_hdr": 40,
    "filepath": 40,
    "unc_path": 30,
    "crypto": 15,
    "base64": 15,
}
# Max length per interesting string
_MAX_STR_LEN = 512

# ---------------------------------------------------------------------------
# Defanging helpers
# ---------------------------------------------------------------------------


def _defang_url(url: str) -> str:
    """Defang a URL: hxxp(s) + dot-bracket notation for the host."""
    url = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    url = url.replace("HTTPS://", "hxxps://").replace("HTTP://", "hxxp://")
    # Defang dots in the authority (host) portion only
    url = _defang_host_dots(url)
    return url


def _defang_host_dots(url: str) -> str:
    """Replace dots with [.] in the host part of a (possibly defanged) URL."""
    prefix_pattern = re.compile(r"^(hxxps?://)([^/?#]+)(.*)", re.IGNORECASE)
    m = prefix_pattern.match(url)
    if not m:
        return url
    scheme, host, rest = m.group(1), m.group(2), m.group(3)
    host = host.replace(".", "[.]")
    return scheme + host + rest


def _defang_ip(ip: str) -> str:
    """Defang an IP address by replacing dots with [.]."""
    return ip.replace(".", "[.]")


def _defang_string(s: str) -> str:
    """Defang any URLs or bare IPs found inside an arbitrary string."""
    # Defang full URLs first
    s = _URL_RE.sub(lambda m: _defang_url(m.group(0)), s)
    # Defang remaining bare IPs that aren't already inside brackets
    def _replace_ip(m: re.Match) -> str:
        ip = m.group(0)
        # Check if already defanged (preceded by '[')
        start = m.start()
        if start > 0 and s[start - 1] == "[":
            return ip
        return _defang_ip(ip)
    s = _IP_RE.sub(_replace_ip, s)
    return s


def _clamp_string(s: str, max_len: int = _MAX_STR_LEN) -> str:
    """Clamp string to max_len, ensuring severed defang markers are cleaned."""
    if len(s) <= max_len:
        return s
    trimmed = s[:max_len]
    if trimmed.endswith("[."):
        trimmed = trimmed[:-2]
    elif trimmed.endswith("["):
        trimmed = trimmed[:-1]
    return trimmed


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte) for *data*."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------


def _extract_ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable ASCII strings of at least *min_len* characters."""
    return [m.group().decode("ascii", errors="replace") for m in _ASCII_RE.finditer(data)]


def _extract_unicode_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract UTF-16-LE encoded strings of at least *min_len* characters."""
    results: List[str] = []
    # Pattern: sequences of (printable-ASCII byte, 0x00) repeated >= min_len times
    pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data):
        try:
            decoded = m.group().decode("utf-16-le")
            results.append(decoded)
        except (UnicodeDecodeError, ValueError):
            pass
    return results


def _classify_interesting(s: str) -> Optional[str]:
    """Return the category tag if *s* is interesting, else None."""
    for tag, pattern in _INTERESTING_PATTERNS:
        if pattern.search(s):
            return tag
    return None


def _iter_strings(data: bytes) -> List[str]:
    """Every printable ASCII and UTF-16-LE string in *data*, in file order."""
    return _extract_ascii_strings(data) + _extract_unicode_strings(data)


def _extract_strings_section(data: bytes) -> dict:
    """Build the ``strings`` contract object from raw file bytes."""
    all_strings = _iter_strings(data)
    total_count = len(all_strings)

    # Bucket by category, de-duplicate on the defanged value, and hold each bucket
    # to its own quota so a flood of one kind cannot evict every other kind.
    taken: Dict[str, int] = {}
    seen: Set[str] = set()
    interesting: List[str] = []
    for s in all_strings:
        tag = _classify_interesting(s)
        if tag is None:
            continue
        quota = _CATEGORY_QUOTA.get(tag, 10)
        if taken.get(tag, 0) >= quota or len(interesting) >= _MAX_INTERESTING:
            continue
        # Defang first, then clamp to _MAX_STR_LEN so defanging expansion
        # (e.g. bare IP dots expanding to "[.]") cannot exceed schema maxLength.
        defanged = _clamp_string(_defang_string(s[:_MAX_STR_LEN]))
        if defanged in seen:
            continue
        seen.add(defanged)
        interesting.append(defanged)
        taken[tag] = taken.get(tag, 0) + 1

    return {
        "count": total_count,
        "interesting": interesting,
        # `deobfuscated_count` is omitted, not zero: no deobfuscation pass runs here, so
        # 0 would report "decoded some strings and none were interesting".
    }


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def _extract_urls(data: bytes) -> List[str]:
    """Extract and defang all URLs found in the binary data."""
    seen: Set[str] = set()
    urls: List[str] = []
    for s in _iter_strings(data):
        for m in _URL_RE.finditer(s):
            defanged = _defang_url(m.group(0))
            if defanged not in seen:
                seen.add(defanged)
                urls.append(defanged)
    return urls


# ---------------------------------------------------------------------------
# Packer indicators
# ---------------------------------------------------------------------------
#
# The reading of the evidence lives in ``m2_static.pe_evidence`` so that M5 scores
# exactly the tokens M2 publishes. M2's job is to choose which of them belong in the
# contract's ``static.packers`` field: the tool signatures and the packing signs,
# not the structural anomalies, which are not packers and are reported by M5 directly.


def _detect_packers(data: bytes, pe: Optional[pefile.PE] = None,
                    evidence: Optional[pe_evidence.PeEvidence] = None) -> List[str]:
    """Packer/protector indicators for ``static.packers``.

    Without a parsed header only container banners can be read, so the non-PE path
    stays honest instead of guessing at sections it cannot see.
    """
    if pe is None:
        return pe_evidence.container_indicators(data, evidence)
    ev = evidence if evidence is not None else pe_evidence.collect_pe_evidence(data, pe)
    return list(ev.packers)


# ---------------------------------------------------------------------------
# PE-specific analysis
# ---------------------------------------------------------------------------

_IMAGE_FILE_DLL = 0x2000
_IMAGE_DIRECTORY_ENTRY_SECURITY = 4


def _analyze_pe(data: bytes) -> Tuple[dict, pefile.PE]:
    """Parse a PE file and return (pe_section_dict, pe_object).

    Raises ``pefile.PEFormatError`` on invalid PE data.
    """
    pe = pefile.PE(data=data, fast_load=False)

    # --- Sections ---
    sections: List[dict] = []
    for section in pe.sections:
        try:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        except Exception:
            name = "<unknown>"
        sec_entry: dict = {
            "name": name,
            "entropy": round(section.get_entropy(), 4),
        }
        try:
            sec_entry["virtual_size"] = section.Misc_VirtualSize
        except AttributeError:
            pass
        try:
            sec_entry["raw_size"] = section.SizeOfRawData
        except AttributeError:
            pass
        sections.append(sec_entry)

    # --- Imports ---
    imports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
            except Exception:
                dll_name = "<unknown>"
            for imp in entry.imports:
                if imp.name:
                    try:
                        func_name = imp.name.decode("utf-8", errors="replace")
                    except Exception:
                        func_name = f"ord{imp.ordinal}"
                else:
                    func_name = f"ord{imp.ordinal}"
                imports.append(f"{dll_name}:{func_name}")

    # --- Exports ---
    exports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                try:
                    exports.append(exp.name.decode("utf-8", errors="replace"))
                except Exception:
                    exports.append(f"ord{exp.ordinal}")
            else:
                exports.append(f"ord{exp.ordinal}")

    # --- Imphash ---
    imphash = ""
    try:
        imphash = pe.get_imphash() or ""
    except Exception:
        pass

    # --- Compile time ---
    compile_time = ""
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        compile_time = dt.isoformat()
    except (OSError, ValueError, OverflowError):
        compile_time = ""

    # --- DLL flag ---
    is_dll = bool(pe.FILE_HEADER.Characteristics & _IMAGE_FILE_DLL)

    # --- Signed (has IMAGE_DIRECTORY_ENTRY_SECURITY) ---
    signed = False
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_IMAGE_DIRECTORY_ENTRY_SECURITY]
        if sec_dir.VirtualAddress != 0 and sec_dir.Size != 0:
            signed = True
    except (IndexError, AttributeError):
        pass

    pe_info: dict = {
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "imphash": imphash,
        "is_dll": is_dll,
        "signed": signed,
    }
    if compile_time:
        pe_info["compile_time"] = compile_time

    return pe_info, pe


# ---------------------------------------------------------------------------
# File-class mapping
# ---------------------------------------------------------------------------

_FILE_CLASS_MAP = {
    "pe": "pe",
    "elf": "elf",
    "macho": "macho",
    "office": "office",
    "pdf": "pdf",
    "script": "script",
    "archive": "archive",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_static(data: bytes, file_type: str, filename: str = "") -> dict:
    """Run static analysis on raw sample bytes.

    Parameters
    ----------
    data : bytes
        Raw file content.
    file_type : str
        One of the ``file_type`` enum values from the contract
        (``pe``, ``elf``, ``macho``, ``office``, ``pdf``,
        ``script``, ``archive``, ``other``).
    filename : str, optional
        Original (sanitised) filename — used for display only.

    Returns
    -------
    dict
        The ``static`` section of the AnalysisResult contract.
    """
    file_class = _FILE_CLASS_MAP.get(file_type, "other")

    # -- Full-file Shannon entropy --
    entropy = _shannon_entropy(data)

    # -- Strings --
    strings_section = _extract_strings_section(data)

    # -- Embedded URLs --
    embedded_urls = _extract_urls(data)

    result: dict = {
        "status": "done",
        "file_class": file_class,
        "entropy": entropy,
        "strings": strings_section,
        "embedded_urls": embedded_urls,
        # `macros` is omitted, not empty: no macro parser exists in this module.
    }

    # -- Optional local YARA --
    # Published only when the engine actually ran. Absent means "not assessed",
    # [] means "ruleset compiled, nothing matched" - M8 renders those two
    # differently and M5's confidence depends on the distinction.
    yara_matches, _yara_result = yara_scan.scan_for_section(data)
    if yara_matches is not None:
        result["yara_matches"] = yara_matches

    # -- PE-specific analysis --
    if file_type == "pe":
        try:
            pe_info, pe_obj = _analyze_pe(data)
            result["pe"] = pe_info
            result["packers"] = _detect_packers(data, pe_obj)
            pe_obj.close()
        except pefile.PEFormatError:
            result["status"] = "failed"
            result["packers"] = _detect_packers(data)
            # Still return whatever we've gathered (entropy, strings, etc.)
            return result
        except Exception:
            result["status"] = "failed"
            result["packers"] = _detect_packers(data)
            return result
    else:
        # Non-PE: packer banners are still readable from the container.
        result["packers"] = _detect_packers(data)

    return result
