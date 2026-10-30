"""
M2 Static Analysis Engine
==========================
Real PE / binary static analysis for the TRAC malware-analysis platform.

Produces the ``static`` section of the shared AnalysisResult contract
(see contract/schemas/analysis_result.schema.json).

Public API
----------
    analyze_static(data, file_type, filename) -> dict

Dependencies: stdlib + pefile (installed in .venv).
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import pefile

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

# Max interesting strings to keep
_MAX_INTERESTING = 100
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


def _extract_strings_section(data: bytes) -> dict:
    """Build the ``strings`` contract object from raw file bytes."""
    ascii_strs = _extract_ascii_strings(data)
    unicode_strs = _extract_unicode_strings(data)
    all_strings = ascii_strs + unicode_strs
    total_count = len(all_strings)

    # De-duplicate interesting strings while preserving order
    seen: Set[str] = set()
    interesting: List[str] = []
    for s in all_strings:
        if _classify_interesting(s) is not None:
            # Truncate and defang
            truncated = s[:_MAX_STR_LEN]
            defanged = _defang_string(truncated)
            if defanged not in seen:
                seen.add(defanged)
                interesting.append(defanged)
            if len(interesting) >= _MAX_INTERESTING:
                break

    return {
        "count": total_count,
        "interesting": interesting,
        "deobfuscated_count": 0,
    }


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------


def _extract_urls(data: bytes) -> List[str]:
    """Extract and defang all URLs found in the binary data."""
    ascii_strs = _extract_ascii_strings(data)
    unicode_strs = _extract_unicode_strings(data)
    all_strings = ascii_strs + unicode_strs

    seen: Set[str] = set()
    urls: List[str] = []
    for s in all_strings:
        for m in _URL_RE.finditer(s):
            raw_url = m.group(0)
            defanged = _defang_url(raw_url)
            if defanged not in seen:
                seen.add(defanged)
                urls.append(defanged)
    return urls


# ---------------------------------------------------------------------------
# Packer detection
# ---------------------------------------------------------------------------


def _detect_packers(data: bytes, pe: Optional[pefile.PE] = None) -> List[str]:
    """Heuristic packer / protector detection.

    Checks:
    1. UPX signature in section names or raw bytes.
    2. High-entropy .text section (> 7.0) heuristic.
    3. Non-standard section names that don't start with ``'.'``.
    """
    packers: List[str] = []
    found_upx = False
    high_entropy_text = False
    anomalous_sections: List[str] = []

    # Check raw bytes for UPX magic
    if b"UPX!" in data:
        found_upx = True

    if pe is not None:
        for section in pe.sections:
            try:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
            except Exception:
                name = ""

            # UPX section names
            if "UPX" in name.upper():
                found_upx = True

            # High-entropy .text
            if name.lower() == ".text":
                try:
                    ent = section.get_entropy()
                    if ent > 7.0:
                        high_entropy_text = True
                except Exception:
                    pass

            # Anomalous section names (non-empty, not starting with '.')
            if name and not name.startswith("."):
                lower_name = name.lower()
                # Skip UPX-related names (already captured)
                if "upx" not in lower_name:
                    anomalous_sections.append(name)

    if found_upx:
        packers.append("UPX")
    if high_entropy_text:
        packers.append("high_entropy_packed")
    for sec_name in anomalous_sections:
        packers.append(f"anomalous_section:{sec_name}")

    return packers


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
        "yara_matches": [],
        "macros": [],
    }

    # -- PE-specific analysis --
    if file_type == "pe":
        try:
            pe_info, pe_obj = _analyze_pe(data)
            result["pe"] = pe_info
            result["packers"] = _detect_packers(data, pe_obj)
            pe_obj.close()
        except pefile.PEFormatError as exc:
            result["status"] = "failed"
            result["packers"] = []
            # Still return whatever we've gathered (entropy, strings, etc.)
            return result
        except Exception as exc:
            result["status"] = "failed"
            result["packers"] = []
            return result
    else:
        # Non-PE: still attempt packer byte-scan
        result["packers"] = _detect_packers(data)

    return result
