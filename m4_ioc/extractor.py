"""
M4 Indicator of Compromise (IOC) Extraction Engine
==================================================
Extracts, deduplicates, scores, and defangs all network, host, and behavioral
indicators from static strings, headers, and dynamic execution traces.

Conforms strictly to the `iocs` section of `analysis_result.schema.json`.

Two rules govern everything below.

*Defang last, parse first.* M2 publishes strings it has already defanged
(`hxxp://`, `[.]`), so a live-URL pattern never matches them. Every scan here runs
against a re-refanged copy of the text and the *extracted value* is defanged again
before it is published. Parsing the defanged form directly is what silently dropped
whole indicator classes.

*An indicator is a token, not a sentence.* A string that merely mentions a mutex
used to be published as the mutex. Only the identifier itself is ever published,
with the extraction path recorded in `source` and its reliability in `confidence`.
"""

from __future__ import annotations

import re
import string
from typing import Any, Dict, List, Set, Tuple

from m2_static.pe_evidence import capability_meta, group_imports

_URL_RE = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

# Registry: an explicit hive root followed by subkeys. Both the abbreviated and the
# long form are matched, and the value stops at the first character that cannot be
# part of a key path, so prose does not become an indicator.
_REGISTRY_RE = re.compile(
    r"\b(?:HKEY_(?:CURRENT_USER|LOCAL_MACHINE|CLASSES_ROOT|CURRENT_CONFIG|USERS|"
    r"PERFORMANCE_DATA|DYN_DATA)|HK(?:CU|LM|CR|CC|U))(?:\\[^\r\n\x00\";]{1,240})+",
    re.IGNORECASE,
)

# Named kernel objects. `Global\`/`Local\` and the session-scoped BaseNamedObjects
# path are unambiguous; a bare word is not, so it is only taken when it is itself a
# mutex-shaped identifier rather than a sentence that contains one. The scope prefix
# is kept in the published value: `Global\Foo` and `Local\Foo` are different objects.
_OBJECT_TAIL = r"[^\r\n\x00\"';|<>*?(),]{1,200}"
_NAMED_OBJECT_RE = re.compile(
    # The leading backslash is optional: M2 publishes both "\Global\Foo" and
    # "Global\Foo" depending on how the string was stored in the binary.
    r"(?<!\w)(\\?(?:Global|Local)\\" + _OBJECT_TAIL + r")",
    re.IGNORECASE,
)
_SESSION_OBJECT_RE = re.compile(
    r"\\Sessions\\\d{1,3}\\BaseNamedObjects\\" + _OBJECT_TAIL
)
_LABELED_MUTEX_RE = re.compile(
    r"\b([A-Za-z0-9_\-.\[\]{}]{1,96}(?:mutex|mut3x)[A-Za-z0-9_\-.\[\]{}]{0,96})\b",
    re.IGNORECASE,
)

# The Win32 entry points that contain the word "mutex" without naming one. They sit in
# almost every import table, so treating them as object names would publish an indicator
# for every sample in the vault.
_MUTEX_API_NAMES = frozenset(
    """
    createmutexa createmutexw createmutexexa createmutexexw openmutexa openmutexw
    releasemutex releasemutexabandoned waitformutex deletemutex createmutex
    """
    .split()
)

_USER_AGENT_RE = re.compile(r"\bUser-Agent\s*:\s*(\S[^\r\n\x00\"]{1,250})", re.IGNORECASE)
_FILEPATH_RE = re.compile(r"\b[A-Za-z]:[\\/][^\r\n\x00\"|<>*?]{3,240}")
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9.\-]+(?:\\[^\r\n\x00\"|<>*?]{1,200})?")

# The contract's semantic gate rejects any value still holding "[A-Za-z0-9-]\.[A-Za-z0-9]".
# The boundaries are matched zero-width on purpose: a consuming pattern swallows the
# character after each dot, so consecutive single-digit octets ("192.0.2.10", "8.8.8.8")
# leave their last dot raw and the indicator fails validation.
_RAW_DOT = re.compile(r"(?<=[A-Za-z0-9\-])\.(?=[A-Za-z0-9])")


def _defang_dots(val: str) -> str:
    return _RAW_DOT.sub("[.]", val)


_SPLIT_WS = re.compile(r"\s+")


def _path_token(value: str) -> str:
    """Cut a path or registry key at the first space that does not continue it.

    A space inside a real Windows path is followed by another segment, so the rest of
    the match still carries a separator ("C:\\Program Files\\app.exe"). Prose is not, so
    "...\\Run key was created" and "C:\\...\\stage2.exe was written at boot" stop at the
    indicator. The price is a truncated file name when the *last* segment itself holds
    a space ("C:\\Dir\\My File.txt"); that is rarer than the sentence bleed it prevents.
    """
    parts = _SPLIT_WS.split(value)
    kept = [parts[0]]
    for part in parts[1:]:
        if "\\" not in part and "/" not in part:
            break
        kept.append(part)
    return " ".join(kept)


def _refang(val: str) -> str:
    """Undo M2's defanging so the live-URL and registry patterns can match.

    Internal to this module: the returned text is input to the scanners only, never
    published. Anything that leaves M4 goes through :func:`defang`.
    """
    return val.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")


# Strings that end a dotted token but are never a real TLD. Without this, every
# "kernel32.dll" or "readme.txt" in the string table is published as a domain.
_NON_TLD_SUFFIXES = frozenset(
    """
    txt dll ocx sys pdb cfg ini cnf htm html xml json png jpg jpeg gif bmp ico cur
    css js ts jsx tsx mjs c cc h hpp cpp cpp2 md rst log tmp bak dat bin lib obj o
    res def manifest msil rtf pdf zip gz tar tgz iso cab msi msp msm ps1 psm1 bat cmd
    vbs vbe reg old new exe drv fon ttf otf woff woff2 svg webp mp3 wav avi mp4 dll2
    debug release assert asm inc def idl proto tfstate lock yaml yml toml sql csv tsv
    """.split()
)

# Real TLDs are ~1500 and change; enumerating them is a maintenance trap. Instead:
# every two-letter code (all ccTLDs are two letters), the generic TLDs that malware
# actually registers under, and the special-use names TRAC's own fixtures use.
_COMMON_TLDS = frozenset(
    {
        "com", "net", "org", "info", "biz", "name", "pro", "edu", "gov", "mil", "int",
        "xyz", "top", "site", "online", "store", "shop", "live", "tech", "click",
        "link", "download", "win", "bid", "date", "trade", "party", "stream", "webcam",
        "cam", "icu", "cyou", "bond", "lol", "sbs", "lat", "ai", "app", "dev", "cloud",
        "host", "space", "website", "press", "fun", "gdn", "zip", "mov", "tv", "cc",
        "me", "co", "io", "ly", "to", "ws", "su", "tk", "ml", "ga", "cf", "gq", "pw",
        "example", "test", "invalid", "localhost",
    }
)
_TWO_LETTER = frozenset(a + b for a in string.ascii_lowercase for b in string.ascii_lowercase)


def _looks_like_domain(candidate: str) -> bool:
    """Reject filename-shaped text that merely has a dot in it.

    Recall is traded away on purpose: an allowlist of two-letter ccTLDs and the
    generic TLDs malware actually registers under keeps "kernel32.dll" and
    "System.Windows" out of the feed. The cost is an unusual gTLD in a URL-less
    string; URLs are still parsed for their host without this filter.
    """
    tld = candidate.rsplit(".", 1)[-1].lower()
    return tld in _TWO_LETTER or tld in _COMMON_TLDS


def _url_authority(url: str) -> str:
    """The host part of a URL, minus scheme, userinfo and port.

    The scheme goes first: splitting on "/" before removing it would cut
    "http://host/path" at the slashes inside the scheme separator.
    """
    stripped = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", url)
    authority = re.split(r"[/?#]", stripped, maxsplit=1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[-1]
    # Strip the port without touching an IPv6 literal's colons.
    if not authority.startswith("[") and ":" in authority:
        authority = authority.rsplit(":", 1)[0]
    return authority.strip()


# Whitelist benign domains from appearing as hostile C2
_BENIGN_DOMAINS = frozenset({
    "w3.org", "microsoft.com", "schemas.microsoft.com", "tempuri.org",
    "github.com", "google.com", "digicert.com", "verisign.com",
    "usertrust.com", "sectigo.com", "letsencrypt.org", "adobe.com",
    "xml.org", "oasis-open.org", "openxmlformats.org"
})

# Addresses that are never a remote indicator: loopback, unspecified, limited
# broadcast and link-local. Documentation space (192.0.2.0/24) and RFC1918 space are
# deliberately NOT excluded - the contract fixtures live in the former, and a
# Trojan beaconing to an internal address is still a beacon.
_NON_REMOTE_IP_PREFIXES = ("127.", "0.", "255.", "169.254.", "224.", "240.")


def _is_remote_ip(ip: str) -> bool:
    return not ip.startswith(_NON_REMOTE_IP_PREFIXES)


# How much each extraction path is trusted, reported as `confidence` on the
# indicator. A hash read back from the vault record is certain; a domain-shaped
# substring of the string table is a guess about what that text meant, so it ranks
# lowest. Observed dynamic artefacts outrank their static counterparts because a
# registry key seen at runtime is a fact, while one found as a string is only a
# possibility. Edit here, not at the call sites, so the ranking stays comparable.
SOURCE_CONFIDENCE = {
    "sample_hash": 1.0,
    "embedded_url": 0.85,
    "url_in_strings": 0.8,
    "url_host": 0.75,
    "ip_in_strings": 0.75,
    "domain_in_strings": 0.6,
    "email_in_strings": 0.65,
    "registry_in_strings": 0.75,
    "named_object_in_strings": 0.7,
    "labeled_mutex_in_strings": 0.5,
    "user_agent_in_strings": 0.7,
    "filepath_in_strings": 0.5,
    "unc_share_in_strings": 0.55,
    "import_capability": 0.85,
    "dynamic_mutex": 0.85,
    "dynamic_registry": 0.8,
    "dynamic_filepath": 0.75,
}


def defang(ioc_type: str, val: str) -> str:
    """Strictly defang indicators per contract semantic rules."""
    if not val:
        return ""
    if ioc_type == "url":
        val = val.replace("https://", "hxxps://").replace("http://", "hxxp://")
        val = val.replace("HTTPS://", "hxxps://").replace("HTTP://", "hxxp://")
        return _defang_dots(val)
    if ioc_type in ("domain", "ip"):
        return _defang_dots(val)
    if ioc_type == "email":
        parts = val.split("@")
        if len(parts) == 2:
            return f"{parts[0]}@{_defang_dots(parts[1])}"
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

    def add_ioc(itype: str, raw_val: str, src: str, conf: float) -> bool:
        clean_val = defang(itype, raw_val.strip().strip("\t "))
        clean_val = clean_val[:2048]
        key = (itype, clean_val.lower())
        if not clean_val or key in seen:
            return False
        seen.add(key)
        items.append({
            "type": itype,
            "value": clean_val,
            "source": src,
            "confidence": round(min(max(conf, 0.1), 1.0), 2),
        })
        return True

    # 1. Hashes from sample
    if sample_record.get("sha256"):
        add_ioc("sha256", sample_record["sha256"], "static_strings", SOURCE_CONFIDENCE["sample_hash"])
    if sample_record.get("md5"):
        add_ioc("md5", sample_record["md5"], "static_strings", SOURCE_CONFIDENCE["sample_hash"])

    # 2. Embedded URLs found by M2 (already defanged; `defang` is idempotent here).
    for u in static_result.get("embedded_urls", []) or []:
        if add_ioc("url", u, "static_strings", SOURCE_CONFIDENCE["embedded_url"]):
            _add_host_indicator(add_ioc, u)

    # 3. The interesting-string table. M2 defangs what it publishes, so scan the
    #    re-refanged copy and defang only the values that get published.
    for s in (static_result.get("strings", {}) or {}).get("interesting", []) or []:
        _mine_string(str(s), add_ioc)

    # 4. Dynamic results (mutexes, registry, filepaths)
    for m in dynamic_result.get("mutexes", []):
        add_ioc("mutex", m, "dynamic", SOURCE_CONFIDENCE["dynamic_mutex"])

    for rev in dynamic_result.get("registry_events", []):
        if rev.get("target"):
            add_ioc("registry_key", rev["target"], "dynamic", SOURCE_CONFIDENCE["dynamic_registry"])

    for fev in dynamic_result.get("file_events", []):
        if fev.get("target"):
            add_ioc("filepath", fev["target"], "dynamic", SOURCE_CONFIDENCE["dynamic_filepath"])

    # 5. ATT&CK techniques supported by actual static markers. These describe
    #    capability, not observed execution; runtime observations arrive from CAPE.
    attack_techniques = _attack_techniques(static_result, dynamic_result)

    # Beacon timing is an observed network property. Static strings cannot establish
    # frequency or jitter, so it is never invented here.
    beacons: List[Dict[str, Any]] = []

    return {
        "status": "done",
        "items": items,
        "attack_techniques": attack_techniques,
        "beacons": beacons,
    }


def _add_host_indicator(add_ioc, url: str) -> None:
    """Publish the host of a URL as its own domain or IP indicator.

    A beacons-grade indicator on its own: an analyst blocks a domain, not a path.
    """
    host = _url_authority(_refang(url))
    if not host:
        return
    if _IP_RE.fullmatch(host):
        if _is_remote_ip(host):
            add_ioc("ip", host, "static_strings", SOURCE_CONFIDENCE["url_host"])
        return
    if "." in host and not any(host.endswith(b) for b in _BENIGN_DOMAINS):
        add_ioc("domain", host.lower(), "static_strings", SOURCE_CONFIDENCE["url_host"])


def _mine_string(raw: str, add_ioc) -> None:
    """Pull every indicator shape out of one published (possibly defanged) string."""
    text = _refang(raw)

    for url in _URL_RE.findall(text):
        if add_ioc("url", url, "static_strings", SOURCE_CONFIDENCE["url_in_strings"]):
            _add_host_indicator(add_ioc, url)

    for ip in _IP_RE.findall(text):
        if _is_remote_ip(ip):
            add_ioc("ip", ip, "static_strings", SOURCE_CONFIDENCE["ip_in_strings"])

    for candidate in _DOMAIN_RE.findall(text):
        host = candidate.lower().strip(".")
        if _IP_RE.fullmatch(host) or not _looks_like_domain(host):
            continue
        if any(host == b or host.endswith("." + b) for b in _BENIGN_DOMAINS):
            continue
        add_ioc("domain", host, "static_strings", SOURCE_CONFIDENCE["domain_in_strings"])

    for email in _EMAIL_RE.findall(text):
        add_ioc("email", email, "static_strings", SOURCE_CONFIDENCE["email_in_strings"])

    for match in _REGISTRY_RE.finditer(text):
        key = _path_token(match.group(0)).rstrip("\\ ")
        if key:
            add_ioc("registry_key", key, "static_strings", SOURCE_CONFIDENCE["registry_in_strings"])

    # Named objects found with their scope, so the bare-name path below can tell
    # "a second object" from "the same object, quoted without its prefix".
    scoped: List[str] = []

    for name in _NAMED_OBJECT_RE.findall(text):
        # The scope is part of the object's identity, so it is kept.
        value = name.lstrip("\\")
        if add_ioc("mutex", value, "static_strings", SOURCE_CONFIDENCE["named_object_in_strings"]):
            scoped.append(value)

    for match in _SESSION_OBJECT_RE.finditer(text):
        value = match.group(0)
        if add_ioc("mutex", value, "static_strings", SOURCE_CONFIDENCE["named_object_in_strings"]):
            scoped.append(value)

    for token in _LABELED_MUTEX_RE.findall(text):
        # The word "mutex" on its own is a label in prose, not an object name.
        if len(token) < 6 or token.lower() in {"mutex", "mut3x"} or token.lower() in _MUTEX_API_NAMES:
            continue
        # `CreateMutexW(\Global\Foo)` yields both `Global\Foo` and the bare `Foo`;
        # publishing the tail again would double the same object at a lower tier.
        if any(name.endswith("\\" + token) for name in scoped):
            continue
        add_ioc("mutex", token, "static_strings", SOURCE_CONFIDENCE["labeled_mutex_in_strings"])

    for agent in _USER_AGENT_RE.findall(text):
        add_ioc("user_agent", agent.strip(), "static_strings", SOURCE_CONFIDENCE["user_agent_in_strings"])

    for path in _FILEPATH_RE.findall(text):
        add_ioc("filepath", _path_token(path).rstrip("\\/ ."), "static_strings",
                SOURCE_CONFIDENCE["filepath_in_strings"])

    for share in _UNC_RE.findall(text):
        add_ioc("filepath", _path_token(share).rstrip("\\/ ."), "static_strings",
                SOURCE_CONFIDENCE["unc_share_in_strings"])


def _attack_techniques(
    static_result: Dict[str, Any],
    dynamic_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """ATT&CK mappings, each carrying the evidence that produced it.

    Two independent sources are merged on technique id: M3's behavioural markers and
    M2's import capability groups. A technique named by both lists both evidences
    rather than publishing the same id twice.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    def note(attack_id: str, tactic: str, evidence: str) -> None:
        entry = merged.setdefault(attack_id, {"id": attack_id, "tactic": tactic, "evidence": []})
        if evidence and evidence not in entry["evidence"]:
            entry["evidence"].append(evidence)

    for info in (dynamic_result.get("_static_capabilities", {}) or {}).values():
        note(info["att_id"], info["tactic"], f"Static markers: {', '.join(info['matches'])[:400]}")

    published_imports = (static_result.get("pe") or {}).get("imports") or []
    for group, members in group_imports(published_imports).items():
        tactic, attack_id = capability_meta(group)
        if not attack_id:
            # Cryptography and file I/O are ordinary application behaviour. Reporting
            # them as a technique would be an accusation without a basis.
            continue
        note(attack_id, tactic, f"Imported APIs: {', '.join(members)[:400]}")

    if static_result.get("entropy", 0.0) > 7.0:
        note("T1027", "defense-evasion", f"Obfuscated / Packed PE payload: Entropy {static_result['entropy']:.2f}")

    techniques: List[Dict[str, Any]] = []
    for entry in merged.values():
        techniques.append({
            "id": entry["id"],
            "tactic": entry["tactic"],
            "evidence": "; ".join(entry["evidence"])[:500],
        })
    return techniques
