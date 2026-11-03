"""
M2 PE structural evidence
=========================
Turns a PE header into analyst-usable facts: which sections carry which
permissions, where the entry point lands, what the imported APIs let the binary
do, whether bytes are appended past the last section, and which packer or
protector signatures are actually present.

Why this lives outside ``analyze_static``'s published output
-----------------------------------------------------------
``contract/schemas/analysis_result.schema.json`` fixes ``static.pe`` to
``additionalProperties: false`` with only ``sections``/``imports``/``exports``
(and a handful of scalars). Permission bits, overlay size and entry-point
placement have no legal home in the published document, so they are exposed
here as a Python API instead:

* M2 calls :func:`collect_pe_evidence` while it already holds the parsed PE and
  publishes only the packer indicators, into ``static.packers``.
* M5 calls the same function to score and describe the structural findings.
  Import groups come from the already-published ``static.pe.imports``, so M4
  needs no second parse.

Every finding is a triple of ``code`` (stable, machine-checked), ``detail``
(the sentence an analyst reads) and ``values`` (the numbers behind it), so a
score contribution can always be traced back to the header field that produced
it. Nothing here executes, unpacks, or loads the sample.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pefile

# ---------------------------------------------------------------------------
# Header constants (windows/winnt.h values, restated so no Windows import is needed)
# ---------------------------------------------------------------------------

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_FILE_DLL = 0x2000

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

# Optional-header data directory indexes used by the checks below.
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6

# Entropy thresholds. 7.2 is the value the rest of TRAC already treats as
# "packed or encrypted"; 6.8 is where a normally-compressible code section stops
# looking like compiler output.
SECTION_HIGH_ENTROPY = 7.2
SECTION_ELEVATED_ENTROPY = 6.8

# A raw region this large past the end of the file is not padding, it is content.
MIN_NOTABLE_OVERLAY = 512

MAX_FINDING_LIST = 12  # how many members of a multi-section finding are named


class Finding(dict):
    """One traceable structural observation."""

    @classmethod
    def build(cls, code: str, detail: str, **values: Any) -> "Finding":
        return cls(code=code, detail=detail, values=values)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Packer and protector signatures
# ---------------------------------------------------------------------------

# Section names are the evidence: these spellings are written by the tools named
# on the right. An unnamed high-entropy section is *not* mapped to a tool here,
# because that would be a guess about provenance rather than a reading of bytes.
_PACKER_SECTION_NAMES = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".ASPACK": "ASPack",
    ".ADATA": "ASPack",
    ".ENIGMA1": "Enigma Protector",
    ".ENIGMA2": "Enigma Protector",
    ".THEMIDA": "Themida",
    ".VMP0": "VMProtect",
    ".VMP1": "VMProtect",
    "VMPROTECT": "VMProtect",
    "MPRESS1": "MPRESS",
    "MPRESS2": "MPRESS",
    ".PETITE": "Petite",
    ".PEC0": "PECompact",
    ".PEC1": "PECompact",
    ".PEC2": "PECompact",
    "PECOMPACT2": "PECompact",
    ".NSP0": "NSPack",
    ".NSP1": "NSPack",
    ".NSP2": "NSPack",
    ".ARMADILLO": "Armadillo",
    "SVKP": "ASPack",
    "MEWT": "MEW",
}

# Signatures that appear verbatim in the container of a file the tool produced.
_PACKER_BYTE_SIGNATURES = {
    b"UPX!": "UPX",
    b"$Info: This file is packed with the UPX": "UPX",
    b"MPRESS header": "MPRESS",
}

# Standard linker-emitted names. Anything else that is executable is worth a look.
_STANDARD_NAMES = frozenset(
    {
        ".text",
        ".data",
        ".rdata",
        ".bss",
        ".idata",
        ".edata",
        ".rsrc",
        ".reloc",
        ".pdata",
        ".tls",
        ".debug",
        ".crt",
        ".sxdata",
        ".gfids",
        ".00cfg",
        ".voltbl",
        ".rodata",
        ".eh_fram",
        ".gcc_table",
        ".ctors",
        ".dtors",
        ".tbss",
        ".init",
        ".fini",
        ".comment",
        ".note",
        ".textalign",
        ".itab",
        ".noptrdata",
        ".noptrbss",
        ".zdebug_abbre",
        ".buildinfo",
        ".go_",
        ".tls_data",
    }
)


# ---------------------------------------------------------------------------
# Import capability groups
# ---------------------------------------------------------------------------

# (group, tactic, attack id, function-name substrings). Lower-case substrings of
# the imported function name; ordinal imports never match.
#
# `attack_id` is only populated where the API cluster has an unambiguous ATT&CK
# technique. Cryptography and file I/O are ordinary application behaviour, so they
# are reported as capabilities without a technique and without a score.
IMPORT_CAPABILITY_GROUPS: Tuple[Tuple[str, str, Optional[str], Tuple[str, ...]], ...] = (
    (
        "process_injection",
        "defense-evasion",
        "T1055",
        (
            "createremotethread",
            "writeprocessmemory",
            "queueuserapc",
            "setthreadcontext",
            "rtlcreateuserthread",
            "ntcreatethreadex",
            "ntmapviewofsection",
            "MapViewOfFile3",
            "NtUnmapViewOfSectionEx",
            "VirtualAllocExNuma",
        ),
    ),
    (
        "persistence",
        "persistence",
        "T1547.001",
        (
            "regsetvalueex",
            "regcreatekeyex",
            "regsavekey",
            "registervalueset",
            "regsetvalue",
        ),
    ),
    (
        "network_c2",
        "command-and-control",
        "T1071.001",
        (
            "internetopen",
            "internetconnect",
            "httpsendrequest",
            "httpopenrequest",
            "winhttpopen",
            "winhttpconnect",
            "urlmondownload",
            "wsastartup",
            "wsasend",
            "sendto",
            "connect",
            "getaddrinfo",
            "winhttpsetoption",
        ),
    ),
    (
        "credential_access",
        "credential-access",
        "T1555",
        ("credread", "cryptunprotectdata", "credreadw", "logonuser", "sspi"),
    ),
    (
        "input_capture",
        "collection",
        "T1056.001",
        ("setwindowshookex", "getasynckeystate", "getkeystate", "callnexthookex"),
    ),
    (
        "screen_capture",
        "collection",
        "T1113",
        ("bitblt", "getdc", "getdibits", "printwindow", "copyfromscreen", "createcompatiblebitmap"),
    ),
    (
        "anti_analysis",
        "defense-evasion",
        "T1497.001",
        (
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "outputdebugstringa",
            "ntqueryinformationprocess",
            "gettickcount",
        ),
    ),
    (
        "service_control",
        "persistence",
        "T1543.003",
        ("createservicea", "createservicew", "startservicectrl", "controlservice", "openservice"),
    ),
    (
        "lateral_movement",
        "lateral-movement",
        "T1021.002",
        ("wnetaddconnection", "netshareenum", "netsharegetinfo", "rpcbind"),
    ),
    ("cryptography", None, None, ("cryptderivekey", "cryptdecrypt", "cryptencrypt", "bcryptgenkey", "cryptimportkey")),
    (
        "file_io",
        None,
        None,
        ("createfilea", "createfilew", "readfile", "writefile", "findfirstfile", "copyfilea", "setfilepointer"),
    ),
)


def group_imports(imports: Iterable[str]) -> Dict[str, List[str]]:
    """Cluster ``"dll:function"`` import strings into capability groups.

    Pure function over what M2 already publishes, so M4 and M5 can group imports
    without parsing the PE themselves. Ordinal imports (``dll:ord12``) are skipped:
    without a name there is no capability to claim.
    """
    groups: Dict[str, List[str]] = {}
    for entry in imports:
        dll, _, function = str(entry).partition(":")
        if not function or function.startswith("ord"):
            continue
        lowered = function.lower()
        for name, _tactic, _attack, needles in IMPORT_CAPABILITY_GROUPS:
            if any(needle in lowered for needle in needles):
                groups.setdefault(name, [])
                label = f"{dll}:{function}"
                if label not in groups[name]:
                    groups[name].append(label)
    return {name: sorted(members) for name, members in sorted(groups.items())}


def capability_meta(group: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(tactic, attack_id)`` for a group name; ``(None, None)`` if descriptive only."""
    for name, tactic, attack, _needles in IMPORT_CAPABILITY_GROUPS:
        if name == group:
            return tactic, attack
    return None, None


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------


def _section_name(section: pefile.SectionStructure) -> str:
    try:
        return section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip() or "<unnamed>"
    except Exception:
        return "<unknown>"


def _permission_mnemonic(characteristics: int) -> str:
    return "".join(
        (
            "R" if characteristics & IMAGE_SCN_MEM_READ else "-",
            "W" if characteristics & IMAGE_SCN_MEM_WRITE else "-",
            "X" if characteristics & IMAGE_SCN_MEM_EXECUTE else "-",
        )
    )


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def _find_section(pe: pefile.PE, rva: int) -> Optional[pefile.SectionStructure]:
    for section in pe.sections:
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < start + size:
            return section
    return None


# ---------------------------------------------------------------------------
# The evidence object
# ---------------------------------------------------------------------------


class PeEvidence:
    """Everything M2's PE reader can say about one image."""

    def __init__(self, parsed: bool = False) -> None:
        self.parsed = parsed
        self.findings: List[Finding] = []
        self.import_groups: Dict[str, List[str]] = {}
        self.overlay_size = 0
        self.resource_entries = 0
        self.resource_bytes = 0
        self.largest_executable_entropy = 0.0
        self.packers: List[str] = []

    # -- finding helpers ---------------------------------------------------

    def add(self, code: str, detail: str, **values: Any) -> None:
        self.findings.append(Finding.build(code, detail, **values))

    @property
    def finding_codes(self) -> List[str]:
        return [finding["code"] for finding in self.findings]

    def has(self, code: str) -> bool:
        return any(finding["code"] == code for finding in self.findings)

    def findings_payload(self) -> List[Dict[str, Any]]:
        return [{"code": f["code"], "detail": f["detail"], "values": f["values"]} for f in self.findings]

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"PeEvidence(parsed={self.parsed}, codes={self.finding_codes}, packers={self.packers})"


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_sections(pe: pefile.PE, ev: PeEvidence) -> None:
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment or 1
    sections = list(pe.sections)

    for section in sections:
        name = _section_name(section)
        chars = int(section.Characteristics)
        writable = bool(chars & IMAGE_SCN_MEM_WRITE)
        executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        perms = _permission_mnemonic(chars)

        if writable and executable:
            ev.add(
                "SECTION_RWX",
                f"Section {name} is writable and executable ({perms}, 0x{chars:08X}); "
                "code can be rewritten in place at runtime",
                section=name,
                permissions=perms,
                characteristics=chars,
            )

        try:
            entropy = round(section.get_entropy(), 4)
        except Exception:
            entropy = 0.0
        if executable and entropy >= SECTION_HIGH_ENTROPY:
            ev.add(
                "EXECUTABLE_SECTION_HIGH_ENTROPY",
                f"Executable section {name} has entropy {entropy:.2f}; code that is not "
                "plaintext is normally packed, encrypted, or stub-decrypted at runtime",
                section=name,
                entropy=entropy,
                permissions=perms,
            )
        ev.largest_executable_entropy = max(
            ev.largest_executable_entropy, entropy if executable else 0.0
        )

        if section.Misc_VirtualSize and section.SizeOfRawData > _align(
            section.Misc_VirtualSize, file_alignment
        ):
            ev.add(
                "SECTION_RAW_LARGER_THAN_VSIZE",
                f"Section {name} declares {section.SizeOfRawData} raw bytes for a "
                f"{section.Misc_VirtualSize}-byte virtual size",
                section=name,
                raw_size=int(section.SizeOfRawData),
                virtual_size=int(section.Misc_VirtualSize),
            )

        if name and name.lower() not in _STANDARD_NAMES and executable:
            ev.add(
                "NONSTANDARD_EXECUTABLE_SECTION",
                f"Section {name} is executable but is not a linker-emitted name",
                section=name,
                permissions=perms,
            )

    # Layout: raw data ranges that overlap each other or run past the file.
    ranges = [
        (int(s.PointerToRawData), int(s.PointerToRawData) + int(s.SizeOfRawData), _section_name(s))
        for s in sections
        if s.SizeOfRawData
    ]
    ranges.sort()
    for (start_a, end_a, name_a), (start_b, end_b, name_b) in zip(ranges, ranges[1:]):
        if start_b < end_a:
            ev.add(
                "SECTION_RAW_OVERLAP",
                f"Sections {name_a} and {name_b} claim overlapping raw byte ranges "
                f"[{start_a:#x},{end_a:#x}) and [{start_b:#x},{end_b:#x})",
                first=name_a,
                second=name_b,
            )

    if len(sections) > 8:
        ev.add(
            "SECTION_COUNT_HIGH",
            f"Image declares {len(sections)} sections, which is more than a normal "
            "linker run produces",
            count=len(sections),
        )


def _check_entry_point(pe: pefile.PE, ev: PeEvidence) -> None:
    entry = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if not entry:
        # A DLL with no entry point is normal; an EXE without one is not.
        if not (pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL):
            ev.add("ENTRYPOINT_MISSING", "Executable image declares no entry point", entry_point=0)
        return

    host = _find_section(pe, entry)
    if host is None:
        ev.add(
            "ENTRYPOINT_OUTSIDE_SECTIONS",
            f"Entry point RVA {entry:#x} does not fall inside any declared section",
            entry_point=entry,
        )
        return

    name = _section_name(host)
    chars = int(host.Characteristics)
    if chars & IMAGE_SCN_MEM_WRITE:
        ev.add(
            "ENTRYPOINT_IN_WRITABLE_SECTION",
            f"Entry point RVA {entry:#x} lands in writable section {name}; the first "
            "instructions executed are attacker-writable memory",
            entry_point=entry,
            section=name,
            permissions=_permission_mnemonic(chars),
        )
    if name.lower() in (".data", ".rsrc", ".rdata"):
        ev.add(
            "ENTRYPOINT_IN_DATA_SECTION",
            f"Entry point RVA {entry:#x} is in {name} rather than a code section",
            entry_point=entry,
            section=name,
        )


def _check_image(pe: pefile.PE, ev: PeEvidence, data: bytes) -> None:
    opt = pe.OPTIONAL_HEADER
    dll_chars = int(opt.DllCharacteristics)
    is_dll = bool(pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL)

    raw_ranges = [
        int(s.PointerToRawData) + int(s.SizeOfRawData) for s in pe.sections if s.SizeOfRawData
    ]
    if raw_ranges:
        end_of_sections = max(max(raw_ranges), opt.SizeOfHeaders)
        ev.overlay_size = max(0, len(data) - end_of_sections)
        if ev.overlay_size >= MIN_NOTABLE_OVERLAY:
            ev.add(
                "OVERLAY_DATA",
                f"{ev.overlay_size} bytes follow the last section's raw data "
                f"(file size {len(data)}, section end {end_of_sections:#x}); data appended past "
                "the image is where a dropper hides its payload",
                overlay_size=ev.overlay_size,
                file_size=len(data),
            )

    if not (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE):
        ev.add(
            "NO_ASLR",
            "DllCharacteristics does not set DYNAMIC_BASE, so the image loads at a fixed base",
            dll_characteristics=dll_chars,
        )
    if not (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT):
        ev.add(
            "NO_NX_COMPAT",
            "DllCharacteristics does not set NX_COMPAT, so the image opts into "
            "executable stack pages",
            dll_characteristics=dll_chars,
        )

    relocs = opt.DATA_DIRECTORY[DIR_BASERELOC]
    if is_dll and not (relocs.VirtualAddress and relocs.Size):
        ev.add(
            "DLL_WITHOUT_RELOCATIONS",
            "DLL declares no base-relocation directory, so it cannot rebase",
            is_dll=True,
        )

    imports = opt.DATA_DIRECTORY[DIR_IMPORT]
    if not (imports.VirtualAddress and imports.Size):
        ev.add(
            "NO_IMPORT_DIRECTORY",
            "Image has no import directory; a hand-built or import-stomped binary "
            "resolves its APIs dynamically",
            import_directory_size=int(imports.Size),
        )


def _check_resources(pe: pefile.PE, ev: PeEvidence) -> None:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[DIR_RESOURCE]
    if not (directory.VirtualAddress and directory.Size):
        return
    ev.resource_bytes = int(directory.Size)

    def walk(node: Any, depth: int) -> None:
        for entry in getattr(node, "entries", []) or []:
            ev.resource_entries += 1
            if depth < 2:
                walk(entry, depth + 1)

    try:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE:
            walk(entry, 0)
    except Exception:
        # A resource tree pefile cannot walk is itself the finding.
        ev.add(
            "RESOURCE_TREE_UNREADABLE",
            f"Resource directory declares {directory.Size} bytes but the tree will not parse",
            resource_bytes=ev.resource_bytes,
        )
        return

    if not ev.resource_entries:
        ev.add(
            "EMPTY_RESOURCE_DIRECTORY",
            f"Resource directory declares {directory.Size} bytes but lists no entries",
            resource_bytes=ev.resource_bytes,
        )


def _check_imports(pe: pefile.PE, ev: PeEvidence) -> None:
    imports: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        try:
            dll = entry.dll.decode("utf-8", errors="replace").lower()
        except Exception:
            dll = "<unknown>"
        for imp in entry.imports:
            if imp.name:
                imports.append(f"{dll}:{imp.name.decode('utf-8', errors='replace')}")
    ev.import_groups = group_imports(imports)

    # A short import table only means something next to a body that cannot be read
    # as compiler output: on its own it is what a small static-linked tool looks like.
    obfuscated_body = (
        ev.largest_executable_entropy >= SECTION_ELEVATED_ENTROPY or ev.overlay_size >= MIN_NOTABLE_OVERLAY
    )
    if imports and len(imports) <= 5 and obfuscated_body:
        companion = (
            f"executable-section entropy {ev.largest_executable_entropy:.2f}"
            if ev.largest_executable_entropy >= SECTION_ELEVATED_ENTROPY
            else f"{ev.overlay_size} appended bytes"
        )
        ev.add(
            "IMPORT_COUNT_MINIMAL",
            f"Only {len(imports)} named imports alongside {companion}; the rest of the "
            "API surface is resolved at runtime",
            import_count=len(imports),
        )


# ---------------------------------------------------------------------------
# Packer indicators
# ---------------------------------------------------------------------------


def _named_tools_from_sections(pe: pefile.PE) -> List[Tuple[str, str]]:
    """(tool, evidence) for every packer/protector section name in the image."""
    found: List[Tuple[str, str]] = []
    for section in pe.sections:
        name = _section_name(section)
        tool = _PACKER_SECTION_NAMES.get(name.upper())
        if tool:
            found.append((tool, f"section:{name}"))
    return found


def _named_tools_from_bytes(data: bytes) -> List[Tuple[str, str]]:
    """(tool, evidence) for container banners that survive without a parsed header.

    Non-Windows callers get this path too: an archive or an ISO holding a packed
    binary still carries the banner.
    """
    return [
        (tool, f"banner:{signature.decode('ascii', errors='replace')[:32]}")
        for signature, tool in _PACKER_BYTE_SIGNATURES.items()
        if signature in data
    ]


def _record_tool_findings(ev: PeEvidence, named_tools: Iterable[Tuple[str, str]], indicators: List[str]) -> None:
    for tool, evidence in named_tools:
        token = f"tool:{tool}"
        if token not in indicators:
            indicators.append(token)
        ev.add(
            "PACKER_TOOL_SIGNATURE",
            f"Signature of the packer/protector {tool} ({evidence})",
            tool=tool,
            evidence=evidence,
        )


def _collect_packers(pe: Optional[pefile.PE], data: bytes, ev: PeEvidence) -> List[str]:
    """Named tools and behavioural packing signs, each one traceable to a byte.

    The tokens are what M2 publishes into ``static.packers``. They are deliberately
    self-describing (``tool:<name>``, ``sign:<code>``) so a reader can tell a
    signature match from a heuristic without opening the code.

    A tool name is only ever emitted from a string the tool itself writes. An
    unnamed high-entropy section is reported as ``sign:executable_section_high_entropy``
    and never attributed to a product, because naming one would be a guess about
    provenance rather than a reading of the bytes.
    """
    indicators: List[str] = []

    named: List[Tuple[str, str]] = []
    if pe is not None:
        named = _named_tools_from_sections(pe)
        for tool, evidence in _named_tools_from_bytes(data):
            if (tool, evidence) not in named:
                named.append((tool, evidence))

        if not named:
            # No known tool wrote these names, but they are not linker names either.
            for section in pe.sections:
                name = _section_name(section)
                if name and not name.startswith(".") and name.upper() not in _PACKER_SECTION_NAMES:
                    token = f"anomalous_section:{name}"
                    if token not in indicators:
                        indicators.append(token)

    _record_tool_findings(ev, named, indicators)

    for code, token in (
        ("EXECUTABLE_SECTION_HIGH_ENTROPY", "sign:executable_section_high_entropy"),
        ("NO_IMPORT_DIRECTORY", "sign:no_import_directory"),
        ("ENTRYPOINT_OUTSIDE_SECTIONS", "sign:entrypoint_outside_sections"),
        ("ENTRYPOINT_IN_WRITABLE_SECTION", "sign:entrypoint_in_writable_section"),
        ("OVERLAY_DATA", "sign:overlay_data"),
    ):
        if ev.has(code):
            indicators.append(token)

    return indicators


def container_indicators(data: bytes, evidence: Optional[PeEvidence] = None) -> List[str]:
    """Packer banners found in bytes that are not a parseable PE image.

    M2 calls this for archives, scripts and document containers, where there is no
    header to read but a banner still identifies a tool inside the payload.
    """
    ev = evidence if evidence is not None else PeEvidence()
    indicators: List[str] = []
    _record_tool_findings(ev, _named_tools_from_bytes(data), indicators)
    return indicators


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def collect_pe_evidence(data: bytes, pe: Optional[pefile.PE] = None) -> PeEvidence:
    """Read structural evidence out of a PE image without running it.

    ``pe`` lets a caller that already parsed the image (M2) avoid a second parse.
    When it is omitted the header is parsed with ``fast_load=True``, which reads
    section headers only: no relocations, no bound imports, nothing that touches
    the sample's own code.

    An unreadable image returns ``PeEvidence(parsed=False)`` rather than raising:
    "could not read" is a different statement from "read it and found nothing", and
    callers must be able to tell the two apart.
    """
    ev = PeEvidence()
    if not data[:2] == b"MZ":
        return ev

    owns_pe = pe is None
    if owns_pe:
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except Exception:
            return ev
    try:
        ev.parsed = True
        _check_sections(pe, ev)
        _check_entry_point(pe, ev)
        _check_image(pe, ev, data)
        _check_resources(pe, ev)
        _check_imports(pe, ev)
        ev.packers = _collect_packers(pe, data, ev)
    except Exception:
        # A half-read header still yields the findings collected so far.
        return ev
    finally:
        if owns_pe and pe is not None:
            try:
                pe.close()
            except Exception:
                pass
    return ev


def describe(ev: PeEvidence) -> Sequence[str]:
    """One sentence per finding, for a detection description or an explanation line."""
    return tuple(finding["detail"] for finding in ev.findings)
