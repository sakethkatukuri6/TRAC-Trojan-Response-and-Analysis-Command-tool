"""Deterministic benign PE fixture used to prove the real M2 parsing path.

The image is assembled here from raw header bytes: it is never downloaded,
never written to disk by the vault under test, and never executed. It is a
structurally valid PE32+ console-free executable with two sections and two
imported DLLs, which is enough to show that ``m2_static.analyzer`` parses real
headers, sections, import descriptors and the import hash rather than emitting
canned values.
"""
from __future__ import annotations

import struct
from typing import Dict, List, Tuple

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
SIZE_OF_HEADERS = 0x400
IMAGE_BASE = 0x140000000
TIME_DATE_STAMP = 0x5F1124B3
IMAGE_DIRECTORY_ENTRY_IMPORT = 1

# (dll, imported function names) as they will appear in the import directory.
IMPORTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("kernel32.dll", ("ExitProcess", "GetVersion")),
    ("user32.dll", ("MessageBoxA",)),
)

IMPORT_DESCRIPTOR_SIZE = 20


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _build_rdata() -> bytes:
    """Lay out import descriptors, DLL names, ILTs, IATs and import-by-names."""
    descriptors_length = IMPORT_DESCRIPTOR_SIZE * (len(IMPORTS) + 1)
    offset = descriptors_length

    dll_names: Dict[str, int] = {}
    for dll, _functions in IMPORTS:
        dll_names[dll] = RDATA_RVA + offset
        offset += len(dll) + 1
    offset = align(offset, 8)

    ilts: Dict[str, int] = {}
    for dll, functions in IMPORTS:
        ilts[dll] = RDATA_RVA + offset
        offset += 8 * (len(functions) + 1)

    iats: Dict[str, int] = {}
    for dll, functions in IMPORTS:
        iats[dll] = RDATA_RVA + offset
        offset += 8 * (len(functions) + 1)

    thunks: List[List[int]] = []
    for _dll, functions in IMPORTS:
        entries = []
        for function in functions:
            entries.append(RDATA_RVA + offset)
            offset += align(2 + len(function) + 1, 2)
        thunks.append(entries)

    image = bytearray(offset)

    def put(relative: int, fmt: str, *values: object) -> None:
        struct.pack_into("<" + fmt, image, relative, *values)

    for index, ((dll, functions), entries) in enumerate(zip(IMPORTS, thunks)):
        base = IMPORT_DESCRIPTOR_SIZE * index
        put(base, "IIIII", ilts[dll], 0, 0, dll_names[dll], iats[dll])

        name_start = dll_names[dll] - RDATA_RVA
        image[name_start:name_start + len(dll) + 1] = dll.encode("ascii") + b"\x00"

        for position, function in enumerate(functions):
            thunk_rva = entries[position]
            put(iats[dll] - RDATA_RVA + 8 * position, "Q", thunk_rva)
            put(ilts[dll] - RDATA_RVA + 8 * position, "Q", thunk_rva)
            by_name = thunk_rva - RDATA_RVA
            put(by_name, "H", 0)
            raw = function.encode("ascii") + b"\x00"
            image[by_name + 2:by_name + 2 + len(raw)] = raw

    return bytes(image)


def build_benign_pe() -> bytes:
    """Return the bytes of a minimal, deterministic, benign PE32+ image."""
    text = b"\xC3" + b"\x90" * 15
    rdata = _build_rdata()

    text_raw = align(len(text), FILE_ALIGNMENT)
    rdata_raw = align(len(rdata), FILE_ALIGNMENT)
    text_pointer = SIZE_OF_HEADERS
    rdata_pointer = text_pointer + text_raw
    size_of_image = align(RDATA_RVA + len(rdata), SECTION_ALIGNMENT)
    import_length = IMPORT_DESCRIPTOR_SIZE * (len(IMPORTS) + 1)

    dos = bytearray(b"MZ" + b"\x00" * 62)
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack("<HHIIIHH", 0x8664, 2, TIME_DATE_STAMP, 0, 0, 240, 0x0022)

    optional = struct.pack(
        "<" + "H" + "BB" + "I" * 5 + "Q" + "I" * 2 + "H" * 6 + "I" * 4
        + "H" * 2 + "Q" * 4 + "I" * 2,
        0x20B, 14, 0,
        text_raw, len(rdata), 0, TEXT_RVA, TEXT_RVA,
        IMAGE_BASE,
        SECTION_ALIGNMENT, FILE_ALIGNMENT,
        6, 0, 1, 0, 6, 0,
        0, size_of_image, SIZE_OF_HEADERS, 0,
        2, 0x0140,
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    )
    for index in range(16):
        entry = (RDATA_RVA, import_length) if index == IMAGE_DIRECTORY_ENTRY_IMPORT else (0, 0)
        optional += struct.pack("<II", *entry)

    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional
        + struct.pack("<8sIIIIIIHHI", b".text", len(text), TEXT_RVA, text_raw,
                      text_pointer, 0, 0, 0, 0, 0x60000020)
        + struct.pack("<8sIIIIIIHHI", b".rdata", len(rdata), RDATA_RVA, rdata_raw,
                      rdata_pointer, 0, 0, 0, 0, 0x40000040)
    )

    image = bytearray(headers.ljust(SIZE_OF_HEADERS, b"\x00"))
    image += text.ljust(text_raw, b"\x00")
    image += rdata.ljust(rdata_raw, b"\x00")
    return bytes(image)


def expected_imports() -> List[str]:
    """The ``dll:function`` strings M2 must recover from this fixture."""
    return [f"{dll}:{function}" for dll, functions in IMPORTS for function in functions]
