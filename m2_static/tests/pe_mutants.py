"""Byte-level mutations of the benign PE fixture, so each check has its own trigger.

Everything here edits header fields of the image built by
``m7_core.tests.benign_pe.build_benign_pe``. The result is never executed and never
written to disk: a parser reads bytes, and the test proves which byte raised which
finding. No real malware is stored in this repository.
"""
from __future__ import annotations

import struct

from m7_core.tests.benign_pe import build_benign_pe

# DOS header (64) + "PE\0\0" (4) + COFF record (20) + optional header (240).
SECTION_HEADER_OFFSET = 64 + 4 + 20 + 240
SECTION_HEADER_SIZE = 40
CHARACTERISTICS_FIELD = 36
NAME_FIELD = 0

EXECUTE = 0x20000000
READ = 0x40000000
WRITE = 0x80000000
CODE = 0x00000020
INITIALIZED_DATA = 0x00000040

# DllCharacteristics sits in the optional header after the 17 pre-directory fields.
DLL_CHARACTERISTICS_OFFSET = 64 + 4 + 20 + 70


def benign_pe() -> bytes:
    return build_benign_pe()


def _patch(image: bytes, offset: int, raw: bytes) -> bytes:
    data = bytearray(image)
    data[offset:offset + len(raw)] = raw
    return bytes(data)


def set_section_flags(image: bytes, index: int, characteristics: int) -> bytes:
    """Rewrite one section's characteristics, leaving the rest of the image alone."""
    return _patch(image,
                  SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE * index + CHARACTERISTICS_FIELD,
                  struct.pack("<I", characteristics))


def rename_section(image: bytes, index: int, name: str) -> bytes:
    return _patch(image, SECTION_HEADER_OFFSET + SECTION_HEADER_SIZE * index + NAME_FIELD,
                  name.encode("ascii")[:8].ljust(8, b"\x00"))


def set_entry_point(image: bytes, rva: int) -> bytes:
    """AddressOfEntryPoint is the 5th optional-header field (offset 16 within it)."""
    return _patch(image, 64 + 4 + 20 + 16, struct.pack("<I", rva))


def set_dll_characteristics(image: bytes, flags: int) -> bytes:
    return _patch(image, DLL_CHARACTERISTICS_OFFSET, struct.pack("<H", flags))


def append_overlay(image: bytes, payload: bytes) -> bytes:
    """Bytes past the last section's raw data: the space a dropper hides its payload in."""
    return image + payload


def overlay_payload(size: int = 4096, seed: int = 0x5A) -> bytes:
    """Deterministic, incompressible-looking filler (so entropy checks fire without randomness)."""
    return bytes(((seed + index * 7919) % 251) ^ ((index * 104729) % 253)
                 for index in range(size))
