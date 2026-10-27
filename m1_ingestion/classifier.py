"""File type classification and MIME detection for M1 Ingestion.

Classifies sample into contract-specified enum:
["pe", "elf", "macho", "office", "pdf", "script", "archive", "other"]
"""
from __future__ import annotations

import mimetypes
from typing import Tuple

MACHO_MAGICS = (
    b"\xfe\xed\xfa\xce",  # MH_MAGIC 32-bit
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 64-bit
    b"\xce\xfa\xed\xfe",  # MH_CIGAM 32-bit
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 64-bit
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
)

SCRIPT_EXTENSIONS = {
    ".ps1", ".bat", ".cmd", ".sh", ".bash", ".vbs", ".js", ".py", ".rb", ".pl", ".php", ".hta"
}


def classify_file(data: bytes, filename: str = "") -> Tuple[str, str]:
    """Classify raw bytes into contract file_type enum and MIME string.

    Returns:
        (file_type, mime_type)
    """
    if not data:
        return "other", "application/octet-stream"

    lower_name = filename.lower()

    # 1. PE (Windows Executable / DLL)
    if data.startswith(b"MZ"):
        return "pe", "application/x-dosexec"

    # 2. ELF (Linux Executable)
    if data.startswith(b"\x7fELF"):
        return "elf", "application/x-executable"

    # 3. Mach-O (macOS Executable / Universal Binary)
    if any(data.startswith(magic) for magic in MACHO_MAGICS):
        return "macho", "application/x-mach-binary"

    # 4. PDF
    if data.startswith(b"%PDF-"):
        return "pdf", "application/pdf"

    # 5. Office (Legacy OLE / Compound Document)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "office", "application/x-ole-storage"

    # 6. Archive / Zip-based Office
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        # Check if it's an Office document (DOCX, XLSX, PPTX)
        probe = data[:2048]
        if b"[Content_Types].xml" in probe or b"word/" in probe or b"xl/" in probe or b"ppt/" in probe:
            return "office", "application/vnd.openxmlformats-officedocument"
        return "archive", "application/zip"

    # Other Archive types
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "archive", "application/x-7z-compressed"
    if data.startswith(b"Rar!\x1a\x07"):
        return "archive", "application/vnd.rar"
    if data.startswith(b"\x1f\x8b"):
        return "archive", "application/gzip"
    if data.startswith(b"BZh"):
        return "archive", "application/x-bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "archive", "application/x-xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "archive", "application/x-tar"

    # 7. Script
    if data.startswith(b"#!"):
        return "script", "text/x-shellscript"

    ext = "." + lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
    if ext in SCRIPT_EXTENSIONS:
        return "script", mimetypes.guess_type(lower_name)[0] or "text/plain"

    # Check for text scripts
    if b"<script" in data[:512].lower() or b"wscript" in data[:512].lower():
        return "script", "text/plain"

    # Default to 'other'
    guessed_mime, _ = mimetypes.guess_type(lower_name) if filename else (None, None)
    return "other", guessed_mime or "application/octet-stream"

