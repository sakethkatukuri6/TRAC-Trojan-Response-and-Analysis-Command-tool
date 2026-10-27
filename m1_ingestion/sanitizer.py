"""Filename sanitization for M1 Ingestion.

Rules enforced:
- Maximum 255 characters.
- Must match pattern: ^[A-Za-z0-9._ -]+$
- Strips any path separators (preventing directory traversal).
- Removes control characters and disallowed symbols.
"""
from __future__ import annotations

import os
import re

ALLOWED_PATTERN = re.compile(r"^[A-Za-z0-9._ -]+$")
DISALLOWED_CHARS = re.compile(r"[^A-Za-z0-9._ -]")


def sanitize_filename(filename: str, fallback: str = "sample.bin") -> str:
    """Sanitize original filename to comply with contract schema.

    - Strips directory components (both Unix and Windows separators).
    - Replaces disallowed characters with underscores.
    - Truncates to max 255 characters while preserving file extension if possible.
    """
    if not filename or not isinstance(filename, str):
        return fallback

    # Strip directory components regardless of OS
    base = re.split(r"[\\/]", filename.strip())[-1]
    # Remove leading dots or slashes that might hide the file or attempt traversal
    base = base.lstrip(". ").rstrip(". ")

    if not base:
        return fallback

    # Replace disallowed chars with underscore
    cleaned = DISALLOWED_CHARS.sub("_", base)

    # Collapse multiple consecutive underscores
    cleaned = re.sub(r"_+", "_", cleaned)

    # Max length: 255
    if len(cleaned) > 255:
        # Try to preserve extension
        parts = cleaned.rsplit(".", 1)
        if len(parts) == 2 and len(parts[1]) < 20:
            ext = "." + parts[1]
            max_stem = 255 - len(ext)
            cleaned = parts[0][:max_stem] + ext
        else:
            cleaned = cleaned[:255]

    if not cleaned or not ALLOWED_PATTERN.match(cleaned):
        return fallback

    return cleaned

