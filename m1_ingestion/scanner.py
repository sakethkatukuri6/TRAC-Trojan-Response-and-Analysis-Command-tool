"""First-pass AV scanner for M1 Ingestion (ClamAV / EICAR signature check).

Returns one of: ["clean", "detected", "error", "not_run"]
"""
from __future__ import annotations

import shutil
import subprocess

EICAR_SIG = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def scan_sample(data: bytes) -> str:
    """Run first-pass AV scan against raw bytes.

    - Checks for EICAR test signature directly.
    - If `clamscan` is available in system PATH, streams bytes to its stdin.
    - Otherwise returns 'not_run' (or 'detected' if EICAR).
    """
    if EICAR_SIG in data:
        return "detected"

    clamscan_path = shutil.which("clamscan")
    if not clamscan_path:
        return "not_run"

    try:
        proc = subprocess.run(
            [clamscan_path, "--no-summary", "-"],
            input=data,
            capture_output=True,
            timeout=10,
        )
        # Clamscan return codes: 0 = clean, 1 = virus found, 2 = error
        if proc.returncode == 0:
            return "clean"
        if proc.returncode == 1:
            return "detected"
        return "error"
    except Exception:
        return "error"

