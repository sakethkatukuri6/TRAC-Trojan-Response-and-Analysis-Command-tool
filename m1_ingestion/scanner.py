"""First-pass AV scanner for M1 Ingestion (ClamAV / EICAR signature check).

Returns one of: ["clean", "detected", "error", "not_run"]
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile

EICAR_SIG = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def scan_sample(data: bytes) -> str:
    """Run first-pass AV scan against raw bytes.

    - Checks for EICAR test signature directly.
    - If `clamscan` is available in system PATH, invokes it on a temporary file.
    - Otherwise returns 'not_run' (or 'detected' if EICAR).
    """
    if EICAR_SIG in data:
        return "detected"

    clamscan_path = shutil.which("clamscan")
    if not clamscan_path:
        return "not_run"

    try:
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            proc = subprocess.run(
                [clamscan_path, "--no-summary", tmp.name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # Clamscan return codes: 0 = clean, 1 = virus found, 2 = error
            if proc.returncode == 0:
                return "clean"
            elif proc.returncode == 1:
                return "detected"
            else:
                return "error"
    except Exception:
        return "error"

