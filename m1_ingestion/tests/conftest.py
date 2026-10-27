import os
import sys
from pathlib import Path

# Ensure repo root and contract tools are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONTRACT_TOOLS = REPO_ROOT / "contract" / "tools"

for p in (str(REPO_ROOT), str(CONTRACT_TOOLS)):
    if p not in sys.path:
        sys.path.insert(0, p)

