# Analysis Platform Contract v1.0.0

The single source of truth that lets four people build eight modules in parallel.

```
contract/
  schemas/analysis_result.schema.json   shared result document (JSON Schema 2020-12)
  schemas/events.schema.json            queue message envelope + per-event payloads
  pipeline/state_machine.yaml           states, transitions, retries, section ownership
  api/openapi.yaml                      M7 REST API (mock against this first)
  examples/valid_*.json                 fixtures that must pass
  examples/invalid_*.json               fixtures that must fail (schema or semantic)
  tools/validate.py                     schema + semantic + ownership + event-flow checks
  tests/test_contract.py                unittest suite
```

## Section ownership

| Section | Writer | Event emitted |
|---|---|---|
| sample | M1 | sample.received |
| static | M2 | static.done |
| dynamic | M3 | dynamic.done |
| iocs | M4 | iocs.done |
| detections, score, verdict | M5 | scoring.done |
| response_actions | M6 | response.done |
| pipeline | M7 only | done |

Report generation (M8) emits `report.done`. M7 is the only module that writes to the database.

## Rules enforced

Schema level:
- No file paths anywhere; samples are addressed by `vault_id`. Unknown fields are rejected.
- Sanitized filenames, 100 MiB size cap, SHA-256/MD5 format, ATT&CK ID format.
- Sandbox network mode is `isolated` or `simulated_internet` only.
- `pipeline.status = complete` requires every section; `suspicious/malicious` requires a score.
- Real-mode `quarantine`, `isolate_host`, `block_ip`, `block_domain` require approval; `executed` actions require `executed_at` and `audit_ref`.

Semantic level (`validate.py`):
- IOC domains, IPs, URLs and embedded URLs must be defanged.
- Score components must sum to the score (±1); `malicious` needs score >= 60, `benign` <= 30.
- A finished sandbox run must have reverted its snapshot.
- Modules may only write sections they own; events must follow the state machine.

## Quick start (Windows PowerShell)

Run every command from the repository root in Windows PowerShell.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If PowerShell blocks the activated scripts, run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, or call
`.\.venv\Scripts\python.exe` directly as shown above.

`requirements.txt` is the single tracked dependency file for the MVP. It installs
everything M1-M8 import (pefile, pyzipper, cryptography, SQLAlchemy, alembic,
FastAPI, Uvicorn, python-multipart, pydantic, python-jose, passlib, httpx, stix2,
reportlab, pypdf, jsonschema, PyYAML) plus `pytest` and `pytest-asyncio`. The
per-module `requirements.txt` files remain as module-local records; you do not
need them to run the platform.

## Run the analyst console (M8 over M7)

```powershell
.\.venv\Scripts\python.exe -m m8_ui_devops.cli --serve-ui --port 8088 --open-browser
```

The console is served at `http://127.0.0.1:8088`. Upload from the page, or:

```powershell
curl.exe -F "file=@C:\samples\sample.zip" http://127.0.0.1:8088/api/samples/upload
curl.exe -F "file=@C:\samples\sample.zip" -F "archive_password=infected" http://127.0.0.1:8088/api/samples/upload
```

- MalwareBazaar archives are protected with `infected`, which is the default.
- Archive payloads are extracted **in memory only**. The submission is rejected
  before anything is ingested when the archive has no file entry, an unsafe
  member name (`..\evil.exe`, `/etc/x`, `C:\x`), more than one executable
  candidate, an undecryptable payload, or a payload larger than 100 MiB after
  extraction. The console answers `400` with the rejection code, or `413` for
  `PAYLOAD_TOO_LARGE`.
- Only benign material belongs on a workstation. Use the EICAR test string or a
  generated benign PE fixture; never analyse live malware on the developer host.
- The dynamic stage reports `Sandbox not configured` unless `TRAC_CAPE_URL` is
  pointed at an isolated CAPEv2 lab. Nothing runtime is displayed until the
  sandbox actually returns telemetry.

## Run the M7 REST API (optional)

```powershell
$env:MODULE_SECRET = "<32+ byte secret>"   $env:USER_SECRET = "<32+ byte secret>"
.\.venv\Scripts\python.exe -m uvicorn m7_core.api.app:app --host 127.0.0.1 --port 8000
```

Interactive OpenAPI documentation is at `http://127.0.0.1:8000/docs`. M7 is the
only module that writes the database.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | M7 database URI | `sqlite:///./trac_dev.db` |
| `VAULT_STORAGE_PATH` | Directory holding encrypted, defanged samples | `m1_ingestion/data/vault` |
| `VAULT_ENCRYPTION_KEY` | Fernet key for the vault | generated into `vault.key` |
| `TRAC_CAPE_URL` | CAPEv2 base URL; unset means the sandbox is skipped | unset |
| `TRAC_CAPE_TOKEN` | Bearer token for CAPEv2 | unset |
| `MODULE_SECRET`, `USER_SECRET` | M7 API JWT signing keys | `.secrets` file (refused in production) |
| `TRAC_ENV`, `REQUIRE_DEPLOYMENT_SECRETS` | Fail closed unless secrets are provisioned | unset |

`run.bat` wraps these commands in an interactive menu (`run.bat gate`,
`run.bat contract-test`, `run.bat ui`, `run.bat server`).

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest m1_ingestion\tests m3_dynamic\tests m4_ioc\tests m5_detection\tests m6_response\tests m7_core\tests m8_ui_devops\tests -q
.\.venv\Scripts\python.exe -m unittest discover -s contract\tests -v
.\.venv\Scripts\python.exe contract\tools\check_all.py --repo-root .
```

On a clean install of `requirements.txt` the expected results are `153 passed`,
`Ran 21 tests ... OK`, and `ok` for M1 through M8. The module suite includes
`m7_core/tests/test_real_pe_static.py`, which parses a generated benign PE32+
image (never executed) to prove the real `pefile` path, and
`m7_core/tests/test_zip_intake.py`, which covers the archive rejection rules.

## Changing the contract
Additive changes bump the minor version (1.1.0); breaking changes need a major bump and agreement from all four owners. Update fixtures and tests in the same PR.

## Contract tooling

From the `contract/` directory:

```powershell
cd contract
..\.venv\Scripts\python.exe -m unittest discover -s tests -v
..\.venv\Scripts\python.exe tools\validate.py examples\valid_synthetic_trojan_record.json
cd ..
```

## Fixtures
All data is synthetic: documentation-range IPs (192.0.2.0/24), `.example` domains, and the standard EICAR test file hashes. No real malware is included.
