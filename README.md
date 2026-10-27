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

## Run

```
pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/validate.py examples/valid_synthetic_trojan_record.json
```

## Changing the contract
Additive changes bump the minor version (1.1.0); breaking changes need a major bump and agreement from all four owners. Update fixtures and tests in the same PR.

## Fixtures
All data is synthetic: documentation-range IPs (192.0.2.0/24), `.example` domains, and the standard EICAR test file hashes. No real malware is included.
