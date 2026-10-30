# TRAC MVP handoff for Qoder

## Current state

- Working branch: `m6-m7-contract-integration`
- Latest pushed commit: `6a212ff` (`fix: make analysis evidence-backed and add CAPE integration`)
- Remote: `origin` -> `https://github.com/ACE4AKSHAY/TRAC-Trojan-Response-and-Analysis-Command-tool.git`
- `main` was not changed.

## What now works

The safe, evidence-backed path is implemented in `m7_core/services/pipeline_runner.py`:

1. M1 accepts a PE or MalwareBazaar ZIP and stores it encrypted and defanged.
2. M2 (`m2_static/analyzer.py`) parses real PE headers, imports, sections,
   entropy, strings, and embedded URLs without executing the submitted file.
3. M3 (`m3_dynamic/inference_engine.py`) reports only static capability markers
   by default. It does **not** invent runtime process trees, dropped files,
   registry edits, beacon timing, or sandbox results.
4. M4 extracts defanged, evidence-backed IOCs.
5. M5 produces weighted scores whose listed component contributions equal the
   score, and does not fabricate an intelligence-provider hit.
6. M6 creates only dry-run response actions.

For actual dynamic execution, M3 contains a CAPEv2 HTTP API adapter. It is
enabled only when `TRAC_CAPE_URL` is set (optional bearer token:
`TRAC_CAPE_TOKEN`). The configured CAPE instance must be an isolated lab with
snapshot reversion and simulated/contained networking. Never execute malware
on the developer workstation.

## Verified checks

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest m3_dynamic\tests\test_inference_engine.py m4_ioc\tests\test_extractor.py m5_detection\tests\test_scoring_engine.py m5_detection\tests\test_m5.py -q
.\.venv\Scripts\python.exe -m unittest discover -s contract\tests -v
.\.venv\Scripts\python.exe contract\tools\check_all.py --repo-root .
```

Results at handoff: focused regression tests `4 passed`; contract tests
`21 passed`; module gate passed for M1 through M8.

The end-to-end pipeline was additionally checked with EICAR using a temporary
vault: it generated a schema-valid malicious result with score `88.0`; M3
correctly returned `skipped` because no CAPE endpoint was configured.

## Important truthfulness rules

- Do not label static imports, strings, or filenames as observed runtime
  behavior.
- Do not generate dummy PIDs, dropped-file hashes, registry targets, C2 hosts,
  beacon frequency/jitter, or threat-intel hits.
- A ZIP password such as `infected` is input to archive extraction only; do not
  write its payload to an unprotected temporary file.
- `m1_ingestion/scanner.py` now streams bytes to ClamAV stdin, rather than
  writing a raw sample to disk.

## Next one priority

**Wire the existing upload route/UI to surface the pipeline result clearly.**

Inspect `m8_ui_devops` and ensure the upload endpoint calls
`run_full_pipeline`, persists/retrieves the finished analysis through M7's
approved ownership flow, and renders these labels exactly:

- `Static evidence` for imports, strings, entropy, and inferred capabilities.
- `Observed sandbox telemetry` only when M3 `dynamic.status == "done"`.
- `Sandbox not configured` when M3 `dynamic.status == "skipped"`.
- `Sandbox failed` with a safe operator-facing error when M3 returns `failed`.

Keep API/contract ownership intact: M7 writes pipeline/database state; M6 owns
only `response_actions`; destructive response actions remain dry-run unless
explicitly approved.

Before each meaningful slice:

```powershell
git status --short --branch
git fetch origin
```

After focused tests and `git diff --check`, commit and push only the feature
branch:

```powershell
git add <only-intended-files>
git commit -m "feat: <short description>"
git push origin m6-m7-contract-integration
```
