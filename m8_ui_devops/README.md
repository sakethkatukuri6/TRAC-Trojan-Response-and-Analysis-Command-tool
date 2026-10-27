# Module M8: Dashboard, Reporting, DevOps & QA

**TRAC (Trojan Response and Analysis Command Platform)**  
*Owner: P4 (with M7 Core)*  
*Contract Version: 1.0.0*

---

## 1. Overview & Purpose

Module M8 provides the presentation, forensic reporting, CI/CD automation, and deployment infrastructure for the TRAC platform:
- **Enterprise SOC Analyst UI**: High-information-density cybersecurity console built without generic "vibe-coded" aesthetics. Designed specifically for tier 2/3 SOC analysts, threat hunters, and incident commanders.
- **Publication-Grade Forensic Reporting**: Multi-page PDF reports (via ReportLab Platypus) and interactive HTML incident dossiers featuring cryptographic hash provenance, weighted score breakdown, MITRE ATT&CK matrix mappings, defanged IOC tables, dynamic process trees, and containment action audit logs.
- **Pipeline Integration**: Consumes `response.done` events, generates forensic artifacts, and emits contract-valid `report.done` queue events (`report_vault_id` payload) that transition the pipeline state machine to `complete`.
- **DevOps & Lab Isolation**: Docker Compose profiles (`core`, `analysis`, `lab`), isolated RFC 5737 airgap network harness, Prometheus/Grafana monitoring, and GitHub Actions CI gates.

---

## 2. Contract Compliance & Rules

Per `contract/pipeline/state_machine.yaml` and `contract/schemas/events.schema.json`:
- **Section Ownership**: M8 owns no section directly within `analysis_result.schema.json` (`REQUIRED["M8"] = []`). M7 remains the sole writer to the central persistence store.
- **Event Produced**: `report.done`
  ```json
  {
    "event_id": "<uuid>",
    "type": "report.done",
    "analysis_id": "<uuid>",
    "vault_id": "<uuid>",
    "emitted_at": "<iso-8601-timestamp>",
    "producer": "M8",
    "contract_version": "1.0.0",
    "payload": {
      "report_vault_id": "<uuid>"
    }
  }
  ```
- **Error Event**: `stage.failed` with payload `{"stage": "report", "code": "<CODE>", "retryable": true/false}`.
- **Safety Enforcement**:
  - All indicators are defanged (`hxxp://`, `[.]`, `[:]`).
  - Strict 100 MiB upload cap enforced on intake.
  - Destructive containment actions in `real` mode hold in `awaiting_approval` until authorized by an incident commander with audit justification.

---

## 3. Architecture

```
                       ┌─────────────────────────┐
                       │   M6 Response Engine    │
                       └────────────┬────────────┘
                                    │ event: response.done
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │             M8 UI, REPORTING & DEVOPS                 │
       │                                                        │
       │  ┌───────────────────┐       ┌──────────────────────┐  │
       │  │  Report Worker    │       │  Enterprise SOC UI   │  │
       │  │  (PDF / HTML)     │       │  (React 18 + TS)     │  │
       │  └─────────┬─────────┘       └──────────┬───────────┘  │
       └────────────┼────────────────────────────┼──────────────┘
                    │ event: report.done         │ REST API
                    ▼                            ▼
       ┌────────────────────────────────────────────────────────┐
       │             M7 Core API & Orchestrator                 │
       │        (State Machine: report -> complete)             │
       └────────────────────────────────────────────────────────┘
```

---

## 4. SOC Analyst Interface Features

The interface avoids "vibe coded" tropes (random purple glows, empty decorative cards, missing error states, low density) and adheres to enterprise SOC analyst tooling standards (similar to CrowdStrike Falcon, SentinelOne, Splunk ES):
1. **Overview Tab**: Sample cryptographic provenance (SHA-256, MD5, Vault ID, ClamAV status), pipeline stage progress stepper (`ingest` &rarr; `complete`), threat score decomposition table.
2. **Static Analysis Tab**: Shannon Entropy spectrum (0.0 to 8.0) with red alert threshold at 7.0 for packed/encrypted sections; PE section table with raw vs virtual size; imports categorized by malicious capability (Injection, C2, Persistence); YARA detections.
3. **Dynamic Behaviour Tab**: Guest sandbox telemetry (CAPE v2, snapshot revert confirmation); visual process hierarchy tree (PID/PPID, command lines); host file and registry mutation timelines; mutexes; dropped payloads.
4. **Network & C2 Tab**: Traffic metrics (DNS, HTTP, TCP); automated C2 periodic beaconing analysis (interval seconds, jitter percentage, ping pulse count); PCAP reference.
5. **Indicators of Compromise (IOC) Tab**: Filterable, searchable table with defanged display (`hxxp://`, `[.]`); instant copy buttons; single-click STIX 2.1 bundle export and CSV export.
6. **MITRE ATT&CK Matrix Tab**: Tactical heatmap covering Execution, Persistence, Defense Evasion, and C2 with technique badges and direct evidence citations.
7. **Response & Containment Tab**: Incident containment log; dry-run vs real mode indicator; approval workflow modal requiring approver ID and audit justification note.
8. **Pipeline & Audit Tab**: State machine transition audit trail; live contract JSON inspector with schema verification.

---

## 5. Usage & CLI Commands

### Generate Forensic PDF and HTML Reports & Emit Event
```bash
python -m m8_ui_devops.cli \
  --analysis-id 00000003-0000-4000-8000-000000000003 \
  --vault-id 00000003-0000-4000-8000-000000000003 \
  --out-pdf data/reports/report.pdf \
  --out-html data/reports/report.html
```

### Launch Interactive SOC Dashboard
```bash
python -m m8_ui_devops.cli --serve-ui --port 8080
```
Open your browser at `http://127.0.0.1:8080` to access the full interactive command console.

---

## 6. Testing & CI Gates

```bash
# 1. Run M8 unit tests (CLI, worker, reporting, security, contract)
pytest m8_ui_devops/tests -v

# 2. Run repository-wide contract checks
python -m unittest discover -s contract/tests -v

# 3. Run strict per-module contract gate
python contract/tools/check_module.py --module M8 --event m8_ui_devops/contract_events/report_done.json

# 4. Run CI gate across all platform modules
python contract/tools/check_all.py --repo-root .
```
