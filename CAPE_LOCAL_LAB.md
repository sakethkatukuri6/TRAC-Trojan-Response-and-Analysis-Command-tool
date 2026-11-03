# CAPE local lab guide (M3 dynamic analysis)

This document describes the only sandbox configuration TRAC is designed to talk
to: a self-hosted CAPEv2 lab on your own hardware. It covers the architecture,
the isolation controls that must exist before TRAC is pointed at it, the
preflight checks, and what TRAC does when any of it is wrong.

**TRAC never executes a sample itself.** M3 is an HTTP client for the CAPE REST
API. Nothing in the repository needs a live sandbox to run, and the M3 test
suite (`m3_dynamic/tests/test_cape_adapter.py`) mocks the HTTP layer, so the
adapter can be verified without submitting anything anywhere.

---

## 1. Safety model

| Rule | How it is enforced |
|---|---|
| Malware never leaves the lab | M3 posts the sample to the CAPE host over the management network only; no third-party analysis service is called. |
| The guest is disposable | Every analysis VM is a snapshot-backed, single-use guest. TRAC only reports `reverted: true` when the operator has attested that the machinery reverts it (see §6). |
| No egress | The guest sits on a libvirt host-only network. If CAPE reports a non-isolated route (`internet`, `tor`, `vpn*`), M3 fails the dynamic stage instead of publishing the result. |
| No ambient credentials | No shared folders, clipboard, USB passthrough, host services, or personal accounts are attached to the guest. TRAC has no mechanism to send any of them. |
| Secrets stay secret | The API token travels only in the `Authorization: Token …` header. Every error string is scrubbed of URL credentials, bearer-style secrets and the configured token, then truncated to 500 characters. |
| Nothing is invented | A report contains only fields CAPE actually returned. Missing telemetry is missing, not zero-filled or guessed. |

With no `TRAC_CAPE_URL` configured, `dynamic.status` is `skipped` and the report
says plainly that no runtime behaviour was observed. That is a valid outcome,
not a degraded one.

---

## 2. Architecture

```
 analyst workstation                 management network (restricted)              analysis network (isolated)
 +--------------------+   HTTPS    +---------------------------+   libvirt API  +--------------------------+
 | TRAC (M1..M8)      | ---------> | CAPE host                 | -------------> | Disposable Windows guest |
 | m3_dynamic         |  /apiv2    | Ubuntu LTS + KVM/libvirt  |  host-only     | win10x64-1 (snapshot:    |
 | - preflight        |            | cape user, uwsgi/web,     |  network       |   "clean")               |
 | - submit/poll/     |            | CAPE scheduler + processing|  (no egress)  | cape-agent on guest      |
 |   fetch report     |            +---------------------------+                +--------------------------+
 +--------------------+                             |
        |                                           v
        v                                    /var/lib/cape/
 +----------------+                          storage: samples,
 | M7 SQLite /    |                          drops, PCAPs, reports
 | vault at rest  |                          (host disk, never a share)
 +----------------+
```

Endpoints M3 uses, and nothing else:

| Call | Purpose |
|---|---|
| `GET  {root}/cuckoo/status/` | preflight: reachability, token validity, service liveness |
| `POST {root}/tasks/create/file/` | submit the sample as the multipart field `file` |
| `GET  {root}/tasks/view/{task_id}/` | poll until the task reaches a terminal status |
| `GET  {root}/tasks/report/{task_id}/json` | retrieve the JSON report |

`{root}` is always `…/apiv2`. `TRAC_CAPE_URL` may be set as
`http://cape-host:8000` or `http://cape-host:8000/apiv2` — either way exactly
one `/apiv2` prefix is generated, including for reverse-proxy sub-paths such as
`https://cape-host/cape/apiv2/`.

---

## 3. CAPE host (Ubuntu + KVM)

1. **Base OS.** Ubuntu LTS 22.04/24.04 on bare metal with CPU virtualisation
   enabled (`egrep -c '(vmx|svm)' /proc/cpuinfo` must be non-zero). A VM inside a
   VM is supported by CAPE but plan for the nesting overhead.
2. **Dedicated unprivileged user.** Run CAPE as its own account (conventionally
   `cape`), never as a personal user and never as root.
3. **Install CAPEv2** from the upstream repository using its own installer so you
   get the matching `conf/` tree, virtualenv and systemd units. KVM/libvirt
   machinery, plus the `windows` auxiliary module, is what M3 expects.
4. **Storage.** Samples, drops and PCAPs live on the host disk under CAPE's
   `storage/` directory. Encrypt that volume at rest (LUKS). Nothing from it is
   ever mounted into a guest.
5. **Patching split.** The CAPE host is patched on a maintenance window; the
   guests are not patched at all — they are reverted. Do not let Windows Update,
   telemetry or scheduled tasks mutate a guest between snapshot and analysis.

## 4. Disposable Windows guest

1. Build one guest per analysis profile from a clean ISO (e.g. a Windows
   evaluation image). Name the libvirt domain so it matches the CAPE machine
   label, e.g. `win10x64-1`.
2. Inside the guest: install the CAPE in-guest agent, disable Windows Update,
   defender definition auto-updates, sleep, screen lock and any first-run
   network chatter. Do not sign in to any account — local, built-in analysis
   credentials only, and never a personal Microsoft, work or school account.
3. Take **one** known-good snapshot named `clean` (or your convention) with the
   guest powered off, and point the machine definition at it. Key names differ
   between CAPE releases, so verify against the `conf/kvm.conf` your installer
   generated rather than assuming.
4. Duplicate the guest for concurrency instead of reusing one guest for several
   tasks, and keep `max_analysis_count`/machine counts consistent with the host's
   RAM.
5. Freeze the snapshot: any change to the guest (software, policy, Windows
   build) invalidates the attestation in §6, so re-take the snapshot and re-run
   the verification.

## 5. Isolation controls

**Host-only network.** Create a libvirt network without a forwarder and without a
route to the physical LAN — the guest gets an address the host can reach, and
nothing else can:

```bash
virsh net-define /etc/libvirt/qemu/networks/trac-isolated.xml   # <forward mode='none'/>, no <route>
virsh net-start trac-isolated && virsh net-autostart trac-isolated
virsh net-dumpxml trac-isolated        # must show no forwarder and no route
virsh domiflist win10x64-1             # the guest NIC is on the isolated network
```

Do not attach a second NIC pointing at a bridged/LAN interface, and do not enable
CAPE's internet routing. In `conf/routing.conf` leave the default route at none
and do not offer `internet`/`tor`/`vpn` routes to submitters — M3 refuses a
report whose `info.route` is anything but none/drop/empty.

**No host↔guest channels.** For every analysis domain, confirm and then enforce:

| Control | What must be absent | Verify with |
|---|---|---|
| Shared folders | `virtiofs`, `9p`, `nfs` mounts, VM Tools shared folders | `virsh dumpxml <domain> \| grep -Ei 'filesystem\|virtiofs\|fileaccess'` |
| Clipboard | spice-vdagent / guest agent channel | `virsh dumpxml <domain> \| grep -i spice`, no `vdagent` in the guest |
| USB passthrough | no `hostdev`, no redir device | `virsh dumpxml <domain> \| grep -Ei 'hostdev\|redirdev'` |
| Host services | no SSH keys, no service accounts, no API tokens inside the guest image | image built without credentials; rotate if one was ever typed into a guest |
| Personal accounts | no Microsoft/work/school sign-in, no browser sync profiles | local-only accounts, `net user` shows no mailbox profile |
| Serial/console | no `--serilog` capture of host paths | `virsh dumpxml <domain>` console is `pty`/`none` only |

`virsh edit` changes to a domain must be reviewed the same way as code — a stray
`<hostdev>` silently breaks the isolation promise.

## 6. Management-only API exposure

The CAPE web/API is a management interface, not an analysis network service.

1. **Bind narrowly.** Keep uwsgi/web on `127.0.0.1` and terminate TLS in a
   reverse proxy bound to the management address only. Never `0.0.0.0` on an
   interface that also faces the analysis network.
2. **Allow-list the callers.** Only the TRAC host (and named analyst hosts) may
   reach the API port:
   ```bash
   sudo ufw allow from 10.10.7.20 to any port 8443 proto tcp   # TRAC node
   sudo ufw deny 8000/tcp && sudo ufw reload
   ss -lntp | grep -E '8000|8443'                              # listener is the intended address
   curl -sk https://cape-host:8443/apiv2/cuckoo/status/        # 401/403 without a token, from a non-allow-listed host
   ```
3. **Use HTTPS** between TRAC and CAPE whenever the two are not on the same host,
   so the token is not in cleartext on the wire. `TRAC_CAPE_URL` then starts with
   `https://`.
4. **Issue one API token per integration.** Generate CAPE's per-user token for a
   dedicated, low-privilege integration account; never reuse an analyst's personal
   token, and rotate on a schedule and on any suspected exposure.
5. **Store it outside the repository.** `TRAC_CAPE_URL`, `TRAC_CAPE_TOKEN` and
   `TRAC_CAPE_SNAPSHOT_REVERTED` come from the environment or an untracked `.env`
   (`.gitignore` already excludes `.env*`). Tokens must never appear in a commit,
   an issue, or a report.
6. **Never expose `/apiv2` to the internet**, and do not enable authentication-
   optional API access — a reachable unauthenticated submit endpoint is a remote
   code-execution surface, because anyone can run their sample on your hardware.

## 7. Preflight, in order

Run these before pointing TRAC at a lab. The first three are what M3 itself does.
The examples assume `CAPE_API` is the normalised root — with
`TRAC_CAPE_URL=http://cape-host:8000` that is `http://cape-host:8000/apiv2`:

```bash
CAPE_API="${TRAC_CAPE_URL%/}"; case "$CAPE_API" in */apiv2) ;; *) CAPE_API="$CAPE_API/apiv2";; esac
```

| # | Check | Command / evidence |
|---|---|---|
| 1 | API reachable and token valid | `curl -s -H "Authorization: Token $TRAC_CAPE_TOKEN" $CAPE_API/cuckoo/status/` returns `success: true` with a `data` block |
| 2 | Scheduler and queues healthy | the same status payload shows `machines.running`, `queues.pending/processing` that are not stuck |
| 3 | An analysis machine exists and is free | machine list/status shows the guest as `idle`, correct platform |
| 4 | Route is isolated | `grep -A5 '\[routing\]' conf/routing.conf` shows no internet routing |
| 5 | Guest disk is snapshot-backed | `virsh snapshot-list-domain win10x64-1` shows the clean snapshot as current |
| 6 | Reversion actually happens | §8 |
| 7 | Disk space / retention | `df -h` on the CAPE `storage/` volume; a full store is the most common cause of `failed_analysis` |
| 8 | TRAC can read a report | `curl … $CAPE_API/tasks/report/<id>/json` returns JSON, not a login page |

A 401/403 here means TRAC will fail the dynamic stage with
`CAPE rejected the API token … (HTTP 401); check TRAC_CAPE_TOKEN`.

## 8. Verify snapshot reversion before attesting it

TRAC publishes `sandbox.reverted = true` **only** when
`TRAC_CAPE_SNAPSHOT_REVERTED` is set to a truthy value. That variable is an
attestation of fact, not an aspiration: set it after you have watched a revert
happen, and re-verify after any host, guest or CAPE configuration change.

1. Boot the guest once (console only, no network) and create a marker file, e.g.
   `C:\trac-marker.txt`, plus a marker registry value and a marker service.
2. Shut the guest down and make sure the machine definition still points at the
   clean snapshot.
3. Submit a **benign** task to CAPE — a text file, a benign command-line package,
   or an EICAR-style test file. Never use a real sample for a lab-integrity test.
4. After the task completes, inspect the guest again and confirm all three
   markers are gone. That proves the machinery reverted to the snapshot.
5. Confirm the host's own state: the domain returned to `shut off`/`running` as
   expected, no stray snapshot was created, and `queues.completed` advanced.
6. Only then set `TRAC_CAPE_SNAPSHOT_REVERTED=true` for the TRAC process.

If reversion is manual, script it (`virsh snapshot-revert <domain> --snapshotname
clean`) and gate the TRAC submission on that step, or leave the attestation unset —
the honest outcome is `dynamic.status = "failed"` with a message naming reversion,
not a completed run whose guest state nobody checked.

---

## 9. TRAC configuration

| Variable | Purpose | Notes |
|---|---|---|
| `TRAC_CAPE_URL` | CAPE API base | `http://cape-host:8000` or `…/apiv2`; normalised to exactly one `/apiv2`. Unset/blank ⇒ dynamic stage is `skipped`. |
| `TRAC_CAPE_TOKEN` | CAPE API token | sent as `Authorization: Token <value>`; absent ⇒ no header is sent |
| `TRAC_CAPE_SNAPSHOT_REVERTED` | operator attestation that the guest reverts after every task | unset/false ⇒ a finished run still fails closed (§10) |
| `timeout_s` (argument) | overall wait budget for one task, default 180 s | each HTTP call is separately bounded: 10 s preflight, 30 s per request, 5 s between polls |

## 10. Failure behaviour

`infer_behavior` never raises into the pipeline. Every path below returns
`{"status": "failed", "_static_capabilities": …, "_error": "<sanitised>"}`, and
the M7 pipeline records `SANDBOX_FAILED` while keeping the static evidence
intact:

| Condition | Sanitised error |
|---|---|
| `TRAC_CAPE_URL` is not a usable http(s) endpoint | `TRAC_CAPE_URL must be an http(s) CAPE API endpoint …` |
| Host unreachable, DNS failure, refused socket | `CAPE endpoint is unreachable at <path>: <reason>` |
| Any request exceeds its timeout | `CAPE request to <path> exceeded its N second timeout` |
| HTTP 401/403 | `CAPE rejected the API token for <path> (HTTP 401); check TRAC_CAPE_TOKEN` |
| HTTP 404 | `CAPE has no endpoint at <path> (HTTP 404); check TRAC_CAPE_URL` |
| Non-JSON / unexpected shape | `CAPE returned a malformed (non-JSON) response for <path>: <detail>` |
| Submission returned no task id | `CAPE accepted the submission but returned no task id` |
| Task status `failed`, `failed_analysis`, `failed_processing`, `report_failed`, `recovered` | `CAPE task <id> ended with status '<status>'` |
| Task never reaches a terminal status | `CAPE task <id> did not reach a terminal status within the N second timeout` |
| Report fetch fails after a completed task | the request-level error above — a completed task is never published without its report |
| `info.route` is not isolated | `CAPE guest '<route>' is not an isolated network route …` |
| Reversion not attested | `CAPE did not confirm snapshot reversion and the operator has not attested it …` |
| Anything unexpected | the exception text, scrubbed and truncated |

Sanitising removes `scheme://user:pass@` credentials, `Authorization: …` /
`Token <secret>` values, `password=`-style assignments and the literal configured
token, then caps the message at 500 characters.

## 11. What M3 normalises from a CAPE report

| Contract field | CAPE source | If CAPE omits it |
|---|---|---|
| `sandbox.engine` | fixed `capev2` (this adapter) | — |
| `sandbox.guest_os` | `info.machine.name` | `unknown` |
| `sandbox.run_id` | the task id M3 was given | — |
| `sandbox.duration_s` | `info.duration` | key omitted |
| `sandbox.timeout_s` | TRAC's configured wait budget | — |
| `sandbox.network_mode` | derived from `info.route` (`none`/`drop`/empty ⇒ `isolated`) | any other route ⇒ fail closed |
| `sandbox.reverted` | operator attestation only | not attested ⇒ fail closed |
| `process_tree[]` | `behavior.processes[]` → `pid`, `name`, and `ppid`/`command_line` only when present | empty list |
| `api_summary{}` | counts of `behavior.processes[].calls[].api` | empty object |
| `file_events[]` | `created_files`/`written_files`/`deleted_files`/`read_files` per process, with that process's pid | empty list |
| `registry_events[]` | `created_keys`/`written_keys`/`deleted_keys`/`read_keys` per process | empty list |
| `mutexes[]` | `behavior.summary.mutexes` | empty list |
| `dropped_files[]` | `dropped[]` entries that carry a valid SHA-256 (`name`, `size_bytes` when present) | empty list; an unhashed drop is not published |
| `network_summary{}` | counts of `network.dns`/`network.http`/`network.tcp` | `network_summary` is omitted entirely when the report has no `network` block |

M3 never emits a beacon, C2 session, process, file or registry event that CAPE
did not return, and it does not translate counts into behaviour — M5 scores what
is there.

## 12. Verify the adapter without a sandbox

The tests replace `urllib.request` inside the adapter with a recording fake, so
they prove the wire format, the fail-closed matrix and the sanitising rules with
no network, no credentials and no executed code:

```powershell
.\.venv\Scripts\python.exe -m pytest m3_dynamic\tests -q      # 51 passed
```

A lab smoke test that needs no malware: point `TRAC_CAPE_URL` at the lab, submit
a text file through the pipeline, and confirm the dynamic section reports the
guest you configured — or fails with one of the messages in §10 rather than
silently reporting `done`.
