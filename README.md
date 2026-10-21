# Threat Detection Pipeline

[![CI](https://github.com/Divided1000/threat-detector-enterprise/actions/workflows/ci.yml/badge.svg)](https://github.com/Divided1000/threat-detector-enterprise/actions/workflows/ci.yml)

A cloud-native threat detection pipeline that ingests security logs, detects suspicious
activity using rules mapped to [MITRE ATT&CK](https://attack.mitre.org/), and generates
prioritized, enriched alerts.

## What it does

```
SOURCES            PIPELINE                                        OUTPUT
CloudTrail  ──▶  ingest → normalize → detect → triage ──────▶  prioritized,
Falco (K8s) ──▶     (common schema)   (ATT&CK) (playbook/LLM)    triaged alerts
```

Both sources flow through a single detection pass. Cloud-audit (CloudTrail)
and runtime (Falco) events are normalized into the same schema, so every
detection and the alerting layer treat them identically.

1. **Ingest** raw security logs from multiple sources.
2. **Normalize** every event into one common schema, so detections don't care where the event came from.
3. **Detect** suspicious patterns with rules, each mapped to a MITRE ATT&CK technique.
4. **Alert** — turn detections into enriched, prioritized, de-duplicated alerts.
5. **Triage** — attach a plain-English "what happened / why it matters / what to do" note to each alert (LLM-backed when an API key is set, deterministic otherwise).

## Status

**Complete.** All three roadmap phases are done:

- **Phase 1** — Core pipeline on synthetic CloudTrail logs
- **Phase 2** — Falco (Kubernetes runtime) source, runtime detection rules, live-cluster verification on minikube, and alert dedup
- **Phase 3** — AI-assisted triage layer, unit tests, and polish

9 detection rules across cloud-audit and runtime telemetry, 25 unit tests,
runnable with zero external dependencies or secrets.

## Detection rules

Every rule operates on the common schema and is mapped to a MITRE ATT&CK
technique. Runtime rules only fire on events that carry container context, so
they never match cloud-audit events (and vice versa) — no source checks needed.

| Rule ID | Source | ATT&CK | Technique | Severity |
|---|---|---|---|---|
| `BRUTE_FORCE_LOGIN` | CloudTrail | T1110 | Brute Force | high |
| `ROOT_CONSOLE_LOGIN` | CloudTrail | T1078.004 | Valid Accounts: Cloud Accounts | high |
| `IAM_POLICY_CHANGE` | CloudTrail | T1098 | Account Manipulation | critical |
| `ACCESS_KEY_CREATED` | CloudTrail | T1098 | Account Manipulation | critical (root) / medium |
| `K8S_SHELL_IN_CONTAINER` | Falco | T1059 | Command and Scripting Interpreter | high |
| `K8S_SENSITIVE_FILE_READ` | Falco | T1552.001 | Unsecured Credentials: Credentials In Files | high |
| `K8S_PACKAGE_MGMT` | Falco | T1105 | Ingress Tool Transfer | medium |
| `K8S_WRITE_BELOW_ETC` | Falco | T1053.003 / T1222 | Scheduled Task/Job: Cron (else File Permissions Mod) | critical (cron) / high |
| `K8S_SUSPICIOUS_OUTBOUND` | Falco | T1572 / T1071 | Protocol Tunneling (reverse shell) / Application Layer Protocol | critical (reverse shell) / high |

Several severities are context-dependent — e.g. an access key created by root is
critical, by a regular user medium; a write under `/etc/cron.*` is critical,
elsewhere under `/etc` high.

**A note on two mappings a reviewer might question:**

- `K8S_SUSPICIOUS_OUTBOUND` maps to the *network* technique, not `T1059`: a
  reverse shell is tunneling an interactive session out to a C2 host
  (**T1572 Protocol Tunneling**); other unexpected egress is **T1071 Application
  Layer Protocol**. The shell interpreter itself is already covered by
  `K8S_SHELL_IN_CONTAINER` (T1059), so mapping this rule to the connection
  avoids double-counting T1059.
- `K8S_PACKAGE_MGMT` → **T1105 Ingress Tool Transfer**: a package manager in a
  running container pulls binaries from an external repo into the workload at
  runtime, which is the tool-transfer behavior T1105 describes.

## Quick start

No dependencies, no secrets — just Python 3.9+ (the core uses only the standard
library; developed and tested on 3.14):

```bash
git clone https://github.com/Divided1000/threat-detector-enterprise
cd threat-detector-enterprise
python3 run.py
```

This ingests the sample logs at `data/sample_cloudtrail.json` (cloud audit) and
`data/sample_falco.json` (Kubernetes runtime), runs both through one detection
pass, and prints prioritized, triaged alerts. It also writes machine-readable
output to `data/alerts.json`.

### Sample output

> The events below come from **synthetic sample data** (`data/sample_*.json`).
> Timestamps are illustrative, not real incidents.

A single alert as rendered to the console:

```
1. [CRIT] (score 100)  IAM policy attached to user 'attacker'
     MITRE ATT&CK : T1098 - Account Manipulation
     Source       : cloudtrail
     Actor        : Root
     Source IP(s) : 192.0.2.200
     Evidence     : 1 event(s), 2026-10-20T15:14:20+00:00 -> 2026-10-20T15:14:20+00:00
     Detail       : Root (Root) attached policy 'AdminAccess' to user 'attacker'. Possible privilege escalation or persistence.
     ── Triage (rule-based) ──
     What happened: IAM policy attached to user 'attacker' from 192.0.2.200. Actor: Root. Mapped to MITRE T1098 (Account Manipulation).
     Why it matters: Attaching a permissive policy can hand an attacker admin rights (privilege escalation) or establish durable access (persistence).
     Do next      : Review the policy attached and whether the change was approved. Revert if unauthorized and audit what the target principal did afterward.
```

The same alert in `data/alerts.json` (machine-readable, triage note included):

```json
{
  "priority_score": 100,
  "severity": "critical",
  "rule_id": "IAM_POLICY_CHANGE",
  "title": "IAM policy attached to user 'attacker'",
  "actor": "Root",
  "sources": ["cloudtrail"],
  "mitre_attack": { "technique_id": "T1098", "technique_name": "Account Manipulation" },
  "source_ips": ["192.0.2.200"],
  "triage": {
    "engine": "rule-based",
    "summary": "IAM policy attached to user 'attacker' from 192.0.2.200. Actor: Root. Mapped to MITRE T1098 (Account Manipulation).",
    "why_it_matters": "Attaching a permissive policy can hand an attacker admin rights (privilege escalation) or establish durable access (persistence).",
    "recommended_actions": "Review the policy attached and whether the change was approved. Revert if unauthorized and audit what the target principal did afterward."
  }
}
```

## Running against a real Kubernetes cluster (live Falco)

The Falco source works on synthetic samples *and* on real telemetry from a live
cluster — same code path. Verified on minikube.

**Prerequisites:** Docker, `minikube`, `kubectl`, and `helm`.

```bash
# 1. cluster + Falco (modern eBPF, JSON output)
minikube start --driver=docker
helm repo add falcosecurity https://falcosecurity.github.io/charts && helm repo update
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set tty=true \
  --set falco.json_output=true --set falco.json_include_output_property=true

# 2. a target workload
kubectl create namespace production
kubectl run web-frontend --image=nginx:alpine -n production

# 3. trigger detections (simulated attacker behavior)
kubectl exec -n production web-frontend -- sh -c 'cat /etc/shadow'

# 4. capture Falco's real JSON alerts, then run the pipeline
#    (grep keeps only JSON lines, dropping Falco's own startup/log chatter)
kubectl logs -n falco -l app.kubernetes.io/name=falco -c falco --tail=1000 \
  | grep -E '^\{' > data/falco_live_capture.json
python3 run.py            # auto-detects data/falco_live_capture.json
```

`run.py` prefers `data/falco_live_capture.json` when present, otherwise falls
back to the synthetic `data/sample_falco.json`. The normalizer, detections, and
alerting layer are identical either way — that's the common-schema payoff.

> Note: the capture is a point-in-time snapshot of Falco's logs, not a live
> tail. Falco's default stable ruleset ships some rules disabled, so not every
> simulated action produces an alert out of the box — that's expected Falco
> behavior, not a pipeline bug.

## AI-assisted triage

Each alert gets a triage note answering the three questions an analyst asks next:
what happened, why it matters, and what to do. Two engines:

- **Rule-based (default):** a deterministic per-rule playbook. No dependencies,
  no secrets, runs anywhere including CI.
- **LLM-backed (optional):** install the client and set a key:

  ```bash
  pip install openai           # or: uncomment the line in requirements.txt
  export OPENAI_API_KEY=sk-...  # optional: export TRIAGE_MODEL=gpt-4o-mini (default)
  python3 run.py
  ```

  The model only ever receives the structured alert fields — never raw logs —
  so there's no secret-leak path. Any API error falls back to the rule-based
  note; the pipeline never crashes on a triage failure.

## Deduplication

Repeated identical activity collapses into one alert instead of spamming the
analyst with a row per event. Two findings are "the same alert" when they share
the **same rule, same actor, and same container** (where present). Dedup
deliberately does **not** key on time: the merged alert keeps the full evidence
list and a time window spanning first-to-last occurrence, with an
`evidence_count`. For example, two reads of `/etc/shadow` a minute apart in the
same container become a single alert with `evidence_count: 2`.

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Covers every detection rule (fires on malicious input, stays silent on benign),
a regression test for the read-vs-write false positive, dedup behavior, and the
rule-based triage path. Note: the tests exercise the **deterministic fallback**;
the LLM call itself is not tested end-to-end (see [Limitations](#limitations)).

CI runs the pipeline smoke test and the full suite on Python 3.9 and 3.12 via
GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) — no
secrets required, which is why the whole thing runs in CI unchanged.

## Adding a detection rule

A detection is just a function `list[NormalizedEvent] -> list[Finding]`,
registered in `ALL_DETECTIONS`. Because it reads the common schema, it works
against any source (CloudTrail, Falco, or a future one) automatically:

```python
# src/detections.py
def detect_disable_cloudtrail(events: list[NormalizedEvent]) -> list[Finding]:
    """T1562.001 - Impair Defenses: Disable or Modify Tools."""
    findings = []
    for e in events:
        if e.action == "StopLogging":            # CloudTrail turned off
            findings.append(Finding(
                rule_id="CLOUDTRAIL_DISABLED",
                title="CloudTrail logging stopped",
                severity="critical",
                attack_technique="T1562.001",
                attack_name="Impair Defenses: Disable or Modify Tools",
                description=f"{e.actor} stopped CloudTrail logging.",
                actor=e.actor,
                events=[e],
            ))
    return findings

ALL_DETECTIONS.append(detect_disable_cloudtrail)   # register it
```

That's the whole extension point — no changes to ingest, alerting, or triage.

## Project layout

```
threat-detector-enterprise/
├── run.py                  # entrypoint: wires the pipeline together
├── src/
│   ├── schema.py           # the common event schema (normalization target)
│   ├── ingest.py           # read raw logs + normalize to the schema
│   ├── detections.py       # detection rules, each mapped to ATT&CK
│   ├── alerting.py         # prioritize, dedup, and render alerts
│   └── triage.py           # AI-assisted triage notes (LLM or rule-based)
├── tests/
│   ├── test_detections.py       # rule fires-on-bad / silent-on-benign
│   └── test_alerting_triage.py  # dedup + triage fallback
├── data/
│   ├── sample_cloudtrail.json   # synthetic CloudTrail events (benign + malicious)
│   ├── sample_falco.json        # synthetic Falco K8s runtime events (JSONL)
│   └── falco_live_capture.json  # real Falco alerts from a live cluster (optional, gitignored)
├── requirements.txt        # runtime deps (optional LLM extra)
├── requirements-dev.txt    # test deps (pytest)
└── LICENSE                 # MIT
```

## What this demonstrates

- Log ingestion and normalization into a common schema — the core of every SIEM
- MITRE ATT&CK-mapped detection engineering across two telemetry types
- Alert enrichment, prioritization, dedup, and severity scoring
- A safe LLM integration: structured input only, deterministic fallback, no crash path
- How cloud-audit (CloudTrail) and runtime (Falco) telemetry complement each other
- Deploying Falco on Kubernetes and validating detections against real telemetry

## Limitations

- **Synthetic cloud data.** CloudTrail events are hand-authored samples, not from a live account.
- **Point-in-time Falco capture.** The live capture is a snapshot of Falco's logs, not a streaming tail. Falco's default stable ruleset also ships some rules disabled, so not every simulated action alerts out of the box — expected behavior, not a bug.
- **No streaming ingestion or persistence.** The pipeline is batch: read files, detect, write `alerts.json`. There's no message queue, database, or continuous processing.
- **LLM triage is optional and untested end-to-end here** — the rule-based fallback is the verified path; the model call is wired but exercised only when a key is supplied.

## License

MIT — see `LICENSE`.
