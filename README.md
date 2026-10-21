# Threat Detection Pipeline

A cloud-native threat detection pipeline that ingests security logs, detects suspicious
activity using rules mapped to [MITRE ATT&CK](https://attack.mitre.org/), and generates
prioritized, enriched alerts.

## What it does

```
SOURCES            PIPELINE                                   OUTPUT
CloudTrail  ──▶  ingest → normalize → detect → triage ──▶  prioritized,
Falco (K8s) ──▶     (common schema)   (ATT&CK)   (AI)        triaged alerts
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

- [x] Phase 1 — Core pipeline on synthetic CloudTrail logs
- [x] Phase 2 — Multi-source + prioritization
  - [x] Falco (Kubernetes runtime) source added, normalized into the common schema
  - [x] Runtime detection rules mapped to ATT&CK (shell-in-container, credential access, tool transfer, persistence, reverse shell)
  - [x] Live Falco from a real cluster — verified end to end on minikube (see below)
  - [x] Alert dedup (collapses repeat activity into one alert with a merged time window)
- [x] Phase 3 — AI-assisted triage layer + tests + polish

9 detection rules across cloud-audit and runtime, 24 unit tests, runnable with
zero external dependencies or secrets.

## Quick start

```bash
cd threat-detection-pipeline
python3 run.py
```

This ingests the sample logs at `data/sample_cloudtrail.json` (cloud audit) and
`data/sample_falco.json` (Kubernetes runtime), runs both through one detection
pass, and prints the prioritized alerts it generates.

## Running against a real Kubernetes cluster (live Falco)

The Falco source works on synthetic samples *and* on real telemetry from a live
cluster — same code path. Verified on minikube:

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
- **LLM-backed (optional):** set `OPENAI_API_KEY` (and optionally `TRIAGE_MODEL`,
  default `gpt-4o-mini`) and install `openai`. The model only ever receives the
  structured alert fields — never raw logs — so there's no secret-leak path.
  Any API error falls back to the rule-based note; the pipeline never crashes on
  a triage failure.

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Covers every detection rule (fires on malicious input, stays silent on benign),
a regression test for the read-vs-write false positive, dedup behavior, and the
triage fallback path.

## Project layout

```
threat-detection-pipeline/
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
└── requirements-dev.txt    # test deps (pytest)
```

## Concepts you can speak to after building this

- Log ingestion and normalization (the core of every SIEM)
- MITRE ATT&CK and detection engineering
- Alert enrichment, prioritization, dedup, and severity
- AI-assisted triage, with a safe LLM integration (structured input only, graceful fallback)
- How cloud-audit (CloudTrail) and runtime (Falco) telemetry complement each other
- Deploying Falco on Kubernetes and validating detections against real telemetry
