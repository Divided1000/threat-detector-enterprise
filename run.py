"""
Entrypoint: wire the pipeline together.

    ingest -> normalize -> detect -> alert

Run it:
    python3 run.py
"""

from __future__ import annotations

from pathlib import Path

from src.alerting import build_alerts, print_alerts, write_alerts_json
from src.detections import run_detections
from src.ingest import ingest_cloudtrail_file, ingest_falco_file
from src.triage import engine_in_use, triage_alerts

DATA_DIR = Path(__file__).parent / "data"
CLOUDTRAIL_FILE = DATA_DIR / "sample_cloudtrail.json"
FALCO_SAMPLE_FILE = DATA_DIR / "sample_falco.json"
# A real capture from a live cluster (kubectl logs ... > this file). When it
# exists we prefer it over the synthetic sample -- same code path either way.
FALCO_LIVE_FILE = DATA_DIR / "falco_live_capture.json"
OUTPUT_FILE = DATA_DIR / "alerts.json"


def main() -> None:
    # 1. INGEST + NORMALIZE: pull from every source into ONE list of
    #    NormalizedEvents. Cloud-audit (CloudTrail) and runtime (Falco) events
    #    now look identical to everything downstream -- that's the whole point
    #    of the common schema.
    events = ingest_cloudtrail_file(CLOUDTRAIL_FILE)
    print(f"Ingested {len(events)} event(s) from {CLOUDTRAIL_FILE.name}")

    # Prefer a real cluster capture if we have one; fall back to the sample.
    falco_file = FALCO_LIVE_FILE if FALCO_LIVE_FILE.exists() else FALCO_SAMPLE_FILE
    falco_events = ingest_falco_file(falco_file)
    tag = "LIVE" if falco_file is FALCO_LIVE_FILE else "sample"
    print(f"Ingested {len(falco_events)} event(s) from {falco_file.name} [{tag}]")

    events += falco_events
    events.sort(key=lambda e: e.timestamp)
    print(f"Total normalized event(s): {len(events)}")

    # 2. DETECT: run every ATT&CK-mapped rule -> list[Finding]
    findings = run_detections(events)
    print(f"Detections produced {len(findings)} finding(s)")

    # 3. ALERT: prioritize + dedup
    alerts = build_alerts(findings)

    # 4. TRIAGE (Phase 3): enrich each alert with a plain-English analyst note.
    print(f"Triage engine: {engine_in_use()}")
    alerts = triage_alerts(alerts)

    # 5. RENDER
    print_alerts(alerts)
    write_alerts_json(alerts, OUTPUT_FILE)


if __name__ == "__main__":
    main()
