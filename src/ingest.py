"""
Ingestion + normalization.

Reads raw log files from a source and converts each raw record into a
`NormalizedEvent`. Each source gets its own normalizer function; the rest
of the pipeline only ever sees NormalizedEvents.

Right now we have one source: AWS CloudTrail (from a JSON file).
In Phase 2 we'll add a Falco normalizer here -- and NOTHING downstream changes.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .schema import NormalizedEvent


def _parse_time(value: str) -> datetime:
    """CloudTrail timestamps look like 2026-10-20T14:05:58Z (ISO-8601, UTC)."""
    # datetime.fromisoformat handles the 'Z' suffix on Python 3.11+;
    # replace to be safe on older versions.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def normalize_cloudtrail_record(record: dict) -> NormalizedEvent:
    """Map ONE raw CloudTrail record into our common schema."""
    identity = record.get("userIdentity", {}) or {}

    # CloudTrail stores login success/failure in responseElements.ConsoleLogin
    outcome = None
    response = record.get("responseElements") or {}
    if "ConsoleLogin" in response:
        outcome = "success" if response["ConsoleLogin"] == "Success" else "failure"

    # Root has no userName; fall back to the identity type.
    actor = identity.get("userName") or identity.get("type", "unknown")

    return NormalizedEvent(
        source="cloudtrail",
        timestamp=_parse_time(record["eventTime"]),
        action=record.get("eventName", "unknown"),
        actor=actor,
        actor_type=identity.get("type", "unknown"),
        source_ip=record.get("sourceIPAddress"),
        region=record.get("awsRegion"),
        outcome=outcome,
        raw=record,
    )


def ingest_cloudtrail_file(path: str | Path) -> list[NormalizedEvent]:
    """Read a CloudTrail JSON file and return a list of NormalizedEvents."""
    data = json.loads(Path(path).read_text())
    records = data.get("Records", [])
    events = [normalize_cloudtrail_record(r) for r in records]
    # Detections that reason about time (brute force) want events in order.
    events.sort(key=lambda e: e.timestamp)
    return events


# ---------------------------------------------------------------------------
# Falco (Kubernetes runtime) source
#
# Falco watches syscalls INSIDE containers and emits one JSON object per line
# (JSONL). Where CloudTrail tells us "who called which AWS API", Falco tells us
# "what a process did inside a pod" -- a totally different shape. The whole point
# of the common schema is that once we map it here, every existing detection and
# the entire alerting layer work on Falco events with ZERO changes downstream.
# ---------------------------------------------------------------------------

def _parse_falco_time(value: str) -> datetime:
    """
    Falco timestamps are RFC3339 with nanosecond precision, e.g.
    2026-10-20T17:05:48.552331000Z. Python's fromisoformat only accepts up to
    microseconds (6 digits), so trim the fractional seconds before parsing.
    """
    value = value.replace("Z", "+00:00")
    # Split off a timezone offset (always present after the Z replacement).
    if "." in value:
        head, frac = value.split(".", 1)
        # frac looks like "552331000+00:00" -> keep <=6 digits of fraction.
        tz = ""
        for marker in ("+", "-"):
            idx = frac.find(marker)
            if idx != -1:
                frac, tz = frac[:idx], frac[idx:]
                break
        frac = frac[:6]  # microseconds max
        value = f"{head}.{frac}{tz}"
    return datetime.fromisoformat(value)


def normalize_falco_record(record: dict) -> NormalizedEvent:
    """Map ONE raw Falco alert into our common schema."""
    fields = record.get("output_fields", {}) or {}

    # Falco priorities -> our outcome isn't success/failure; leave outcome None.
    # The RULE name is the most useful "action" -- it's the behavior Falco named.
    return NormalizedEvent(
        source="falco",
        timestamp=_parse_falco_time(record["time"]),
        action=record.get("rule", "unknown"),
        actor=fields.get("user.name", "unknown"),
        actor_type="container_user",
        source_ip=fields.get("fd.sip"),       # destination/peer IP when present
        region=None,                           # not an AWS concept here
        outcome=None,
        container=fields.get("container.name"),
        namespace=fields.get("k8s.ns.name"),
        pod=fields.get("k8s.pod.name"),
        process=fields.get("proc.cmdline") or fields.get("proc.name"),
        raw=record,
    )


def ingest_falco_file(path: str | Path) -> list[NormalizedEvent]:
    """
    Read a Falco JSONL file (one JSON alert per line) and return NormalizedEvents.
    Blank lines are skipped so hand-edited files stay forgiving.
    """
    events: list[NormalizedEvent] = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(normalize_falco_record(json.loads(line)))
    events.sort(key=lambda e: e.timestamp)
    return events
