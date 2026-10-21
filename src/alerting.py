"""
Alerting.

Detections produce Findings. This layer turns Findings into ALERTS:
  - assigns a numeric priority score so the worst things sort to the top
  - enriches with a stable timestamp and evidence summary
  - renders to the console (for an analyst) and to a JSON file (for tooling)

Severity -> score mapping lets us sort mixed findings sensibly. Later
(Phase 3) the AI triage layer will add a plain-English "what happened /
what to do" summary onto each alert.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .detections import Finding

SEVERITY_SCORE = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


def finding_to_alert(finding: Finding) -> dict:
    """Convert a Finding into a serializable, enriched alert dict."""
    first_seen = min((e.timestamp for e in finding.events), default=None)
    last_seen = max((e.timestamp for e in finding.events), default=None)

    # Which source(s) did the evidence come from, and any K8s context it carried.
    sources = sorted({e.source for e in finding.events if e.source})
    namespaces = sorted({e.namespace for e in finding.events if e.namespace})
    pods = sorted({e.pod for e in finding.events if e.pod})
    containers = sorted({e.container for e in finding.events if e.container})

    alert = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "priority_score": SEVERITY_SCORE.get(finding.severity, 0),
        "severity": finding.severity,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "actor": finding.actor,
        "sources": sources,
        "mitre_attack": {
            "technique_id": finding.attack_technique,
            "technique_name": finding.attack_name,
        },
        "evidence_count": len(finding.events),
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "source_ips": sorted({e.source_ip for e in finding.events if e.source_ip}),
    }

    # Only attach Kubernetes context when a runtime source actually provided it,
    # so cloud-audit alerts stay clean.
    k8s = {}
    if namespaces:
        k8s["namespaces"] = namespaces
    if pods:
        k8s["pods"] = pods
    if containers:
        k8s["containers"] = containers
    if k8s:
        alert["kubernetes"] = k8s

    return alert


def _dedup_key(finding: Finding) -> tuple:
    """
    What makes two findings 'the same alert'. Same rule, same actor, same
    place (container when present) => one alert, not N. We deliberately do NOT
    key on timestamp: repeated identical activity should fold into one alert
    with a higher count, not spam the analyst with a row per event.
    """
    container = next((e.container for e in finding.events if e.container), None)
    return (finding.rule_id, finding.actor, container)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Collapse duplicate findings into one, merging their evidence so the
    resulting alert's count and time window reflect ALL occurrences.
    Order is preserved (first occurrence wins its slot).
    """
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = _dedup_key(f)
        if key in merged:
            # fold this finding's evidence into the one we already kept
            existing = merged[key]
            seen = set(id(e) for e in existing.events)
            for e in f.events:
                if id(e) not in seen:
                    existing.events.append(e)
        else:
            # keep a shallow copy so we don't mutate the caller's Finding
            merged[key] = Finding(
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity,
                attack_technique=f.attack_technique,
                attack_name=f.attack_name,
                description=f.description,
                actor=f.actor,
                events=list(f.events),
            )
    return list(merged.values())


def build_alerts(findings: list[Finding], dedup: bool = True) -> list[dict]:
    """Turn findings into alerts, highest priority first (deduped by default)."""
    if dedup:
        findings = deduplicate_findings(findings)
    alerts = [finding_to_alert(f) for f in findings]
    alerts.sort(key=lambda a: a["priority_score"], reverse=True)
    return alerts


def print_alerts(alerts: list[dict]) -> None:
    """Human-readable console output for an analyst."""
    if not alerts:
        print("No alerts generated. (No suspicious activity detected.)")
        return

    icons = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}
    print(f"\n{'=' * 70}")
    print(f"  THREAT DETECTION RESULTS — {len(alerts)} alert(s)")
    print(f"{'=' * 70}\n")

    for i, a in enumerate(alerts, 1):
        tag = icons.get(a["severity"], "[????]")
        mitre = a["mitre_attack"]
        print(f"{i}. {tag} (score {a['priority_score']})  {a['title']}")
        print(f"     MITRE ATT&CK : {mitre['technique_id']} - {mitre['technique_name']}")
        print(f"     Source       : {', '.join(a['sources']) if a.get('sources') else 'unknown'}")
        print(f"     Actor        : {a['actor']}")
        if a.get("kubernetes"):
            k = a["kubernetes"]
            bits = []
            if k.get("namespaces"):
                bits.append(f"ns={','.join(k['namespaces'])}")
            if k.get("pods"):
                bits.append(f"pod={','.join(k['pods'])}")
            if k.get("containers"):
                bits.append(f"container={','.join(k['containers'])}")
            print(f"     Kubernetes   : {'  '.join(bits)}")
        if a["source_ips"]:
            print(f"     Source IP(s) : {', '.join(a['source_ips'])}")
        print(f"     Evidence     : {a['evidence_count']} event(s), "
              f"{a['first_seen']} -> {a['last_seen']}")
        print(f"     Detail       : {a['description']}")
        if a.get("triage"):
            t = a["triage"]
            print(f"     ── Triage ({t.get('engine', 'n/a')}) ──")
            print(f"     What happened: {t.get('summary', '')}")
            print(f"     Why it matters: {t.get('why_it_matters', '')}")
            print(f"     Do next      : {t.get('recommended_actions', '')}")
        print()


def write_alerts_json(alerts: list[dict], path: str | Path) -> None:
    """Machine-readable output for downstream tooling."""
    Path(path).write_text(json.dumps(alerts, indent=2))
    print(f"Wrote {len(alerts)} alert(s) to {path}")
