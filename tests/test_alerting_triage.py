"""
Unit tests for dedup (alerting) and the triage fallback.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from src.alerting import build_alerts, deduplicate_findings
from src.detections import Finding
from src.schema import NormalizedEvent
from src.triage import triage_alert

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def _falco_event(at, container="web-frontend"):
    return NormalizedEvent(
        source="falco", timestamp=at, action="Read sensitive file untrusted",
        actor="root", container=container, namespace="production",
        pod="web-frontend-abc", process="cat /etc/shadow",
        raw={"output_fields": {"fd.name": "/etc/shadow"}},
    )


def _finding(at, container="web-frontend"):
    return Finding(
        rule_id="K8S_SENSITIVE_FILE_READ",
        title=f"Sensitive file read in {container}",
        severity="high", attack_technique="T1552.001",
        attack_name="Unsecured Credentials: Credentials In Files",
        description="read /etc/shadow", actor="root",
        events=[_falco_event(at, container)],
    )


# --- dedup -----------------------------------------------------------------

def test_dedup_collapses_duplicates_and_merges_evidence():
    f1 = _finding(T0)
    f2 = _finding(T0 + timedelta(minutes=1))  # same rule/actor/container
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    assert len(merged[0].events) == 2  # evidence merged


def test_dedup_keeps_distinct_containers_separate():
    f1 = _finding(T0, container="web-frontend")
    f2 = _finding(T0, container="payments-api")
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 2


def test_build_alerts_dedup_reflects_count_and_window():
    f1 = _finding(T0)
    f2 = _finding(T0 + timedelta(minutes=5))
    alerts = build_alerts([f1, f2])
    assert len(alerts) == 1
    assert alerts[0]["evidence_count"] == 2
    assert alerts[0]["first_seen"] != alerts[0]["last_seen"]


def test_build_alerts_can_disable_dedup():
    f1 = _finding(T0)
    f2 = _finding(T0 + timedelta(minutes=1))
    assert len(build_alerts([f1, f2], dedup=False)) == 2


def test_alerts_sorted_by_priority():
    low = Finding("X", "low thing", "low", "T0000", "n", "d", "a", events=[_falco_event(T0)])
    crit = Finding("Y", "crit thing", "critical", "T0001", "n", "d", "a", events=[_falco_event(T0)])
    alerts = build_alerts([low, crit])
    assert alerts[0]["severity"] == "critical"
    assert alerts[-1]["severity"] == "low"


# --- triage fallback (no API key) ------------------------------------------

def test_triage_fallback_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    alert = build_alerts([_finding(T0)])[0]
    enriched = triage_alert(alert)
    t = enriched["triage"]
    assert t["engine"] == "rule-based"
    assert t["summary"]
    assert t["why_it_matters"]
    assert t["recommended_actions"]
    # the per-rule playbook text should be used for this rule_id
    assert "credential" in t["why_it_matters"].lower()


def test_triage_generic_fallback_for_unknown_rule(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = Finding("UNKNOWN_RULE", "mystery", "medium", "T9999", "n",
                "d", "a", events=[_falco_event(T0)])
    alert = build_alerts([f])[0]
    t = triage_alert(alert)["triage"]
    assert t["engine"] == "rule-based"
    assert t["recommended_actions"]  # generic advice still present
