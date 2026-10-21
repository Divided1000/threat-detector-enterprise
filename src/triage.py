"""
Phase 3 - AI-assisted triage.

An alert tells an analyst WHAT fired. Triage answers the three questions an
analyst actually has next:

    1. What happened?      (plain-English summary of the activity)
    2. Why does it matter?  (impact / what an attacker gains)
    3. What do I do?        (concrete next steps)

This module attaches a `triage` block to each alert.

Design: it works WITH or WITHOUT an LLM.
  - If an API key is configured (OPENAI_API_KEY), we ask a model to write the
    narrative from the alert's structured facts.
  - If not, we fall back to a deterministic, rule-aware template. The fallback
    is good enough to be useful on its own and keeps the whole pipeline runnable
    with no secrets and in CI -- which matters for a portfolio project.

The LLM only ever sees the already-structured alert fields (rule, technique,
actor, k8s context). We never send raw logs, so there's no secret-leak path.
"""

from __future__ import annotations

import json
import os
from typing import Any

# ---------------------------------------------------------------------------
# Deterministic fallback triage
#
# Per-rule playbook text. Keyed by rule_id so each detection gets advice that
# actually fits it. Unknown rules fall back to a generic-but-sane template.
# ---------------------------------------------------------------------------

_PLAYBOOK: dict[str, dict[str, str]] = {
    "BRUTE_FORCE_LOGIN": {
        "why": "Repeated failed logins suggest an attacker is guessing credentials. "
               "A later success would mean account takeover.",
        "do": "Confirm whether any attempt succeeded. If so, disable the account and "
              "rotate its credentials. Enforce MFA and consider blocking the source IP.",
    },
    "ROOT_CONSOLE_LOGIN": {
        "why": "Root has unrestricted access to the entire account. It should be "
               "locked away and essentially never used interactively.",
        "do": "Verify this login was authorized. If not, treat as account compromise: "
              "rotate root credentials, review recent root activity, enable MFA on root.",
    },
    "IAM_POLICY_CHANGE": {
        "why": "Attaching a permissive policy can hand an attacker admin rights "
               "(privilege escalation) or establish durable access (persistence).",
        "do": "Review the policy attached and whether the change was approved. Revert "
              "if unauthorized and audit what the target principal did afterward.",
    },
    "ACCESS_KEY_CREATED": {
        "why": "Long-lived access keys are a common persistence mechanism — they keep "
               "working even after a password reset.",
        "do": "Confirm the key was expected. If not, deactivate and delete it, then "
              "review CloudTrail for API calls made with it.",
    },
    "K8S_SHELL_IN_CONTAINER": {
        "why": "Containers should run their application, not an interactive shell. A "
               "shell usually means hands-on-keyboard access to a running workload.",
        "do": "Identify who/what spawned the shell. If unexpected, isolate the pod, "
              "capture forensics, and redeploy from a known-good image.",
    },
    "K8S_SENSITIVE_FILE_READ": {
        "why": "Reading files like /etc/shadow or credential files is a credential-"
               "access move that can lead to lateral movement.",
        "do": "Treat exposed credentials as compromised and rotate them. Investigate "
              "how the process got access and whether data left the container.",
    },
    "K8S_PACKAGE_MGMT": {
        "why": "Running containers should be immutable. Installing packages at runtime "
               "is often a precursor to pulling in attacker tooling.",
        "do": "Determine what was installed and why. If unexpected, isolate the pod and "
              "rebuild from the original image; bake needed tools into the image instead.",
    },
    "K8S_WRITE_BELOW_ETC": {
        "why": "Writing under /etc (especially cron) is a classic persistence backdoor "
               "that survives restarts.",
        "do": "Inspect the written file, remove unauthorized entries, and rebuild the "
              "workload from a trusted image. Review how the write was possible.",
    },
    "K8S_SUSPICIOUS_OUTBOUND": {
        "why": "Unexpected egress — especially a shell piped to a socket — is a reverse "
               "shell / C2 channel giving an attacker remote control.",
        "do": "Cut network egress for the pod immediately, isolate it, and capture the "
              "destination for threat intel. Hunt for the same pattern elsewhere.",
    },
}

_GENERIC = {
    "why": "This activity matched a detection rule mapped to a known adversary "
           "technique and warrants analyst review.",
    "do": "Confirm whether the activity was authorized. If not, contain the affected "
          "identity or workload and investigate related events around the same time.",
}


def _fallback_triage(alert: dict) -> dict:
    """Deterministic triage built from the alert's own fields."""
    play = _PLAYBOOK.get(alert.get("rule_id", ""), _GENERIC)

    where = ""
    k8s = alert.get("kubernetes")
    if k8s and k8s.get("containers"):
        where = f" in container '{', '.join(k8s['containers'])}'"
    elif alert.get("source_ips"):
        where = f" from {', '.join(alert['source_ips'])}"

    summary = (
        f"{alert.get('title', 'Suspicious activity')}{where}. "
        f"Actor: {alert.get('actor', 'unknown')}. "
        f"Mapped to MITRE {alert['mitre_attack']['technique_id']} "
        f"({alert['mitre_attack']['technique_name']})."
    )

    return {
        "engine": "rule-based",
        "summary": summary,
        "why_it_matters": play["why"],
        "recommended_actions": play["do"],
    }


# ---------------------------------------------------------------------------
# Optional LLM-backed triage
# ---------------------------------------------------------------------------

_TRIAGE_SYSTEM_PROMPT = (
    "You are a senior SOC analyst. Given a structured security alert, write a brief "
    "triage note for another analyst. Respond ONLY with JSON containing exactly three "
    "string fields: 'summary' (what happened, 1-2 sentences), 'why_it_matters' (impact, "
    "1-2 sentences), and 'recommended_actions' (concrete next steps, 1-2 sentences). "
    "Be specific and practical. Do not invent facts beyond the alert."
)


def _llm_triage(alert: dict) -> dict | None:
    """
    Ask an LLM to write the triage note. Returns None on any failure so the
    caller can fall back cleanly. Only the structured alert is sent.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        from openai import OpenAI  # imported lazily so the dep is optional
    except ImportError:
        return None

    # Send only the fields that matter for narrative — no raw logs.
    facts = {
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "rule_id": alert.get("rule_id"),
        "actor": alert.get("actor"),
        "mitre_attack": alert.get("mitre_attack"),
        "sources": alert.get("sources"),
        "kubernetes": alert.get("kubernetes"),
        "source_ips": alert.get("source_ips"),
        "description": alert.get("description"),
    }

    try:
        client = OpenAI(api_key=api_key)
        model = os.environ.get("TRIAGE_MODEL", "gpt-4o-mini")
        resp = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(facts)},
            ],
            temperature=0.2,
        )
        data = json.loads(resp.choices[0].message.content)
        return {
            "engine": f"llm:{model}",
            "summary": data.get("summary", ""),
            "why_it_matters": data.get("why_it_matters", ""),
            "recommended_actions": data.get("recommended_actions", ""),
        }
    except Exception:
        # Any API/parse error -> let the caller fall back. We never crash the
        # pipeline just because triage enrichment failed.
        return None


def triage_alert(alert: dict) -> dict:
    """Attach a `triage` block to one alert (LLM if available, else fallback)."""
    triage = _llm_triage(alert) or _fallback_triage(alert)
    return {**alert, "triage": triage}


def triage_alerts(alerts: list[dict]) -> list[dict]:
    """Enrich every alert with triage. Highest-priority alerts first (unchanged)."""
    return [triage_alert(a) for a in alerts]


def engine_in_use() -> str:
    """Report which triage engine will be used, for a friendly startup message."""
    if os.environ.get("OPENAI_API_KEY"):
        return "LLM (OPENAI_API_KEY detected)"
    return "rule-based fallback (set OPENAI_API_KEY for LLM triage)"
