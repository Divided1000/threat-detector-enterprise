"""
Detection engine.

A detection is a function that looks at the stream of NormalizedEvents and
returns zero or more `Finding`s. Each detection is mapped to a MITRE ATT&CK
technique, which is how real detection engineering is organized: you reason
about adversary behavior (techniques), not just raw log lines.

Design notes you can speak to in an interview:
  - Detections operate on the COMMON SCHEMA, so they're source-agnostic.
  - Each rule declares its ATT&CK technique and a base severity.
  - Stateful rules (like brute force) aggregate across many events;
    stateless rules fire on a single event. We support both.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable

from .schema import NormalizedEvent


@dataclass
class Finding:
    """One thing a detection decided is suspicious."""

    rule_id: str
    title: str
    severity: str                       # "low" | "medium" | "high" | "critical"
    attack_technique: str               # e.g. "T1110"
    attack_name: str                    # e.g. "Brute Force"
    description: str
    actor: str
    events: list[NormalizedEvent] = field(default_factory=list)  # evidence


# ---------------------------------------------------------------------------
# Individual detection rules
# Each takes the full list of events and returns a list of Findings.
# ---------------------------------------------------------------------------

# How many failed logins, within what window, counts as a brute-force attempt.
BRUTE_FORCE_THRESHOLD = 4
BRUTE_FORCE_WINDOW = timedelta(minutes=5)


def detect_brute_force(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1110 - Brute Force.
    Fire when a single actor has >= THRESHOLD failed ConsoleLogins inside a
    sliding time window. This is a STATEFUL rule: it aggregates many events.
    """
    findings: list[Finding] = []
    # group failed logins per actor
    failures_by_actor: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.action == "ConsoleLogin" and e.outcome == "failure":
            failures_by_actor[e.actor].append(e)

    for actor, failures in failures_by_actor.items():
        failures.sort(key=lambda e: e.timestamp)
        # sliding window: is any run of THRESHOLD failures within WINDOW?
        for i in range(len(failures)):
            window = [
                f for f in failures[i:]
                if f.timestamp - failures[i].timestamp <= BRUTE_FORCE_WINDOW
            ]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="BRUTE_FORCE_LOGIN",
                        title=f"Brute-force login attempts against '{actor}'",
                        severity="high",
                        attack_technique="T1110",
                        attack_name="Brute Force",
                        description=(
                            f"{len(window)} failed console logins for '{actor}' "
                            f"within {int(BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes "
                            f"from IP {window[0].source_ip}."
                        ),
                        actor=actor,
                        events=window,
                    )
                )
                break  # one finding per actor is enough
    return findings


def detect_root_usage(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1078.004 - Valid Accounts: Cloud Accounts (root).
    Root should almost never be used directly. Any root activity is noteworthy;
    a successful root console login is high severity.
    """
    findings: list[Finding] = []
    for e in events:
        if e.actor_type == "Root" and e.action == "ConsoleLogin" and e.outcome == "success":
            findings.append(
                Finding(
                    rule_id="ROOT_CONSOLE_LOGIN",
                    title="Root account console login",
                    severity="high",
                    attack_technique="T1078.004",
                    attack_name="Valid Accounts: Cloud Accounts",
                    description=(
                        f"Root account logged in to the console from {e.source_ip}. "
                        "Root should be locked away and almost never used interactively."
                    ),
                    actor="root",
                    events=[e],
                )
            )
    return findings


def detect_iam_privilege_escalation(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1098 - Account Manipulation.
    Attaching admin-like policies to a user is a classic privilege-escalation /
    persistence move. We flag PutUserPolicy / AttachUserPolicy.
    """
    findings: list[Finding] = []
    for e in events:
        if e.action in ("PutUserPolicy", "AttachUserPolicy"):
            params = e.get("requestParameters", {}) or {}
            target = params.get("userName", "unknown")
            policy = params.get("policyName") or params.get("policyArn", "unknown")
            findings.append(
                Finding(
                    rule_id="IAM_POLICY_CHANGE",
                    title=f"IAM policy attached to user '{target}'",
                    severity="critical",
                    attack_technique="T1098",
                    attack_name="Account Manipulation",
                    description=(
                        f"{e.actor} ({e.actor_type}) attached policy '{policy}' to "
                        f"user '{target}'. Possible privilege escalation or persistence."
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


def detect_access_key_creation(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1098 - Account Manipulation (persistence via long-lived credentials).
    Creating an access key for a user establishes durable programmatic access.
    Suspicious especially when done by root or right after a policy change.
    """
    findings: list[Finding] = []
    for e in events:
        if e.action == "CreateAccessKey":
            params = e.get("requestParameters", {}) or {}
            target = params.get("userName", "unknown")
            severity = "critical" if e.actor_type == "Root" else "medium"
            findings.append(
                Finding(
                    rule_id="ACCESS_KEY_CREATED",
                    title=f"Access key created for user '{target}'",
                    severity=severity,
                    attack_technique="T1098",
                    attack_name="Account Manipulation",
                    description=(
                        f"{e.actor} ({e.actor_type}) created a long-lived access key for "
                        f"'{target}'. Long-lived keys are a common persistence mechanism."
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Runtime (Falco / Kubernetes) detection rules.
#
# These reason about the SAME NormalizedEvent schema as the CloudTrail rules.
# They just happen to key off runtime signals (process, container) that only
# Falco populates. A CloudTrail event has container=None, so these naturally
# never fire on it -- no source checks needed.
# ---------------------------------------------------------------------------

def _k8s_where(e: NormalizedEvent) -> str:
    """Human-readable 'where did this happen' for container events."""
    parts = []
    if e.container:
        parts.append(f"container '{e.container}'")
    if e.pod:
        parts.append(f"pod '{e.pod}'")
    if e.namespace:
        parts.append(f"namespace '{e.namespace}'")
    return ", ".join(parts) if parts else "an unknown location"


def detect_shell_in_container(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1059 - Command and Scripting Interpreter.
    An interactive shell spawned inside a running container is a strong signal
    of hands-on-keyboard activity -- containers should run their app, not a shell.
    """
    findings: list[Finding] = []
    for e in events:
        if e.source == "falco" and "shell" in e.action.lower():
            findings.append(
                Finding(
                    rule_id="K8S_SHELL_IN_CONTAINER",
                    title=f"Shell spawned in {e.container or 'container'}",
                    severity="high",
                    attack_technique="T1059",
                    attack_name="Command and Scripting Interpreter",
                    description=(
                        f"A shell ('{e.process}') was spawned inside {_k8s_where(e)} "
                        f"as user '{e.actor}'. Interactive shells in containers often "
                        "indicate hands-on-keyboard intrusion."
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


def detect_sensitive_file_read(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1552.001 - Unsecured Credentials: Credentials In Files.
    Reading files like /etc/shadow or /proc/self/environ from inside a container
    is a classic credential-access move.
    """
    SENSITIVE = ("/etc/shadow", "/etc/passwd", "/proc/self/environ", "id_rsa", ".aws/credentials")
    findings: list[Finding] = []
    for e in events:
        if e.source != "falco":
            continue
        target = (e.get("output_fields", {}) or {}).get("fd.name", "")
        if target and any(s in target for s in SENSITIVE):
            findings.append(
                Finding(
                    rule_id="K8S_SENSITIVE_FILE_READ",
                    title=f"Sensitive file read in {e.container or 'container'}",
                    severity="high",
                    attack_technique="T1552.001",
                    attack_name="Unsecured Credentials: Credentials In Files",
                    description=(
                        f"Process '{e.process}' read sensitive file '{target}' in "
                        f"{_k8s_where(e)} as user '{e.actor}'. Possible credential access."
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


def detect_package_mgmt_in_container(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1105 - Ingress Tool Transfer.
    Rationale: a package manager in a running container fetches binaries from an
    external repo into the workload at runtime -- i.e. transferring new tools
    into the environment, which is what T1105 describes. Containers are meant to
    be immutable, so this is both anomalous and a common precursor to installing
    attacker tooling (netcat, nmap, etc.).
    """
    PKG_MGRS = ("apt-get", "apt", "yum", "dnf", "apk", "pip", "pip3", "npm")
    findings: list[Finding] = []
    for e in events:
        if e.source != "falco":
            continue
        proc_name = (e.get("output_fields", {}) or {}).get("proc.name", "")
        if proc_name in PKG_MGRS:
            findings.append(
                Finding(
                    rule_id="K8S_PACKAGE_MGMT",
                    title=f"Package manager run in {e.container or 'container'}",
                    severity="medium",
                    attack_technique="T1105",
                    attack_name="Ingress Tool Transfer",
                    description=(
                        f"Package manager '{e.process}' ran inside {_k8s_where(e)}. "
                        "Running containers should be immutable; this often precedes "
                        "installing attacker tooling."
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


def detect_write_below_etc(events: list[NormalizedEvent]) -> list[Finding]:
    """
    T1543.003 / T1053 - Persistence via system files (e.g. cron, init).
    Writing under /etc inside a container -- especially /etc/cron.* -- is a
    persistence mechanism. We flag writes below /etc.
    """
    findings: list[Finding] = []
    for e in events:
        if e.source != "falco":
            continue
        # Only treat this as a WRITE when Falco's rule is about writing -- otherwise
        # a "Read sensitive file" event (fd.name=/etc/shadow) would misfire here.
        if "write" not in e.action.lower():
            continue
        target = (e.get("output_fields", {}) or {}).get("fd.name", "")
        if target.startswith("/etc/"):
            is_cron = "cron" in target
            findings.append(
                Finding(
                    rule_id="K8S_WRITE_BELOW_ETC",
                    title=f"Write below /etc in {e.container or 'container'}",
                    severity="critical" if is_cron else "high",
                    attack_technique="T1053.003" if is_cron else "T1222",
                    attack_name="Scheduled Task/Job: Cron" if is_cron else "File and Directory Permissions Modification",
                    description=(
                        f"Process '{e.process}' wrote to '{target}' in {_k8s_where(e)}. "
                        + ("Writing to cron is a classic persistence backdoor." if is_cron
                           else "Writes under /etc in a running container are suspicious.")
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


def detect_suspicious_outbound(events: list[NormalizedEvent]) -> list[Finding]:
    """
    Unexpected egress from a container.

    ATT&CK mapping (chosen for the *connection*, not the shell):
      - Reverse shell (nc -e, bash -i, /dev/tcp) => T1572 Protocol Tunneling.
        The attacker tunnels an interactive session out over a network socket to
        a C2 host; T1572 describes exactly this channel. (The shell interpreter
        itself is T1059, already covered by the shell-in-container rule, so we
        map this rule to the network behavior to avoid double-counting T1059.)
      - Other unexpected egress => T1071 Application Layer Protocol, the generic
        "attacker communicates outbound over a standard protocol" technique.
    """
    findings: list[Finding] = []
    for e in events:
        if e.source != "falco":
            continue
        cmd = (e.process or "").lower()
        looks_like_revshell = (
            ("nc " in cmd or cmd.startswith("nc")) and "-e" in cmd
        ) or ("bash -i" in cmd) or ("/dev/tcp/" in cmd)
        if "outbound" in e.action.lower() or looks_like_revshell:
            dst = (e.get("output_fields", {}) or {}).get("fd.sip")
            findings.append(
                Finding(
                    rule_id="K8S_SUSPICIOUS_OUTBOUND",
                    title=f"Suspicious outbound connection from {e.container or 'container'}",
                    severity="critical" if looks_like_revshell else "high",
                    attack_technique="T1572" if looks_like_revshell else "T1071",
                    attack_name="Protocol Tunneling" if looks_like_revshell else "Application Layer Protocol",
                    description=(
                        f"Process '{e.process}' opened an outbound connection"
                        + (f" to {dst}" if dst else "")
                        + f" from {_k8s_where(e)}. "
                        + ("Command pattern matches a reverse shell (interactive session "
                           "tunneled out to a C2 host)." if looks_like_revshell
                           else "Unexpected egress from a container.")
                    ),
                    actor=e.actor,
                    events=[e],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# The registry: every rule the engine runs.
# Adding a new detection = write a function and add it here.
# ---------------------------------------------------------------------------

ALL_DETECTIONS: list[Callable[[list[NormalizedEvent]], list[Finding]]] = [
    # cloud-audit (CloudTrail) rules
    detect_brute_force,
    detect_root_usage,
    detect_iam_privilege_escalation,
    detect_access_key_creation,
    # runtime (Falco / Kubernetes) rules
    detect_shell_in_container,
    detect_sensitive_file_read,
    detect_package_mgmt_in_container,
    detect_write_below_etc,
    detect_suspicious_outbound,
]


def run_detections(events: list[NormalizedEvent]) -> list[Finding]:
    """Run every registered detection over the events and collect all findings."""
    findings: list[Finding] = []
    for detection in ALL_DETECTIONS:
        findings.extend(detection(events))
    return findings
