"""
The common event schema.

Every source (CloudTrail, Falco, etc.) produces events in its own format.
Rather than writing detections for each raw format, we map every raw event
into ONE normalized shape -- the `NormalizedEvent` below.

This is the single most important idea in a detection pipeline:
detections operate on the normalized schema, not on raw source formats.
Add a new source later? You only write a new normalizer -- every existing
detection keeps working unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class NormalizedEvent:
    """A single security event, normalized into a source-agnostic shape."""

    # --- core fields every event has ---
    source: str                 # where it came from, e.g. "cloudtrail" or "falco"
    timestamp: datetime         # when the event happened (UTC)
    action: str                 # what happened, e.g. "ConsoleLogin", "CreateAccessKey"

    # --- identity: who did it ---
    actor: str = "unknown"      # user / principal / identity
    actor_type: str = "unknown" # e.g. "IAMUser", "Root", "AssumedRole"

    # --- context: where / how ---
    source_ip: str | None = None
    region: str | None = None
    outcome: str | None = None  # "success" / "failure" when known

    # --- Kubernetes / runtime context (populated by runtime sources like Falco) ---
    # Cloud-audit sources (CloudTrail) leave these None; runtime sources fill them in.
    # Detections stay source-agnostic, but alerts can surface K8s context when present.
    container: str | None = None   # container name, e.g. "web-frontend"
    namespace: str | None = None   # k8s namespace, e.g. "production"
    pod: str | None = None         # k8s pod name
    process: str | None = None     # the process/command involved, e.g. "bash", "nc ..."

    # --- the raw event, kept for investigation ---
    raw: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Convenience accessor into the raw event for detection rules."""
        return self.raw.get(key, default)
