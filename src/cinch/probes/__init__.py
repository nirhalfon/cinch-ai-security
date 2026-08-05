"""Probes — read-only checks that turn a real deployment into control evidence.

A probe observes something about a running agent's environment (its host, the
project it runs from, or its behaviour when pushed) and reports what it saw
against one or more checklist controls. Probes never mutate the target.

Three statuses, and the difference matters:

``pass``    the control is demonstrably enforced — the observation proves it.
``fail``    the control is demonstrably not enforced.
``unknown`` the probe could not tell (wrong OS, missing privilege, tool absent).
            Unknown is *not* a pass: it leaves the control unreviewed so it shows
            up as missing completeness rather than as satisfied.

Each observation carries the raw evidence it was derived from, so a human or a
separate auditing agent can check the probe's reasoning instead of trusting it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Probe verdicts. Not credentials — bandit's B105 heuristic sees the word "pass".
PASS = "pass"  # nosec B105
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class Observation:
    """One probe's finding about one control."""

    control_id: str
    status: str
    detail: str
    probe: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "detail": self.detail,
            "probe": self.probe,
            "raw": self.raw,
        }


# Probe registry, keyed by target kind ("host", "project", "behaviour").
_REGISTRY: dict[str, list[Callable]] = {}


def probe(kind: str, *control_ids: str) -> Callable:
    """Register a probe function for a target kind and the controls it covers."""

    def wrap(fn: Callable) -> Callable:
        fn.control_ids = control_ids
        fn.probe_name = fn.__name__
        _REGISTRY.setdefault(kind, []).append(fn)
        return fn

    return wrap


def probes_for(kind: str) -> list[Callable]:
    """Return the registered probes for a target kind, in registration order."""
    return list(_REGISTRY.get(kind, []))


def unknown(control_id: str, detail: str, probe_name: str = "", **raw) -> Observation:
    """Build an ``unknown`` observation — the honest answer when a probe can't tell."""
    return Observation(control_id, UNKNOWN, detail, probe_name, raw)


def verdict(control_id: str, ok: bool, detail: str, probe_name: str = "", **raw) -> Observation:
    """Build a pass/fail observation."""
    return Observation(control_id, PASS if ok else FAIL, detail, probe_name, raw)
