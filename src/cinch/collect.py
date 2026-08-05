"""Evidence collection — run probes against a running agent, emit a signed bundle.

Implements ``protocols/evidence-collect.md``: the collector records *who collected
what, where and when*, and every observation keeps the raw evidence it was derived
from, so an external reviewer can check the reasoning rather than trust it.

The protocol's core requirement is separation of duties — an agent auditing its own
host is a self-audit, and a compromised or simply wrong agent can mark everything
"pass". Cinch cannot prevent that when collection is invoked by an agent, so it does
the next best thing: it *detects and records* it. ``self_attested: true`` propagates
into the assessment as a finding, and independence is never assumed.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import shutil
import socket
import subprocess  # nosec B404
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .probes import Observation
from .probes import behaviour as behaviour_probes
from .probes import host as host_probes
from .probes import project as project_probes

SCHEMA = "cinch-evidence/1"
KINDS = ("host", "project", "behaviour")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collector_identity(via_mcp: bool = False) -> dict[str, Any]:
    """Record who is collecting. The audited agent must not be this identity."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError):  # no passwd entry (common in containers)
        user = f"uid:{os.getuid()}" if hasattr(os, "getuid") else "unknown"
    return {
        "user": user,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "invoked_via_mcp": via_mcp,
        "tool": "cinch",
    }


def _self_attestation(collector: dict[str, Any], targets: list[dict[str, Any]]) -> dict[str, Any]:
    """Decide whether this bundle is independent evidence or self-attestation."""
    reasons = []
    if collector["invoked_via_mcp"]:
        reasons.append(
            "collection was invoked through the MCP server, so the requester is an agent rather "
            "than an out-of-band operator"
        )
    for t in targets:
        if t.get("kind") == "host" and t.get("pid") == collector["pid"]:
            reasons.append(
                "the inspected process is the collector's own process — it is describing itself"
            )
        if t.get("kind") == "host" and t.get("resolved_by", "").startswith("collector process"):
            reasons.append("no target PID was given, so the collector inspected itself")
    unique = list(dict.fromkeys(reasons))
    return {
        "self_attested": bool(unique),
        "reasons": unique,
        "independent": not unique,
        "requirement": "protocols/evidence-collect.md — the collector must run as an identity "
        "independent of the agent (sidecar, CI runner, or human operator).",
    }


def sign_bundle(bundle: dict[str, Any], sign_cmd: list[str] | None) -> dict[str, Any] | None:
    """Sign the canonical bundle bytes with an operator-supplied command.

    ``sign_cmd`` receives the canonical JSON on stdin and must print a detached
    signature on stdout, e.g. ``["ssh-keygen", "-Y", "sign", "-f", "key", "-n", "cinch"]``
    or ``["cosign", "sign-blob", "-"]``. The signing key must not be reachable by the
    agent — that is what makes the signature meaningful.
    """
    if not sign_cmd:
        return None
    if not shutil.which(sign_cmd[0]):
        return {"error": f"signing command not found: {sign_cmd[0]}", "signed": False}
    payload = canonical_bytes(bundle)
    try:
        # argv comes from the operator's --sign-cmd, never from an agent.
        out = subprocess.run(  # nosec B603
            sign_cmd, input=payload, capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"error": f"signing failed: {exc}", "signed": False}
    if out.returncode != 0:
        return {
            "error": f"signing command exited {out.returncode}: "
            f"{out.stderr.decode(errors='replace')[:200]}",
            "signed": False,
        }
    return {
        "signed": True,
        "command": sign_cmd[0],
        "signature": out.stdout.decode(errors="replace").strip(),
        "over": "canonical JSON of the bundle with 'signature' removed",
    }


def canonical_bytes(bundle: dict[str, Any]) -> bytes:
    """Deterministic bytes a signature is computed over (bundle minus the signature)."""
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def collect(
    kinds: tuple[str, ...] = ("host",),
    pid: int | None = None,
    unit: str | None = None,
    project_path: Path | None = None,
    endpoint: str | None = None,
    authorized: bool = False,
    deployment: str = "unnamed-deployment",
    via_mcp: bool = False,
    sign_cmd: list[str] | None = None,
    request_field: str = "input",
    response_field: str = "output",
) -> dict[str, Any]:
    """Run the requested probe families and return an evidence bundle."""
    unsupported = [k for k in kinds if k not in KINDS]
    if unsupported:
        raise ValueError(f"unknown probe kind(s): {', '.join(unsupported)}; expected {KINDS}")

    collector = collector_identity(via_mcp=via_mcp)
    observations: list[Observation] = []
    targets: list[dict[str, Any]] = []
    notes: list[str] = []

    if "host" in kinds:
        obs, target = host_probes.collect(pid=pid, unit=unit)
        observations += obs
        targets.append(target)
    if "project" in kinds:
        path = project_path or Path.cwd()
        obs, target = project_probes.collect(Path(path))
        if not target["exists"]:
            notes.append(f"project path does not exist: {path}")
        observations += obs
        targets.append(target)
    if "behaviour" in kinds:
        if not endpoint:
            raise ValueError("behavioural probing needs an endpoint URL")
        obs, target = behaviour_probes.collect(
            endpoint,
            authorized=authorized,
            request_field=request_field,
            response_field=response_field,
        )
        observations += obs
        targets.append(target)

    observations += derive_related(observations)

    bundle = {
        "schema": SCHEMA,
        "collected_at": _now(),
        "deployment": deployment,
        "collector": collector,
        "targets": targets,
        "provenance": _self_attestation(collector, targets),
        "notes": notes,
        "counts": _counts(observations),
        "observations": [o.as_dict() for o in observations],
    }
    signature = sign_bundle(bundle, sign_cmd)
    if signature is not None:
        bundle["signature"] = signature
    return bundle


def _counts(observations: list[Observation]) -> dict[str, int]:
    # Keys are probe verdicts, not credentials.
    counts: dict[str, int] = dict.fromkeys(("pass", "fail", "unknown"), 0)
    for o in observations:
        counts[o.status] = counts.get(o.status, 0) + 1
    counts["controls"] = len({o.control_id for o in observations})
    return counts


# Host findings are direct evidence for containment controls that say the same thing
# in AC language. Derived observations are labelled so the chain stays visible.
DERIVATIONS = {
    "AE-001": ("AC-018", "privilege boundary of the agent process"),
    "AE-005": ("AC-019", "egress control on the agent's network path"),
    "AE-006": ("AC-020", "reachability of neighbouring services and the metadata API"),
    "AE-007": ("AC-013", "tamper-evidence of the audit trail"),
    "AE-008": ("AC-016", "credential material in the agent's environment"),
    "AE-010": ("AC-023", "persistence of agent-made changes"),
    "AE-011": ("AC-017", "resource bounds on a runaway loop"),
}


def derive_related(observations: list[Observation]) -> list[Observation]:
    """Map host observations onto the containment controls that assert the same thing."""
    have = {o.control_id for o in observations}
    derived: list[Observation] = []
    for o in observations:
        mapping = DERIVATIONS.get(o.control_id)
        if not mapping:
            continue
        target_id, what = mapping
        if target_id in have:
            continue  # a direct observation already covers it — never overwrite
        have.add(target_id)
        derived.append(
            Observation(
                control_id=target_id,
                status=o.status,
                detail=f"Derived from {o.control_id} ({what}): {o.detail}",
                probe=f"derived:{o.probe or o.control_id}",
                raw={"derived_from": o.control_id, **o.raw},
            )
        )
    return derived


def read_bundle(path: Path) -> dict[str, Any]:
    """Load an evidence bundle and check it is one."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise TypeError(f"{path}: expected a JSON object")
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not a {SCHEMA} bundle (schema={data.get('schema')!r})")
    if not isinstance(data.get("observations"), list):
        raise TypeError(f"{path}: bundle has no observations array")
    return data
