"""Verification — turn an evidence bundle into a graded assessment.

Separate from collection on purpose: the thing that decides pass/fail should be able
to run somewhere the audited agent does not control, over a bundle it can check the
provenance of. ``verify_bundle`` maps observations onto control statuses, carries the
probe's own words across as the evidence note, and hands the result to the existing
assessment engine so a probed deployment is graded by exactly the same rules as a
hand-reviewed one.

``unknown`` observations deliberately do not become statuses. An unverifiable control
stays unreviewed, which costs completeness rather than silently earning credit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .assess import build_assessment
from .collect import read_bundle


def statuses_from(bundle: dict[str, Any]) -> tuple[dict[str, str], dict[str, str], dict[str, Any]]:
    """Reduce observations to (status, evidence, stats).

    One control can be observed by several probes. Conflicts resolve pessimistically:
    a single ``fail`` wins over any number of passes, because a control that is
    demonstrably not enforced somewhere is not enforced.
    """
    status: dict[str, str] = {}
    notes: dict[str, list[str]] = {}
    unknown_ids: list[str] = []
    conflicts: list[str] = []

    for obs in bundle.get("observations", []):
        cid = str(obs.get("control_id", "")).strip()
        state = obs.get("status")
        if not cid:
            continue
        detail = str(obs.get("detail", "")).strip()
        probe = str(obs.get("probe", "")).strip()
        line = f"[{probe or 'probe'}] {detail}" if detail else f"[{probe or 'probe'}] observed"
        notes.setdefault(cid, []).append(line)
        if state == "unknown":
            unknown_ids.append(cid)
            continue
        if state not in ("pass", "fail"):
            continue
        if cid in status and status[cid] != state:
            conflicts.append(cid)
            status[cid] = "fail"
        else:
            status[cid] = state

    evidence = {cid: " · ".join(lines) for cid, lines in notes.items()}
    stats = {
        "observed_controls": len(notes),
        "resolved": len(status),
        "unverifiable": sorted({cid for cid in unknown_ids if cid not in status}),
        "conflicts": sorted(set(conflicts)),
    }
    return status, evidence, stats


def verify_bundle(bundle: dict[str, Any], deployment: str | None = None) -> dict[str, Any]:
    """Grade an evidence bundle, carrying provenance into the assessment."""
    status, evidence, stats = statuses_from(bundle)
    assessment = build_assessment(
        status,
        evidence,
        deployment=deployment or bundle.get("deployment") or "unnamed-deployment",
    )
    provenance = dict(bundle.get("provenance") or {})
    assessment["evidence_source"] = {
        "schema": bundle.get("schema"),
        "collected_at": bundle.get("collected_at"),
        "collector": bundle.get("collector", {}),
        "targets": bundle.get("targets", []),
        "signed": bool((bundle.get("signature") or {}).get("signed")),
        "provenance": provenance,
        "stats": stats,
    }
    assessment["insights"] = _provenance_insights(provenance, stats, bundle) + assessment["insights"]
    return assessment


def _provenance_insights(
    provenance: dict[str, Any], stats: dict[str, Any], bundle: dict[str, Any]
) -> list[dict[str, str]]:
    """Findings about the evidence itself — these rank above findings about controls."""
    out: list[dict[str, str]] = []
    if provenance.get("self_attested"):
        out.append(
            {
                "severity": "critical",
                "title": "Evidence is self-attested, not independently collected",
                "detail": "This assessment grades evidence the audited party produced about "
                "itself: "
                + "; ".join(provenance.get("reasons", []))
                + ". A compromised or mistaken agent can report every control as enforced. "
                "Re-collect out of band — a sidecar, CI runner, or human operator with its own "
                "identity and signing key — before treating this grade as assurance.",
            }
        )
    if not (bundle.get("signature") or {}).get("signed"):
        out.append(
            {
                "severity": "low",
                "title": "Evidence bundle is unsigned",
                "detail": "Nothing binds these observations to the collector that produced them, "
                "so the bundle cannot be shown to be untampered. Pass --sign-cmd with a key the "
                "agent cannot reach.",
            }
        )
    unverifiable = stats.get("unverifiable") or []
    if unverifiable:
        out.append(
            {
                "severity": "high",
                "title": f"{len(unverifiable)} control(s) could not be verified automatically",
                "detail": "Probes ran but could not reach a verdict for "
                + ", ".join(unverifiable[:10])
                + ("…" if len(unverifiable) > 10 else "")
                + ". These are unreviewed, not passing — supply the missing privilege, run the "
                "collector on the right host, or review them by hand.",
            }
        )
    if stats.get("conflicts"):
        out.append(
            {
                "severity": "medium",
                "title": f"{len(stats['conflicts'])} control(s) had conflicting observations",
                "detail": "Different probes disagreed about "
                + ", ".join(stats["conflicts"])
                + "; each was resolved as a gap. Read both observations in the evidence note.",
            }
        )
    return out


def verify_file(path: Path, deployment: str | None = None) -> dict[str, Any]:
    """Read an evidence bundle from disk and grade it."""
    return verify_bundle(read_bundle(Path(path)), deployment=deployment)
