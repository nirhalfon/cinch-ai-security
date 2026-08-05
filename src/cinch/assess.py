"""Containment assessment engine — turns control statuses into a graded result.

An assessment *state* is just what a reviewer decided per control::

    {"deployment": "checkout-agent-prod",
     "status": {"AC-001": "pass", "AC-006": "fail", "AC-014": "na"},
     "evidence": {"AC-006": "retrieval output concatenated into system turn"}}

``build_assessment`` turns that into a result pack: weighted score, letter grade,
insights, ranked recommendations, and a phased action plan. The dashboard loads
the same pack (``data/assessment.json``) and re-derives it live in the browser as
controls are toggled; both sides read their rules from ``data/rubric.json`` so
the grade a reviewer sees and the grade CI gates on cannot drift apart.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .console import console_dir
from .loader import list_checklists, load_checklist

SCHEMA = "cinch-assessment/1"
STATUSES = ("pass", "fail", "na")
_GRADE_ORDER = ["A", "B", "C", "D", "F"]


# ── rubric ──────────────────────────────────────────────────────────────────


def load_rubric(path: Path | None = None) -> dict[str, Any]:
    """Load the scoring rubric shared with the dashboard."""
    path = path or console_dir() / "data" / "rubric.json"
    if not path.is_file():
        raise FileNotFoundError(f"rubric not found at {path}")
    return json.loads(path.read_text())


# ── catalog ─────────────────────────────────────────────────────────────────


def load_catalog() -> list[dict[str, Any]]:
    """Flatten every checklist into one list of control dicts."""
    controls: list[dict[str, Any]] = []
    for meta in list_checklists():
        name = meta["name"]
        if meta.get("error"):
            continue
        for item in load_checklist(name).items:
            layer = item.lasm_layer or ""
            controls.append(
                {
                    "id": item.id,
                    "checklist": name,
                    "threat": item.threat,
                    "control": item.control,
                    "severity": (item.severity or "medium").lower(),
                    "verification": item.verification,
                    "sources": list(item.sources),
                    "pillar": item.custody_pillar or "",
                    "layer": layer.split(" ")[0] if layer else "",
                    "layer_full": layer,
                    "category": item.category or "",
                }
            )
    return controls


# ── scoring ─────────────────────────────────────────────────────────────────


def _grade_for(score: int, critical_gaps: int, rubric: dict[str, Any]) -> dict[str, str]:
    """Map a score to a letter grade, then apply the critical-gap caps."""
    band = next(
        (b for b in rubric["grades"] if score >= b["min"]),
        rubric["grades"][-1],
    )
    grade, label, meaning, capped_by = band["grade"], band["label"], band["meaning"], ""
    for cap in rubric.get("grade_caps", []):
        if critical_gaps >= cap["min_critical_gaps"] and _GRADE_ORDER.index(
            cap["max_grade"]
        ) > _GRADE_ORDER.index(grade):
            grade, capped_by = cap["max_grade"], cap["reason"]
            cband = next(b for b in rubric["grades"] if b["grade"] == grade)
            label, meaning = cband["label"], cband["meaning"]
    return {"grade": grade, "label": label, "meaning": meaning, "capped_by": capped_by}


def _summary(controls, status, rubric) -> dict[str, Any]:
    weights = rubric["severity_weights"]

    def w(c):
        return weights.get(c["severity"], 1)
    scoped = [c for c in controls if status.get(c["id"]) in ("pass", "fail")]
    pass_w = sum(w(c) for c in scoped if status[c["id"]] == "pass")
    fail_w = sum(w(c) for c in scoped if status[c["id"]] == "fail")
    denom = pass_w + fail_w
    score = round(pass_w / denom * 100) if denom else 0
    gaps = [c for c in controls if status.get(c["id"]) == "fail"]
    critical_gaps = [c for c in gaps if c["severity"] == "critical"]
    na = [c for c in controls if status.get(c["id"]) == "na"]
    reviewed = len(scoped)
    applicable = len(controls) - len(na)
    summary = {
        "score": score,
        "reviewed": reviewed,
        "total": len(controls),
        "applicable": applicable,
        "not_applicable": len(na),
        "unreviewed": applicable - reviewed,
        "completeness": round(reviewed / applicable * 100) if applicable else 0,
        "enforced": sum(1 for c in scoped if status[c["id"]] == "pass"),
        "gaps": len(gaps),
        "critical_gaps": len(critical_gaps),
        "high_gaps": sum(1 for c in gaps if c["severity"] == "high"),
    }
    summary.update(_grade_for(score, len(critical_gaps), rubric))
    return summary


def _coverage(controls, status) -> dict[str, Any]:
    """Enforced/gap/reviewed counts grouped by checklist, CUSTODY pillar, LASM layer."""

    def group(key: str) -> list[dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for c in controls:
            k = c[key] or "unmapped"
            row = out.setdefault(k, {"name": k, "total": 0, "enforced": 0, "gaps": 0, "reviewed": 0})
            row["total"] += 1
            st = status.get(c["id"])
            if st == "pass":
                row["enforced"] += 1
            if st == "fail":
                row["gaps"] += 1
            if st in ("pass", "fail"):
                row["reviewed"] += 1
        for row in out.values():
            row["ratio"] = round(row["enforced"] / row["total"] * 100) if row["total"] else 0
        return sorted(out.values(), key=lambda r: r["name"])

    return {"checklists": group("checklist"), "custody": group("pillar"), "lasm": group("layer")}


def _insights(controls, status, evidence, summary, coverage, rubric) -> list[dict[str, str]]:
    """Rule-based findings about the assessment as a whole, worst first."""
    out: list[dict[str, str]] = []
    gaps = [c for c in controls if status.get(c["id"]) == "fail"]
    crit = [c for c in gaps if c["severity"] == "critical"]

    if crit:
        out.append(
            {
                "severity": "critical",
                "title": f"{len(crit)} critical containment control"
                f"{'s' if len(crit) != 1 else ''} unenforced",
                "detail": "Until these are closed, a single manipulated or mistaken model "
                "decision can reach production systems: "
                + ", ".join(c["id"] for c in crit[:8])
                + ("…" if len(crit) > 8 else "")
                + ".",
            }
        )
    elif summary["reviewed"]:
        out.append(
            {
                "severity": "ok",
                "title": "No critical gaps in the reviewed scope",
                "detail": "Every critical control reviewed so far is enforced. Keep it that way "
                "by re-running the assessment on each material change to the deployment.",
            }
        )

    floor = rubric.get("completeness_floor", 0.6) * 100
    if summary["completeness"] < floor:
        out.append(
            {
                "severity": "high",
                "title": f"Assessment is {summary['completeness']}% complete",
                "detail": f"The {summary['score']}% score only covers {summary['reviewed']} of "
                f"{summary['applicable']} applicable controls. Unreviewed controls are unknown "
                "risk, not accepted risk.",
            }
        )

    weakest = [
        p
        for p in coverage["custody"]
        if p["name"] != "unmapped" and p["gaps"] and p["total"]
    ]
    if weakest:
        w = min(weakest, key=lambda p: (p["ratio"], p["name"]))
        out.append(
            {
                "severity": "high",
                "title": f"Weakest CUSTODY pillar: {w['name']} ({w['enforced']}/{w['total']} enforced)",
                "detail": f"{w['gaps']} gap{'s' if w['gaps'] != 1 else ''} "
                f"{'concentrate' if w['gaps'] != 1 else 'sits'} in this "
                "pillar. Capability accretion is pillar-shaped: an agent that is contained "
                "everywhere else still inherits authority through the weak one.",
            }
        )

    layered = [
        row for row in coverage["lasm"] if row["name"] not in ("unmapped", "") and row["gaps"]
    ]
    if layered:
        top = max(layered, key=lambda r: (r["gaps"], r["name"]))
        if top["gaps"] > 1:
            out.append(
                {
                    "severity": "medium",
                    "title": f"Gaps cluster at LASM layer {top['name']} ({top['gaps']} open)",
                    "detail": "A control at another layer will not detect an attack at this one. "
                    "Clustered gaps mean this layer currently has no depth.",
                }
            )

    not_started = [c for c in coverage["checklists"] if c["reviewed"] == 0]
    if not_started:
        out.append(
            {
                "severity": "medium",
                "title": f"{len(not_started)} checklist"
                f"{'s' if len(not_started) != 1 else ''} not started",
                "detail": "No control reviewed in: "
                + ", ".join(c["name"] for c in not_started)
                + ". The score says nothing about these areas.",
            }
        )

    undocumented = [c["id"] for c in gaps if not (evidence.get(c["id"]) or "").strip()]
    if undocumented:
        out.append(
            {
                "severity": "low",
                "title": f"{len(undocumented)} gap"
                f"{'s' if len(undocumented) != 1 else ''} without evidence notes",
                "detail": "A gap with no note is not auditable and will not survive handover: "
                + ", ".join(undocumented[:8])
                + ("…" if len(undocumented) > 8 else "")
                + ".",
            }
        )
    return out


def _recommendations(controls, status, evidence, rubric) -> list[dict[str, Any]]:
    """One ranked recommendation per open gap, worst severity first."""
    weights = rubric["severity_weights"]
    phase_of = {
        sev: name
        for name, spec in rubric["phases"].items()
        for sev in spec["severities"]
    }
    gaps = [c for c in controls if status.get(c["id"]) == "fail"]
    gaps.sort(key=lambda c: (-weights.get(c["severity"], 1), c["id"]))
    return [
        {
            "rank": i,
            "id": c["id"],
            "checklist": c["checklist"],
            "severity": c["severity"],
            "phase": phase_of.get(c["severity"], "later"),
            "threat": c["threat"],
            "action": c["control"],
            "verification": c["verification"],
            "pillar": c["pillar"],
            "layer": c["layer_full"] or c["layer"],
            "frameworks": c["sources"],
            "evidence": evidence.get(c["id"], ""),
        }
        for i, c in enumerate(gaps, start=1)
    ]


def _action_plan(recommendations, summary, rubric) -> list[dict[str, Any]]:
    """Group the recommendations into the rubric's remediation phases."""
    plan = []
    for name, spec in rubric["phases"].items():
        items = [r for r in recommendations if r["phase"] == name]
        plan.append(
            {
                "phase": name,
                "window": spec["window"],
                "goal": spec["goal"],
                "exit_criterion": spec["exit"],
                "control_ids": [r["id"] for r in items],
                "count": len(items),
            }
        )
    if summary["unreviewed"]:
        plan.append(
            {
                "phase": "complete-the-assessment",
                "window": "before sign-off",
                "goal": f"Review the remaining {summary['unreviewed']} applicable controls.",
                "exit_criterion": "Completeness at 100%; every control enforced, a gap, or "
                "explicitly not applicable.",
                "control_ids": [],
                "count": summary["unreviewed"],
            }
        )
    return plan


def build_assessment(
    status: dict[str, str],
    evidence: dict[str, str] | None = None,
    deployment: str = "unnamed-deployment",
    controls: list[dict[str, Any]] | None = None,
    rubric: dict[str, Any] | None = None,
    generated: str | None = None,
) -> dict[str, Any]:
    """Build a full assessment result pack from per-control statuses."""
    controls = controls if controls is not None else load_catalog()
    rubric = rubric or load_rubric()
    evidence = evidence or {}
    known = {c["id"] for c in controls}
    unknown = sorted(set(status) - known)
    status = {k: v for k, v in status.items() if k in known and v in STATUSES}

    summary = _summary(controls, status, rubric)
    coverage = _coverage(controls, status)
    recommendations = _recommendations(controls, status, evidence, rubric)
    return {
        "schema": SCHEMA,
        "generated": generated or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "deployment": deployment,
        "summary": summary,
        "coverage": coverage,
        "insights": _insights(controls, status, evidence, summary, coverage, rubric),
        "recommendations": recommendations,
        "action_plan": _action_plan(recommendations, summary, rubric),
        "unknown_control_ids": unknown,
        "results": [
            {
                "id": c["id"],
                "checklist": c["checklist"],
                "severity": c["severity"],
                "status": status.get(c["id"]) or "unreviewed",
                "evidence": evidence.get(c["id"], ""),
            }
            for c in controls
        ],
    }


# ── state input ─────────────────────────────────────────────────────────────


def read_state(path: Path) -> tuple[dict[str, str], dict[str, str], str]:
    """Read an assessment state file, or re-read a previously exported pack.

    Accepts either ``{"status": {...}, "evidence": {...}}`` or an exported
    assessment (``{"results": [{"id", "status", "evidence"}, ...]}``) so a saved
    report round-trips back into a new assessment.
    """
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise TypeError(f"{path}: expected a JSON object")
    deployment = raw.get("deployment") or "unnamed-deployment"
    if isinstance(raw.get("status"), dict):
        status = {str(k): str(v) for k, v in raw["status"].items()}
        evidence = {str(k): str(v) for k, v in (raw.get("evidence") or {}).items()}
        return status, evidence, deployment
    if isinstance(raw.get("results"), list):
        status, evidence = {}, {}
        for row in raw["results"]:
            if not isinstance(row, dict) or "id" not in row:
                continue
            if row.get("status") in STATUSES:
                status[str(row["id"])] = str(row["status"])
            if row.get("evidence"):
                evidence[str(row["id"])] = str(row["evidence"])
        return status, evidence, deployment
    raise ValueError(
        f"{path}: no assessment found — expected a 'status' object or a 'results' array"
    )


# ── text report ─────────────────────────────────────────────────────────────


def format_report(assessment: dict[str, Any], max_recommendations: int = 10) -> str:
    """Render a terminal summary of an assessment pack."""
    s = assessment["summary"]
    lines = [
        f"Cinch containment assessment — {assessment['deployment']}",
        (
            f"  Grade {s['grade']} ({s['label']})  ·  score {s['score']}%  ·  "
            f"{s['reviewed']}/{s['applicable']} applicable controls reviewed"
        ),
        (
            f"  {s['gaps']} open gaps ({s['critical_gaps']} critical, {s['high_gaps']} high)"
            f"  ·  {s['unreviewed']} unreviewed"
        ),
    ]
    if s["capped_by"]:
        lines.append(f"  Grade capped: {s['capped_by']}")
    lines.append("")
    lines.append("Insights")
    for i in assessment["insights"]:
        lines.append(f"  [{i['severity']}] {i['title']}")
        lines.append(f"      {i['detail']}")
    recs = assessment["recommendations"]
    if recs:
        lines.append("")
        lines.append(f"Recommendations ({len(recs)} total, top {min(len(recs), max_recommendations)})")
        for r in recs[: max_recommendations]:
            lines.append(f"  {r['rank']}. [{r['severity']}] {r['id']} — {r['threat']}")
            lines.append(f"      Do: {r['action']}")
            lines.append(f"      Verify: {r['verification']}")
    lines.append("")
    lines.append("Action plan")
    for phase in assessment["action_plan"]:
        ids = ", ".join(phase["control_ids"]) or "—"
        lines.append(f"  {phase['phase'].upper()} ({phase['window']}) — {phase['count']} item(s)")
        lines.append(f"      {phase['goal']}")
        lines.append(f"      Controls: {ids}")
        lines.append(f"      Exit: {phase['exit_criterion']}")
    return "\n".join(lines)
