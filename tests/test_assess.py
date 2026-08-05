"""Tests for the containment assessment engine.

The dashboard renders whatever this engine produces, and CI can gate on it, so the
grade rules, the critical-gap caps, the insight triggers and the phase mapping are
all pinned here.
"""

from __future__ import annotations

import json

import pytest

from cinch.assess import (
    build_assessment,
    format_report,
    load_catalog,
    load_rubric,
    read_state,
)
from cinch.server import _gate, main

CATALOG = load_catalog()
RUBRIC = load_rubric()
BY_SEV = {}
for _c in CATALOG:
    BY_SEV.setdefault(_c["severity"], []).append(_c["id"])


def build(status, evidence=None, **kw):
    return build_assessment(
        status, evidence, controls=CATALOG, rubric=RUBRIC, generated="test", **kw
    )


# ── catalog ─────────────────────────────────────────────────────────────────


def test_catalog_matches_the_published_checklists():
    assert len(CATALOG) == 117
    assert len({c["checklist"] for c in CATALOG}) == 6
    assert all(c["id"] and c["control"] and c["verification"] for c in CATALOG)


# ── scoring and grading ─────────────────────────────────────────────────────


def test_all_enforced_scores_100_and_grades_a():
    a = build({c["id"]: "pass" for c in CATALOG})
    assert a["summary"]["score"] == 100
    assert a["summary"]["grade"] == "A"
    assert a["summary"]["gaps"] == 0
    assert a["recommendations"] == []


def test_score_is_severity_weighted():
    """One critical gap costs 3 points of weight; one low/medium gap costs 1."""
    crit, medium = BY_SEV["critical"][0], BY_SEV["medium"][0]
    heavy = build({crit: "fail", medium: "pass"})["summary"]["score"]
    light = build({crit: "pass", medium: "fail"})["summary"]["score"]
    assert heavy < light


def test_unreviewed_controls_do_not_dilute_the_score_but_hit_completeness():
    a = build({BY_SEV["critical"][0]: "pass"})
    assert a["summary"]["score"] == 100
    assert a["summary"]["completeness"] == 1  # 1 of 116 applicable
    assert any("complete" in i["title"] for i in a["insights"])


def test_na_controls_leave_the_applicable_denominator():
    a = build({c["id"]: "na" for c in CATALOG})
    assert a["summary"]["applicable"] == 0
    assert a["summary"]["not_applicable"] == 117
    assert a["summary"]["score"] == 0


def test_one_critical_gap_caps_the_grade_at_d():
    """A high score cannot outvote an unenforced critical control."""
    status = {c["id"]: "pass" for c in CATALOG}
    status[BY_SEV["critical"][0]] = "fail"
    s = build(status)["summary"]
    assert s["score"] >= 90
    assert s["grade"] == "D"
    assert "caps the grade" in s["capped_by"]


def test_three_critical_gaps_cap_the_grade_at_f():
    status = {c["id"]: "pass" for c in CATALOG}
    for cid in BY_SEV["critical"][:3]:
        status[cid] = "fail"
    s = build(status)["summary"]
    assert s["grade"] == "F"
    assert s["critical_gaps"] == 3


def test_grade_bands_are_read_from_the_rubric():
    """Same rules the dashboard reads from data/rubric.json."""
    assert [b["grade"] for b in RUBRIC["grades"]] == ["A", "B", "C", "D", "F"]
    assert RUBRIC["severity_weights"]["critical"] == 3


# ── insights ────────────────────────────────────────────────────────────────


def test_critical_gaps_produce_the_leading_insight_with_ids():
    cid = BY_SEV["critical"][0]
    a = build({cid: "fail"})
    lead = a["insights"][0]
    assert lead["severity"] == "critical"
    assert cid in lead["detail"]


def test_clean_scope_reports_no_critical_gaps():
    a = build({c["id"]: "pass" for c in CATALOG})
    assert a["insights"][0]["severity"] == "ok"


def test_gaps_without_evidence_are_flagged():
    cid = BY_SEV["high"][0]
    titles = [i["title"] for i in build({cid: "fail"})["insights"]]
    assert any("without evidence notes" in t for t in titles)
    documented = build({cid: "fail"}, {cid: "compensating control in place"})
    assert not any("without evidence notes" in i["title"] for i in documented["insights"])


def test_not_started_checklists_are_named():
    a = build({BY_SEV["critical"][0]: "pass"})
    insight = next(i for i in a["insights"] if "not started" in i["title"])
    assert "red-team" in insight["detail"]


# ── recommendations and action plan ─────────────────────────────────────────


def test_recommendations_are_ranked_worst_first_and_carry_the_fix():
    crit, low = BY_SEV["critical"][0], BY_SEV["high"][0]
    recs = build({low: "fail", crit: "fail"})["recommendations"]
    assert recs[0]["id"] == crit
    assert [r["rank"] for r in recs] == [1, 2]
    top = recs[0]
    assert top["action"] and top["verification"]
    assert top["phase"] == "now"


def test_action_plan_phases_group_by_severity_and_carry_exit_criteria():
    status = {BY_SEV["critical"][0]: "fail", BY_SEV["high"][0]: "fail"}
    plan = {p["phase"]: p for p in build(status)["action_plan"]}
    assert plan["now"]["control_ids"] == [BY_SEV["critical"][0]]
    assert plan["next"]["control_ids"] == [BY_SEV["high"][0]]
    assert all(plan[p]["exit_criterion"] for p in ("now", "next", "later"))
    assert plan["complete-the-assessment"]["count"] == 115


def test_no_completion_phase_once_everything_is_answered():
    phases = [p["phase"] for p in build({c["id"]: "pass" for c in CATALOG})["action_plan"]]
    assert "complete-the-assessment" not in phases


# ── results, round-trip, robustness ─────────────────────────────────────────


def test_results_cover_every_control_with_a_status():
    a = build({BY_SEV["critical"][0]: "pass"})
    assert len(a["results"]) == 117
    assert {r["status"] for r in a["results"]} == {"pass", "unreviewed"}


def test_unknown_and_invalid_statuses_are_ignored_not_trusted():
    a = build({"NOPE-999": "pass", BY_SEV["critical"][0]: "banana"})
    assert a["unknown_control_ids"] == ["NOPE-999"]
    assert a["summary"]["reviewed"] == 0


def test_exported_pack_round_trips_back_into_an_assessment(tmp_path):
    cid = BY_SEV["critical"][0]
    first = build({cid: "fail"}, {cid: "note"})
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(first))
    status, evidence, deployment = read_state(path)
    assert status[cid] == "fail"
    assert evidence[cid] == "note"
    second = build(status, evidence, deployment=deployment)
    assert second["summary"] == first["summary"]


def test_read_state_accepts_the_example_state_file():
    status, evidence, deployment = read_state(
        __import__("pathlib").Path("examples/assessment-state.json")
    )
    assert deployment == "checkout-agent-prod"
    assert status["AC-006"] == "fail"
    assert evidence["AC-006"]


def test_read_state_rejects_a_file_with_no_assessment(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"hello": "world"}')
    with pytest.raises(ValueError, match="no assessment found"):
        read_state(path)


def test_format_report_mentions_grade_insights_and_plan():
    cid = BY_SEV["critical"][0]
    text = format_report(build({cid: "fail"}))
    assert "Grade" in text and "Insights" in text and "Action plan" in text
    assert cid in text


# ── published pack + CLI gating ─────────────────────────────────────────────


def test_published_assessment_pack_is_current():
    """docs-site/data/assessment.json is what the console loads; it must be in sync."""
    from pathlib import Path

    published = json.loads(Path("docs-site/data/assessment.json").read_text())
    status, evidence, deployment = read_state(Path("examples/assessment-state.json"))
    rebuilt = build_assessment(
        status, evidence, deployment=deployment, generated=published["generated"]
    )
    assert rebuilt == published, "run scripts/build_assessment.py and commit the result"


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [
        ("never", False),
        ("critical", True),
        ("high", True),
        ("any-gap", True),
    ],
)
def test_gate_thresholds(fail_on, expected):
    summary = {"critical_gaps": 1, "high_gaps": 0, "gaps": 2}
    assert _gate(summary, fail_on) is expected


def test_gate_passes_a_clean_assessment():
    summary = {"critical_gaps": 0, "high_gaps": 0, "gaps": 0}
    assert all(not _gate(summary, f) for f in ("never", "critical", "high", "any-gap"))


def test_cli_assess_writes_a_pack_and_can_fail_the_build(tmp_path, capsys):
    out = tmp_path / "pack.json"
    code = main(
        [
            "assess",
            "--state",
            "examples/assessment-state.json",
            "--out",
            str(out),
            "--fail-on",
            "critical",
        ]
    )
    assert code == 2  # the example deployment has open critical gaps
    pack = json.loads(out.read_text())
    assert pack["summary"]["grade"] == "D"
    assert pack["recommendations"][0]["phase"] == "now"
    assert "grade D" in capsys.readouterr().err


def test_cli_assess_reports_a_missing_state_file(capsys):
    assert main(["assess", "--state", "does-not-exist.json"]) == 1
    assert "cinch assess:" in capsys.readouterr().err
