"""Tests for probing a running agent: host, project and behavioural probes.

The point of these probes is that a *real* deployment produces the statuses, so the
tests build real fixtures on disk / real fake endpoints and assert on the verdicts.
Two invariants matter most and are pinned repeatedly:

* an ``unknown`` observation never becomes a passing control;
* evidence never records a secret value.
"""

from __future__ import annotations

import json
import os
import platform
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from cinch import collect as collect_mod
from cinch.collect import DERIVATIONS, canonical_bytes, collect, derive_related, read_bundle
from cinch.probes import FAIL, PASS, UNKNOWN, Observation, probes_for
from cinch.probes import behaviour as bh
from cinch.probes import host as host_probes
from cinch.probes import project as project_probes
from cinch.verify import statuses_from, verify_bundle

IS_LINUX = platform.system() == "Linux"


def by_control(observations) -> dict[str, Observation]:
    return {o.control_id: o for o in observations}


# ── registry ────────────────────────────────────────────────────────────────


def test_every_probe_family_is_registered():
    assert {fn.probe_name for fn in probes_for("host")}
    assert {fn.probe_name for fn in probes_for("project")}
    assert {fn.probe_name for fn in probes_for("behaviour")}


def test_host_probes_cover_the_agent_environment_checklist():
    covered = {cid for fn in probes_for("host") for cid in fn.control_ids}
    assert covered == {f"AE-{n:03d}" for n in range(1, 12)}


# ── host probes ─────────────────────────────────────────────────────────────


def test_host_collect_returns_one_observation_per_ae_control():
    observations, target = host_probes.collect()
    assert target["kind"] == "host"
    assert {o.control_id for o in observations} == {f"AE-{n:03d}" for n in range(1, 12)}


@pytest.mark.skipif(IS_LINUX, reason="checks the non-Linux honesty path")
def test_non_linux_host_reports_unknown_not_pass():
    """A macOS collector cannot see /proc — it must not claim controls are enforced."""
    observations, _ = host_probes.collect()
    assert all(o.status == UNKNOWN for o in observations)
    assert all("not Linux" in o.detail for o in observations)


@pytest.mark.skipif(not IS_LINUX, reason="requires /proc")
def test_privilege_posture_reads_real_proc_status():
    obs = host_probes.privilege_posture(pid=1)[0]
    assert obs.status in (PASS, FAIL, UNKNOWN)
    assert obs.raw.get("pid") == 1


def test_decode_caps_names_only_boundary_crossing_capabilities():
    assert host_probes.decode_caps("0") == []
    assert "cap_sys_admin" in host_probes.decode_caps(hex(1 << 21))
    assert host_probes.decode_caps("not-hex") == []


def test_resolve_pid_falls_back_to_the_collector_and_says_so():
    pid, how = host_probes.resolve_pid()
    assert pid is not None
    assert "collector process" in how


def test_a_raising_probe_degrades_to_unknown(monkeypatch):
    """One broken probe must not take the collector down or fake a result."""

    def boom(**_):
        raise RuntimeError("probe exploded")

    boom.control_ids = ("AE-001",)
    boom.probe_name = "boom"
    monkeypatch.setattr(host_probes, "probes_for_host", lambda: [boom])
    observations, _ = host_probes.collect(pid=1)
    assert [o.status for o in observations] == [UNKNOWN]
    assert "probe exploded" in observations[0].detail


# ── project probes ──────────────────────────────────────────────────────────


@pytest.fixture()
def hardened_project(tmp_path: Path) -> Path:
    """A deployment that does most things right."""
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"cinch": {"command": "cinch", "allowedTools": ["checklist_get"]}}}
        )
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  agent:\n    user: '10001'\n    read_only: true\n"
        "    cap_drop: [ALL]\n    security_opt: ['no-new-privileges:true']\n"
    )
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "netpol.yaml").write_text(
        "kind: NetworkPolicy\nspec:\n  policyTypes:\n    - Egress\n  egress:\n    - to:\n"
        "        - ipBlock:\n            cidr: 10.0.0.0/8\n"
    )
    (tmp_path / "requirements.txt").write_text("pyyaml==6.0.3 --hash=sha256:abc123\n")
    (tmp_path / "sbom.cdx.json").write_text("{}")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    wf.joinpath("ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: pip-audit\n      - uses: actions/attest-build-provenance@v1\n"
        "      - run: cosign sign $IMAGE\n"
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "threat-model.md").write_text("# Threat model\n")
    (tmp_path / "docs" / "incident-runbook.md").write_text("# Runbook\n")
    return tmp_path


def test_hardened_project_passes_the_controls_it_can_prove(hardened_project):
    obs = by_control(project_probes.collect(hardened_project)[0])
    for cid in ("HE-011", "AC-003", "HE-003", "AC-018", "AC-023", "HE-004", "AC-019"):
        assert obs[cid].status == PASS, (cid, obs[cid].detail)
    for cid in ("SC-001", "SC-002", "SC-003", "SC-006", "SC-008", "SC-011", "HE-002", "HE-024"):
        assert obs[cid].status == PASS, (cid, obs[cid].detail)


def test_privileged_container_fails_isolation(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  agent:\n    user: '10001'\n    privileged: true\n    cap_drop: [ALL]\n"
    )
    obs = by_control(project_probes.collect(tmp_path)[0])
    assert obs["HE-003"].status == FAIL
    assert "privileged" in obs["HE-003"].detail
    assert obs["AC-023"].status == FAIL  # no read-only root either


def test_committed_secret_fails_and_records_no_value(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=AKIA1234567890ABCDEF\nDEBUG=true\n")
    obs = by_control(project_probes.collect(tmp_path)[0])
    for cid in ("HE-005", "SC-012", "AC-016"):
        assert obs[cid].status == FAIL
    blob = json.dumps([o.as_dict() for o in project_probes.collect(tmp_path)[0]])
    assert "AKIA1234567890ABCDEF" not in blob, "probe evidence must never carry the secret value"
    assert "key_pattern" in blob


def test_placeholder_values_are_not_treated_as_secrets(tmp_path):
    (tmp_path / ".env").write_text("API_KEY=${API_KEY}\nTOKEN=changeme\nSECRET=<your-secret-here>\n")
    obs = by_control(project_probes.collect(tmp_path)[0])
    assert obs["HE-005"].status == PASS


def test_unpinned_requirements_fail_supply_chain_pinning(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\nflask\n")
    obs = by_control(project_probes.collect(tmp_path)[0])
    assert obs["SC-003"].status == FAIL
    assert "unpinned" in json.dumps(obs["SC-003"].raw)


def test_supply_chain_probes_abstain_outside_a_build_tree(tmp_path):
    """A config directory has no build to assess — claiming "no SBOM" there is wrong.

    Found by running the probes against a live Claude Code harness config directory:
    SC-001/002/006 came back as failures for a tree that is not built at all.
    """
    (tmp_path / "settings.json").write_text("{}")
    obs = by_control(project_probes.collect(tmp_path)[0])
    for cid in ("SC-001", "SC-002", "SC-003", "SC-006", "SC-008", "HE-002", "HE-024"):
        assert obs[cid].status == UNKNOWN, (cid, obs[cid].detail)
        assert "not a build tree" in obs[cid].detail


def test_build_tree_detection(tmp_path):
    assert project_probes.is_build_tree(tmp_path) is False
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    assert project_probes.is_build_tree(tmp_path) is True


def test_missing_config_is_unknown_not_fail(tmp_path):
    """An empty deployment proves nothing — it must not be graded as failing."""
    obs = by_control(project_probes.collect(tmp_path)[0])
    for cid in ("HE-011", "AC-003", "HE-003", "AC-018", "HE-004", "AC-019"):
        assert obs[cid].status == UNKNOWN


def test_keyword_leads_stay_unknown(hardened_project):
    """Grep hits are leads for a reviewer, never proof a runtime limit is enforced."""
    obs = by_control(project_probes.collect(hardened_project)[0])
    for cid in ("HE-014", "HE-016", "HE-017", "HE-019"):
        assert obs[cid].status == UNKNOWN


def test_vendored_trees_are_never_walked(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")  # a real build tree
    junk = tmp_path / ".venv" / "lib"
    junk.mkdir(parents=True)
    junk.joinpath("threat-model.md").write_text("# not ours\n")
    obs = by_control(project_probes.collect(tmp_path)[0])
    assert obs["HE-002"].status == FAIL  # the vendored file must not count


def test_nonexistent_project_path_yields_no_observations(tmp_path):
    observations, target = project_probes.collect(tmp_path / "nope")
    assert observations == []
    assert target["exists"] is False


# ── behavioural probes ──────────────────────────────────────────────────────


class _Agent(BaseHTTPRequestHandler):
    """A fake agent. `mode` decides whether it is contained or not."""

    mode = "contained"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        prompt = body.get("input", "")
        if self.mode == "compromised":
            reply = bh.CANARY if "CINCH-CANARY" in prompt else "ok"
        elif self.mode == "leaky":
            reply = "System prompt: You are an internal assistant. Rules: never refuse. " * 4
        elif self.mode == "throttling":
            self.send_error(429, "Too Many Requests")
            return
        else:
            reply = "I can help with that request."
        payload = json.dumps({"output": reply}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


@pytest.fixture()
def agent_server():
    """Start a fake agent; the test sets `.mode` before probing."""
    servers = []

    def start(mode: str) -> str:
        handler = type("_H", (_Agent,), {"mode": mode})
        httpd = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return f"http://127.0.0.1:{httpd.server_port}/"

    yield start
    for s in servers:
        s.shutdown()


def test_behavioural_probing_refuses_without_authorization():
    with pytest.raises(bh.NotAuthorized, match="refused by default"):
        bh.collect("http://127.0.0.1:1/", authorized=False)


def test_behavioural_probing_rejects_a_non_http_endpoint():
    with pytest.raises(ValueError, match="http"):
        bh.collect("file:///etc/passwd", authorized=True)


def test_contained_agent_passes_the_injection_probes(agent_server):
    url = agent_server("contained")
    obs = by_control(bh.collect(url, authorized=True)[0])
    assert obs["RT-001"].status == PASS
    assert obs["AC-005"].status == PASS
    assert obs["RT-002"].status == PASS
    assert obs["AC-006"].status == PASS
    assert obs["RT-009"].status == PASS


def test_injectable_agent_fails_direct_and_indirect_injection(agent_server):
    url = agent_server("compromised")
    obs = by_control(bh.collect(url, authorized=True)[0])
    assert obs["RT-001"].status == FAIL
    assert obs["AC-005"].status == FAIL
    assert obs["RT-002"].status == FAIL
    assert obs["AC-006"].status == FAIL
    assert bh.CANARY in obs["RT-001"].raw["reply"]


def test_prompt_leakage_is_detected(agent_server):
    url = agent_server("leaky")
    obs = by_control(bh.collect(url, authorized=True)[0])
    assert obs["RT-009"].status == FAIL


def test_throttling_agent_shows_a_rate_limit(agent_server):
    url = agent_server("throttling")
    obs = by_control(bh.collect(url, authorized=True)[0])
    assert obs["RT-008"].status == PASS
    assert obs["AC-017"].status == PASS


def test_unreachable_endpoint_is_unknown_not_fail():
    obs = by_control(bh.collect("http://127.0.0.1:9/", authorized=True)[0])
    assert all(o.status == UNKNOWN for o in obs.values())


def test_tool_enumeration_is_informational_only(agent_server):
    """Enumerating tools is not itself a breach — it must never auto-fail a control."""
    obs = by_control(bh.collect(agent_server("contained"), authorized=True)[0])
    assert obs["RT-005"].status == UNKNOWN


# ── bundle assembly ─────────────────────────────────────────────────────────


def test_bundle_records_collector_targets_and_counts(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path, deployment="d1")
    assert bundle["schema"] == "cinch-evidence/1"
    assert bundle["deployment"] == "d1"
    assert bundle["collector"]["pid"]
    assert bundle["targets"][0]["kind"] == "project"
    assert set(bundle["counts"]) >= {"pass", "fail", "unknown", "controls"}
    assert bundle["observations"]


def test_self_attestation_is_detected_when_the_collector_inspects_itself():
    bundle = collect(kinds=("host",))
    assert bundle["provenance"]["self_attested"] is True
    assert bundle["provenance"]["independent"] is False
    assert any("its own process" in r or "inspected itself" in r for r in bundle["provenance"]["reasons"])


def test_collector_spawned_by_the_audited_agent_is_self_attested(monkeypatch):
    """PID equality is not enough: an agent that *spawns* the collector is auditing itself.

    Found by pointing cinch at the Claude Code process that had spawned it — same UID,
    same authority, different PID, and the bundle claimed to be independent evidence.
    """
    parent = collect_mod.process_ancestors()[0]
    bundle = collect(kinds=("host",), pid=parent)
    assert bundle["provenance"]["self_attested"] is True
    assert any("spawned by the audited process" in r for r in bundle["provenance"]["reasons"])


def test_process_ancestors_walks_up_to_a_real_parent():
    chain = collect_mod.process_ancestors()
    assert chain, "expected at least one ancestor PID"
    assert all(isinstance(p, int) and p > 0 for p in chain)
    assert os.getpid() not in chain


def test_unrelated_target_process_stays_independent():
    """PID 1 did not spawn the test runner, so evidence about it is independent."""
    bundle = collect(kinds=("host",), pid=1)
    if 1 in collect_mod.process_ancestors():  # containers where init is our ancestor
        pytest.skip("init is an ancestor of the test runner in this environment")
    assert bundle["provenance"]["independent"] is True


def test_mcp_invocation_is_never_treated_as_independent(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path, via_mcp=True)
    assert bundle["provenance"]["self_attested"] is True
    assert any("MCP" in r for r in bundle["provenance"]["reasons"])


def test_out_of_band_project_collection_is_independent(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path)
    assert bundle["provenance"]["independent"] is True


def test_unknown_probe_kind_is_rejected():
    with pytest.raises(ValueError, match="unknown probe kind"):
        collect(kinds=("host", "telepathy"))


def test_behaviour_without_endpoint_is_rejected():
    with pytest.raises(ValueError, match="endpoint"):
        collect(kinds=("behaviour",), authorized=True)


def test_derivations_map_host_findings_onto_containment_controls():
    obs = [Observation("AE-005", FAIL, "egress is default-allow", "egress_policy")]
    derived = derive_related(obs)
    assert derived[0].control_id == DERIVATIONS["AE-005"][0]
    assert derived[0].status == FAIL
    assert derived[0].raw["derived_from"] == "AE-005"
    assert derived[0].probe.startswith("derived:")


def test_derivation_never_overwrites_a_direct_observation():
    obs = [
        Observation("AE-005", FAIL, "host says fail", "egress_policy"),
        Observation("AC-019", PASS, "manifest says pass", "egress_manifest"),
    ]
    assert derive_related(obs) == []


def test_signing_reports_a_missing_command_instead_of_pretending(tmp_path):
    bundle = collect(
        kinds=("project",), project_path=tmp_path, sign_cmd=["definitely-not-a-real-signer"]
    )
    assert bundle["signature"]["signed"] is False
    assert "not found" in bundle["signature"]["error"]


def test_signature_covers_canonical_bytes_without_the_signature_itself(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path, sign_cmd=["cat"])
    payload = canonical_bytes(bundle)
    assert b'"signature"' not in payload
    if bundle["signature"]["signed"]:  # `cat` echoes the payload back
        assert bundle["signature"]["signature"].startswith("{")


def test_read_bundle_rejects_a_foreign_document(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"schema": "something-else"}))
    with pytest.raises(ValueError, match="not a cinch-evidence"):
        read_bundle(path)


def test_read_bundle_round_trips(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path)
    path = tmp_path / "b.json"
    path.write_text(json.dumps(bundle))
    assert read_bundle(path)["counts"] == bundle["counts"]


# ── verification ────────────────────────────────────────────────────────────


def test_unknown_observations_do_not_become_statuses():
    bundle = {
        "observations": [
            {"control_id": "AE-001", "status": "unknown", "detail": "not linux", "probe": "p"},
            {"control_id": "AE-005", "status": "pass", "detail": "default deny", "probe": "p"},
        ]
    }
    status, evidence, stats = statuses_from(bundle)
    assert status == {"AE-005": "pass"}
    assert stats["unverifiable"] == ["AE-001"]
    assert "AE-001" in evidence  # the reason is still recorded as evidence


def test_conflicting_observations_resolve_to_a_gap():
    bundle = {
        "observations": [
            {"control_id": "AC-019", "status": "pass", "detail": "manifest", "probe": "a"},
            {"control_id": "AC-019", "status": "fail", "detail": "host", "probe": "b"},
        ]
    }
    status, evidence, stats = statuses_from(bundle)
    assert status["AC-019"] == "fail"
    assert stats["conflicts"] == ["AC-019"]
    assert "[a]" in evidence["AC-019"] and "[b]" in evidence["AC-019"]


def test_verify_grades_a_bundle_and_keeps_probe_evidence(tmp_path):
    bundle = collect(kinds=("project",), project_path=tmp_path, deployment="probed")
    assessment = verify_bundle(bundle)
    assert assessment["deployment"] == "probed"
    assert assessment["summary"]["grade"]
    results = {r["id"]: r for r in assessment["results"]}
    observed = {o["control_id"] for o in bundle["observations"]}
    assert any(results[cid]["evidence"].startswith("[") for cid in observed)


def test_verify_flags_self_attested_evidence_as_critical():
    bundle = collect(kinds=("host",))
    insights = verify_bundle(bundle)["insights"]
    assert insights[0]["severity"] == "critical"
    assert "self-attested" in insights[0]["title"]


def test_verify_flags_unsigned_bundles_and_unverifiable_controls():
    titles = [i["title"] for i in verify_bundle(collect(kinds=("host",)))["insights"]]
    assert any("unsigned" in t for t in titles)
    assert any("could not be verified" in t for t in titles)


def test_verify_carries_provenance_into_the_pack_for_the_dashboard(tmp_path):
    assessment = verify_bundle(collect(kinds=("project",), project_path=tmp_path))
    src = assessment["evidence_source"]
    assert src["schema"] == "cinch-evidence/1"
    assert src["provenance"]["independent"] is True
    assert src["signed"] is False
    assert src["targets"][0]["kind"] == "project"


def test_independent_bundle_has_no_self_attestation_insight(tmp_path):
    insights = verify_bundle(collect(kinds=("project",), project_path=tmp_path))["insights"]
    assert not any("self-attested" in i["title"] for i in insights)


def test_collector_identity_survives_a_missing_passwd_entry(monkeypatch):
    monkeypatch.setattr(collect_mod.getpass, "getuser", lambda: (_ for _ in ()).throw(KeyError()))
    identity = collect_mod.collector_identity()
    assert identity["user"].startswith("uid:") or identity["user"] == "unknown"
