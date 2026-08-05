"""Tests for cinch.loader — focusing on the path-traversal fix and data loading."""

import pytest

from cinch.loader import (
    MAX_QUERY_LEN,
    get_checklist_item,
    list_checklists,
    load_checklist,
    load_mapping,
    load_protocol,
    search_by_threat,
)

CHECKLISTS = ["agent-containment", "harness-engineering", "red-team", "supply-chain", "system-hardening"]
MAPPINGS = ["atlas-crosswalk", "custody-crosswalk", "lasm-crosswalk", "nist-rmf-crosswalk", "owasp-llm-crosswalk"]
PROTOCOLS = ["agent-deployment", "harness-setup", "incident-response", "red-team-engagement"]


# ── Valid loads ──

@pytest.mark.parametrize("name", CHECKLISTS)
def test_load_checklist_valid(name):
    cl = load_checklist(name)
    assert cl.name
    assert len(cl.items) > 0
    # Every item has the required fields populated.
    for item in cl.items:
        assert item.id
        assert item.category


def test_list_checklists_has_all_five():
    cls = list_checklists()
    names = {c["name"] for c in cls}
    assert names == set(CHECKLISTS)
    for c in cls:
        assert c["item_count"] > 0


@pytest.mark.parametrize("name", MAPPINGS)
def test_load_mapping_valid(name):
    entries = load_mapping(name)
    assert len(entries) > 0
    for e in entries:
        assert e.framework
        assert e.control_id


@pytest.mark.parametrize("short,file_stem", [
    ("atlas", "atlas-crosswalk"),
    ("custody", "custody-crosswalk"),
    ("lasm", "lasm-crosswalk"),
    ("nist-rmf", "nist-rmf-crosswalk"),
    ("owasp-llm", "owasp-llm-crosswalk"),
])
def test_load_mapping_accepts_short_name(short, file_stem):
    # Documented short framework names must resolve to the -crosswalk files.
    assert load_mapping(short) == load_mapping(file_stem)


@pytest.mark.parametrize("name", PROTOCOLS)
def test_load_protocol_valid(name):
    content = load_protocol(name)
    assert isinstance(content, str)
    assert len(content) > 100


def test_get_checklist_item_found():
    item = get_checklist_item("agent-containment", "AC-001")
    assert item is not None
    assert item.id == "AC-001"


def test_get_checklist_item_not_found():
    assert get_checklist_item("agent-containment", "ZZ-999") is None


# ── Path-traversal rejection (the security fix) ──

TRAVERSAL_INPUTS = [
    "../../etc/passwd",
    "..",
    "../etc/hostname",
    "foo/bar",
    "/etc/passwd",
    "agent-containment.yaml",   # must be bare name, no extension
    "agent-containment.md",
    "Agent-Containment",        # uppercase rejected
    "with spaces",
    "with..dots",
    ".hidden",
    "a" * 65,                   # too long
    "",
    "a/b",
    "./agent-containment",
]

@pytest.mark.parametrize("bad", TRAVERSAL_INPUTS)
def test_load_checklist_rejects_traversal(bad):
    with pytest.raises(ValueError):
        load_checklist(bad)


@pytest.mark.parametrize("bad", TRAVERSAL_INPUTS)
def test_load_mapping_rejects_traversal(bad):
    with pytest.raises(ValueError):
        load_mapping(bad)


@pytest.mark.parametrize("bad", TRAVERSAL_INPUTS)
def test_load_protocol_rejects_traversal(bad):
    with pytest.raises(ValueError):
        load_protocol(bad)


def test_load_protocol_traversal_does_not_read_file(tmp_path):
    """A traversal attempt must raise before any out-of-tree file is read."""
    target = tmp_path / "secret.md"
    target.write_text("TOPSECRET")
    # Try to reach it via a relative escape; must be rejected, not returned.
    with pytest.raises(ValueError):
        load_protocol(f"../../{tmp_path.name}/secret")


def test_get_checklist_item_rejects_bad_id():
    with pytest.raises(ValueError):
        get_checklist_item("agent-containment", "../../etc/passwd")
    with pytest.raises(ValueError):
        get_checklist_item("agent-containment", "bad id with spaces")
    with pytest.raises(ValueError):
        get_checklist_item("agent-containment", "a" * 33)


# ── Threat search ──

def test_search_by_threat_returns_matches():
    results = search_by_threat("prompt injection")
    assert isinstance(results, list)
    assert len(results) > 0
    for r in results:
        assert "checklist" in r
        assert "id" in r


def test_search_by_threat_rejects_empty():
    with pytest.raises(ValueError):
        search_by_threat("   ")


def test_search_by_threat_rejects_overlong():
    with pytest.raises(ValueError):
        search_by_threat("x" * (MAX_QUERY_LEN + 1))


def test_search_by_threat_rejects_non_string():
    with pytest.raises((ValueError, TypeError)):
        search_by_threat(None)  # type: ignore[arg-type]