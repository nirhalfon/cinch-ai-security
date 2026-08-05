"""Tests for cinch.server — tool dispatch, error handling, and schema validity.

Exercises the real MCPServer dispatch path (APP.call_tool / APP.list_tools).
"""

import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from cinch.server import APP

EXPECTED_TOOLS = {
    "checklist_list",
    "checklist_run",
    "checklist_get",
    "protocol_get",
    "mapping_lookup",
    "threat_search",
}


def _run(coro):
    return asyncio.run(coro)


def _payload(result):
    """Extract the JSON-decoded payload from a CallToolResult."""
    assert result.content, "tool returned no content"
    text = result.content[0].text
    return json.loads(text)


# ── list_tools ──

def test_list_tools_advertises_all_six():
    tools = _run(APP.list_tools())
    names = {t.name for t in tools}
    assert names == EXPECTED_TOOLS
    for t in tools:
        assert t.description, f"tool {t.name} missing description"
        # Schema must be a JSON object.
        schema = t.input_schema
        assert schema["type"] == "object"


# ── happy paths ──

def test_checklist_list_returns_json():
    payload = _payload(_run(APP.call_tool("checklist_list", {})))
    assert isinstance(payload, list)
    assert len(payload) == 5
    assert {c["name"] for c in payload} == {
        "agent-containment", "harness-engineering", "red-team",
        "supply-chain", "system-hardening",
    }


def test_checklist_run_returns_items():
    payload = _payload(_run(APP.call_tool("checklist_run", {"name": "agent-containment"})))
    assert payload["name"]
    assert payload["item_count"] > 0
    assert all("id" in i and "threat" in i for i in payload["items"])


def test_checklist_get_returns_item():
    payload = _payload(_run(APP.call_tool("checklist_get", {
        "checklist_name": "agent-containment", "item_id": "AC-001",
    })))
    assert payload["id"] == "AC-001"
    assert payload["threat"]


def test_mapping_lookup_returns_entries():
    payload = _payload(_run(APP.call_tool("mapping_lookup", {"framework": "nist-rmf"})))
    assert isinstance(payload, list)
    assert len(payload) > 0
    assert all("control_id" in e for e in payload)


def test_protocol_get_returns_markdown():
    result = _run(APP.call_tool("protocol_get", {"name": "agent-deployment"}))
    text = result.content[0].text
    assert "Protocol" in text


def test_threat_search_returns_matches():
    payload = _payload(_run(APP.call_tool("threat_search", {"query": "prompt injection"})))
    assert isinstance(payload, list)
    assert len(payload) > 0


# ── not-found returns error JSON, not a crash ──

def test_checklist_run_not_found():
    payload = _payload(_run(APP.call_tool("checklist_run", {"name": "no-such-checklist"})))
    assert "error" in payload


def test_checklist_get_item_not_found():
    payload = _payload(_run(APP.call_tool("checklist_get", {
        "checklist_name": "agent-containment", "item_id": "ZZ-999",
    })))
    assert "error" in payload


# ── malicious input is rejected at the boundary ──

@pytest.mark.parametrize("bad", [
    "../../etc/passwd",
    "agent-containment.yaml",
    "/etc/passwd",
    "..",
    "with spaces",
])
def test_checklist_run_rejects_traversal(bad):
    payload = _payload(_run(APP.call_tool("checklist_run", {"name": bad})))
    assert "error" in payload


@pytest.mark.parametrize("bad", [
    "../../etc/passwd",
    "agent-containment",
    "/etc/passwd",
])
def test_protocol_get_rejects_traversal(bad):
    payload = _payload(_run(APP.call_tool("protocol_get", {"name": bad})))
    assert "error" in payload


def test_threat_search_rejects_overlong():
    payload = _payload(_run(APP.call_tool("threat_search", {"query": "x" * 1000})))
    assert "error" in payload


def test_unknown_tool_raises():
    # An unknown tool name is a protocol error, raised as ToolError.
    with pytest.raises(ToolError):
        _run(APP.call_tool("does_not_exist", {}))