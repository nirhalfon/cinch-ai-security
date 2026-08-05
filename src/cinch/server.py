"""MCP server entry point for Cinch.

Built on the MCP SDK 2.0 high-level ``MCPServer`` API. Tool input schemas are
inferred from the function signatures and docstrings, and the server is
configured with built-in path-traversal rejection for resource security.
"""

from __future__ import annotations

import json
import logging
import sys

from mcp.server.mcpserver.server import MCPServer

from .loader import (
    get_checklist_item,
    list_checklists,
    load_checklist,
    load_mapping,
    load_protocol,
    search_by_threat,
)

APP = MCPServer(
    name="cinch",
    version="1.0.0",
    description=(
        "MCP server + cross-harness skills for building and operating AI agents "
        "safely. Provides security checklists, protocols, and framework mappings "
        "grounded in NIST AI RMF, CISA, OWASP, CUSTODY, and LASM."
    ),
    # Defense in depth: the SDK rejects path-traversal in resource params.
    # Our loader also validates names independently.
)

# Audit log to stderr (stdout is reserved for the MCP protocol). No tool
# argument values are logged — only the tool name and argument key/lengths —
# so sensitive user input is never written to the log.
logger = logging.getLogger("cinch")


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s cinch: %(message)s"))
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _validate_str(value, key: str) -> str:
    """Validate a string tool argument. Raises TypeError if not a string."""
    if not isinstance(value, str):
        raise TypeError(f"invalid {key}: expected string, got {type(value).__name__}")
    return value


def _err(message: str) -> str:
    return json.dumps({"error": message})


def _log_call(name: str, arguments: dict) -> None:
    """Log a tool call with arg key/lengths only — never arg values."""
    summary = {
        k: (len(v) if isinstance(v, str) else type(v).__name__)
        for k, v in arguments.items()
    }
    logger.info("tool=%s args=%s", name, summary)


# ── Tool implementations ──
# Each function's signature + docstring defines the MCP input schema. All
# user input is validated here and again in the loader (defense in depth).
# Invalid input returns a JSON error object rather than raising, so a malformed
# call cannot crash the server.


def checklist_list() -> str:
    """List all available security checklists with item counts and frameworks.

    Returns checklist name, version, description, item count, and mapped
    frameworks. No arguments.
    """
    _setup_logging()
    _log_call("checklist_list", {})
    return json.dumps(list_checklists(), indent=2)


def checklist_run(name: str) -> str:
    """Run a named checklist against a description of your AI agent or deployment.

    Returns all items in the checklist with their threat, control, severity,
    and verification steps. Use this to assess whether your deployment meets
    security controls from NIST, CISA, OWASP, CUSTODY, and LASM.

    Args:
        name: Checklist name, e.g. 'agent-containment', 'harness-engineering',
            'system-hardening', 'red-team', or 'supply-chain'.
    """
    _setup_logging()
    _log_call("checklist_run", {"name": name})
    try:
        _validate_str(name, "name")
        checklist = load_checklist(name)
        items = [
            {
                "id": item.id,
                "category": item.category,
                "threat": item.threat,
                "control": item.control,
                "severity": item.severity,
                "verification": item.verification,
                "sources": item.sources,
                "custody_pillar": item.custody_pillar,
                "lasm_layer": item.lasm_layer,
            }
            for item in checklist.items
        ]
        result = {
            "name": checklist.name,
            "version": checklist.version,
            "description": checklist.description,
            "frameworks": checklist.frameworks,
            "item_count": len(items),
            "items": items,
        }
        return json.dumps(result, indent=2)
    except (FileNotFoundError, ValueError, TypeError) as e:
        return _err(str(e))


def checklist_get(checklist_name: str, item_id: str) -> str:
    """Get a specific checklist item by its ID (e.g. 'AC-001', 'HE-006').

    Returns the full item with threat, control, severity, verification, and
    source framework references.

    Args:
        checklist_name: Checklist name, e.g. 'agent-containment'.
        item_id: Item ID, e.g. 'AC-001'.
    """
    _setup_logging()
    _log_call("checklist_get", {"checklist_name": checklist_name, "item_id": item_id})
    try:
        _validate_str(checklist_name, "checklist_name")
        _validate_str(item_id, "item_id")
        item = get_checklist_item(checklist_name, item_id)
        if item is None:
            return _err(f"Item {item_id} not found in {checklist_name}")
        result = {
            "id": item.id,
            "category": item.category,
            "threat": item.threat,
            "control": item.control,
            "severity": item.severity,
            "verification": item.verification,
            "sources": item.sources,
            "custody_pillar": item.custody_pillar,
            "lasm_layer": item.lasm_layer,
        }
        return json.dumps(result, indent=2)
    except (FileNotFoundError, ValueError, TypeError) as e:
        return _err(str(e))


def protocol_get(name: str) -> str:
    """Get a step-by-step security protocol by name.

    Returns the full protocol document with prerequisites, steps, verification,
    and rollback procedures.

    Args:
        name: Protocol name, e.g. 'agent-deployment', 'incident-response',
            'red-team-engagement', or 'harness-setup'.
    """
    _setup_logging()
    _log_call("protocol_get", {"name": name})
    try:
        _validate_str(name, "name")
        return load_protocol(name)
    except (FileNotFoundError, ValueError, TypeError) as e:
        return _err(str(e))


def mapping_lookup(framework: str) -> str:
    """Look up security controls mapped to a specific framework.

    Returns all checklist items that correspond to framework controls, enabling
    cross-reference between NIST AI RMF, OWASP, CUSTODY, LASM, and MITRE ATLAS.

    Args:
        framework: Framework name: 'nist-rmf', 'owasp-llm', 'atlas', 'custody',
            or 'lasm'.
    """
    _setup_logging()
    _log_call("mapping_lookup", {"framework": framework})
    try:
        _validate_str(framework, "framework")
        entries = load_mapping(framework)
        result = [
            {
                "framework": e.framework,
                "control_id": e.control_id,
                "framework_control_name": e.framework_control_name,
                "checklist_ids": e.checklist_ids,
                "description": e.description,
            }
            for e in entries
        ]
        return json.dumps(result, indent=2)
    except (FileNotFoundError, ValueError, TypeError) as e:
        return _err(str(e))


def threat_search(query: str) -> str:
    """Search all checklists for controls that mitigate a given threat.

    Use this to find relevant controls for specific threats like 'prompt
    injection', 'credential theft', 'data exfiltration', 'privilege escalation',
    or 'lateral movement'.

    Args:
        query: Threat or control to search for.
    """
    _setup_logging()
    _log_call("threat_search", {"query": query})
    try:
        _validate_str(query, "query")
        results = search_by_threat(query)
        return json.dumps(results, indent=2)
    except (FileNotFoundError, ValueError, TypeError) as e:
        return _err(str(e))


# ── Register tools with the MCP server ──
APP.add_tool(checklist_list, name="checklist_list")
APP.add_tool(checklist_run, name="checklist_run")
APP.add_tool(checklist_get, name="checklist_get")
APP.add_tool(protocol_get, name="protocol_get")
APP.add_tool(mapping_lookup, name="mapping_lookup")
APP.add_tool(threat_search, name="threat_search")


def serve() -> None:
    """Run the MCP server using stdio transport."""
    _setup_logging()
    APP.run(transport="stdio")


def main() -> None:
    """CLI entry point."""
    serve()


if __name__ == "__main__":
    main()