"""MCP server entry point for Cinch.

Built on the MCP SDK 2.0 high-level ``MCPServer`` API. Tool input schemas are
inferred from the function signatures and docstrings, and the server is
configured with built-in path-traversal rejection for resource security.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml
from mcp.server.mcpserver.server import MCPServer

from .assess import build_assessment, format_report, read_state
from .collect import collect as collect_evidence
from .console import DEFAULT_HOST, DEFAULT_PORT, serve_console
from .loader import (
    diff_checklists,
    get_checklist_item,
    list_checklists,
    load_checklist,
    load_mapping,
    load_protocol,
    search_by_threat,
)
from .probes.behaviour import NotAuthorized
from .verify import verify_bundle, verify_file

APP = MCPServer(
    name="cinch",
    version="1.1.0",
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
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
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
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
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
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
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
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
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
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
        return _err(str(e))


def checklist_diff(a: str, b: str) -> str:
    """Compare two checklists and show coverage gaps and duplicated controls.

    Returns items present in checklist A but missing from B, and vice versa.
    Matching is by normalized control text (case- and whitespace-insensitive),
    not by item ID, so the same control stated in two checklists (e.g.
    agent-containment and harness-engineering) is recognized as a duplicate.
    Use this to keep the catalog maintainable as it grows.

    Args:
        a: First checklist name, e.g. 'agent-containment'.
        b: Second checklist name, e.g. 'harness-engineering'.
    """
    _setup_logging()
    _log_call("checklist_diff", {"a": a, "b": b})
    try:
        _validate_str(a, "a")
        _validate_str(b, "b")
        return json.dumps(diff_checklists(a, b), indent=2)
    except (FileNotFoundError, ValueError, TypeError, yaml.YAMLError, KeyError, AttributeError) as e:
        return _err(str(e))


def evidence_collect(
    host: bool = False,
    pid: int | None = None,
    unit: str = "",
    project_path: str = "",
    endpoint: str = "",
    authorized: bool = False,
    deployment: str = "unnamed-deployment",
) -> str:
    """Probe a running agent deployment and return an evidence bundle.

    Runs read-only probes and returns what was actually observed, per control:
    'pass' (demonstrably enforced), 'fail' (demonstrably not), 'unknown' (could not
    tell — never counted as enforced). Feed the bundle to evidence_verify to get a
    grade, insights and an action plan.

    Self-audit warning: when an agent calls this tool about its own host, the result
    is self-attestation, not assurance. The bundle records that ('provenance.
    self_attested') and the assessment raises it as a critical finding. Independent
    evidence needs `cinch collect` run out of band under a separate identity — see
    the 'evidence-collect' protocol.

    Args:
        host: Probe the host/container running the agent (AE-001..AE-011).
        pid: PID of the agent process to inspect. Omit and the collector inspects
            itself, which is flagged as self-attestation.
        unit: systemd unit name of the agent, used to resolve its MainPID.
        project_path: Deployment directory to inspect — MCP tool grants, container
            manifests, CI workflows, dependency pinning, secret handling.
        endpoint: Running agent's HTTP endpoint for behavioural probes (prompt
            injection, prompt leakage, tool enumeration, rate bounds).
        authorized: Must be true to probe `endpoint`. Confirms you are permitted to
            send adversarial input to that target.
        deployment: Name recorded in the bundle.
    """
    _setup_logging()
    _log_call(
        "evidence_collect",
        {"host": host, "pid": pid, "unit": unit, "project_path": project_path,
         "endpoint": endpoint, "authorized": authorized},
    )
    kinds = []
    if host or pid or unit:
        kinds.append("host")
    if project_path:
        kinds.append("project")
    if endpoint:
        kinds.append("behaviour")
    if not kinds:
        return _err(
            "choose at least one target: host=true (optionally with pid/unit), "
            "project_path, or endpoint"
        )
    try:
        bundle = collect_evidence(
            kinds=tuple(kinds),
            pid=pid,
            unit=unit or None,
            project_path=Path(project_path) if project_path else None,
            endpoint=endpoint or None,
            authorized=authorized,
            deployment=deployment,
            via_mcp=True,  # the requester is an agent — never claimed as independent
        )
    except (NotAuthorized, FileNotFoundError, OSError, TypeError, ValueError) as e:
        return _err(str(e))
    return json.dumps(bundle, indent=2)


def evidence_verify(bundle_json: str, deployment: str = "") -> str:
    """Grade an evidence bundle: score, letter grade, insights, recommendations, plan.

    Applies the same rubric a human reviewer sees in the console, and reports on the
    evidence itself as well as the controls — self-attested collection, unsigned
    bundles, and controls no probe could verify all surface as findings. 'unknown'
    observations stay unreviewed rather than counting as enforced.

    Args:
        bundle_json: A 'cinch-evidence/1' bundle, as returned by evidence_collect.
        deployment: Optional deployment name override.
    """
    _setup_logging()
    _log_call("evidence_verify", {"bundle_json": bundle_json, "deployment": deployment})
    try:
        _validate_str(bundle_json, "bundle_json")
        bundle = json.loads(bundle_json)
        if not isinstance(bundle, dict) or not isinstance(bundle.get("observations"), list):
            return _err("bundle_json is not a cinch-evidence/1 bundle with an observations array")
        return json.dumps(verify_bundle(bundle, deployment=deployment or None), indent=2)
    except (json.JSONDecodeError, TypeError, ValueError, KeyError) as e:
        return _err(str(e))


# ── Register tools with the MCP server ──
APP.add_tool(checklist_list, name="checklist_list")
APP.add_tool(checklist_run, name="checklist_run")
APP.add_tool(checklist_get, name="checklist_get")
APP.add_tool(protocol_get, name="protocol_get")
APP.add_tool(mapping_lookup, name="mapping_lookup")
APP.add_tool(threat_search, name="threat_search")
APP.add_tool(checklist_diff, name="checklist_diff")
APP.add_tool(evidence_collect, name="evidence_collect")
APP.add_tool(evidence_verify, name="evidence_verify")


def serve() -> None:
    """Run the MCP server using stdio transport."""
    _setup_logging()
    APP.run(transport="stdio")


def build_parser() -> argparse.ArgumentParser:
    """Build the ``cinch`` CLI parser."""
    parser = argparse.ArgumentParser(
        prog="cinch",
        description=(
            "Cinch — MCP server + cross-harness skills for operating AI agents safely."
        ),
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the MCP server over stdio (default)")
    console_cmd = sub.add_parser(
        "console",
        help="serve the assessment console dashboard on localhost",
    )
    console_cmd.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})"
    )
    console_cmd.add_argument(
        "--host", default=DEFAULT_HOST, help=f"bind address (default {DEFAULT_HOST})"
    )
    console_cmd.add_argument(
        "--no-browser", action="store_true", help="do not open a browser window"
    )
    console_cmd.add_argument(
        "--assessment",
        type=Path,
        help="assessment result pack to load into the dashboard on open",
    )
    assess_cmd = sub.add_parser(
        "assess",
        help="grade an assessment state file and emit insights, recommendations, action plan",
    )
    assess_cmd.add_argument(
        "--state",
        type=Path,
        required=True,
        help="assessment state JSON ({'status': {...}, 'evidence': {...}}), or a previously "
        "exported assessment pack",
    )
    assess_cmd.add_argument(
        "--out", type=Path, help="write the full result pack here (JSON); default is a text report"
    )
    assess_cmd.add_argument("--deployment", help="override the deployment name in the pack")
    assess_cmd.add_argument(
        "--fail-on",
        choices=["critical", "high", "any-gap", "never"],
        default="never",
        help="exit non-zero when gaps at this level remain (for CI gating)",
    )

    collect_cmd = sub.add_parser(
        "collect",
        help="probe a running agent (host, project, behaviour) and emit an evidence bundle",
    )
    collect_cmd.add_argument(
        "--host", action="store_true", help="probe the host/container running the agent (AE-*)"
    )
    collect_cmd.add_argument("--pid", type=int, help="PID of the agent process to inspect")
    collect_cmd.add_argument("--unit", help="systemd unit of the agent, to resolve its MainPID")
    collect_cmd.add_argument(
        "--project", type=Path, help="deployment directory to inspect (MCP config, manifests, CI)"
    )
    collect_cmd.add_argument(
        "--endpoint", help="running agent's HTTP endpoint, for behavioural probes"
    )
    collect_cmd.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you are permitted to send adversarial input to --endpoint (required)",
    )
    collect_cmd.add_argument("--request-field", default="input", help="request JSON field")
    collect_cmd.add_argument("--response-field", default="output", help="response JSON field")
    collect_cmd.add_argument("--deployment", default="unnamed-deployment", help="deployment name")
    collect_cmd.add_argument("--out", type=Path, help="write the evidence bundle here (JSON)")
    collect_cmd.add_argument(
        "--sign-cmd",
        help="command that signs the bundle from stdin, e.g. 'cosign sign-blob -'. "
        "Use a key the agent cannot reach.",
    )

    verify_cmd = sub.add_parser(
        "verify", help="grade an evidence bundle: insights, recommendations, action plan"
    )
    verify_cmd.add_argument("--evidence", type=Path, required=True, help="evidence bundle JSON")
    verify_cmd.add_argument("--out", type=Path, help="write the assessment pack here (JSON)")
    verify_cmd.add_argument("--deployment", help="override the deployment name")
    verify_cmd.add_argument(
        "--fail-on",
        choices=["critical", "high", "any-gap", "never"],
        default="never",
        help="exit non-zero when gaps at this level remain (for CI gating)",
    )
    return parser


def _gate(summary: dict, fail_on: str) -> bool:
    """Return True when the assessment should fail the build."""
    return (
        (fail_on == "critical" and summary["critical_gaps"] > 0)
        or (fail_on == "high" and summary["critical_gaps"] + summary["high_gaps"] > 0)
        or (fail_on == "any-gap" and summary["gaps"] > 0)
    )


def _run_collect(args: argparse.Namespace) -> int:
    """Probe a running agent and emit an evidence bundle."""
    kinds = []
    if args.host or args.pid or args.unit:
        kinds.append("host")
    if args.project:
        kinds.append("project")
    if args.endpoint:
        kinds.append("behaviour")
    if not kinds:
        print(
            "cinch collect: choose at least one target — --host (with optional --pid/--unit), "
            "--project PATH, or --endpoint URL.",
            file=sys.stderr,
        )
        return 1
    bundle = collect_evidence(
        kinds=tuple(kinds),
        pid=args.pid,
        unit=args.unit,
        project_path=args.project,
        endpoint=args.endpoint,
        authorized=args.authorized,
        deployment=args.deployment,
        sign_cmd=args.sign_cmd.split() if args.sign_cmd else None,
        request_field=args.request_field,
        response_field=args.response_field,
    )
    c = bundle["counts"]
    where = args.out or Path("-")
    if args.out:
        args.out.write_text(json.dumps(bundle, indent=2) + "\n")
    else:
        print(json.dumps(bundle, indent=2))
    print(
        f"Collected {c['pass']} pass / {c['fail']} fail / {c['unknown']} unknown across "
        f"{c['controls']} controls → {where}",
        file=sys.stderr,
    )
    if bundle["provenance"]["self_attested"]:
        print(
            "warning: this evidence is self-attested — "
            + "; ".join(bundle["provenance"]["reasons"])
            + ". See protocols/evidence-collect.md.",
            file=sys.stderr,
        )
    return 0


def _run_verify(args: argparse.Namespace) -> int:
    """Grade an evidence bundle."""
    assessment = verify_file(args.evidence, deployment=args.deployment)
    if args.out:
        args.out.write_text(json.dumps(assessment, indent=2) + "\n")
        s = assessment["summary"]
        print(
            f"Wrote {args.out} — grade {s['grade']} ({s['label']}), score {s['score']}%, "
            f"{s['gaps']} open gaps ({s['critical_gaps']} critical).",
            file=sys.stderr,
        )
    else:
        print(format_report(assessment))
    if _gate(assessment["summary"], args.fail_on):
        print(f"cinch verify: failing on --fail-on {args.fail_on}", file=sys.stderr)
        return 2
    return 0


def _run_assess(args: argparse.Namespace) -> int:
    """Build an assessment pack from a state file; print or write it."""
    status, evidence, deployment = read_state(args.state)
    assessment = build_assessment(
        status, evidence, deployment=args.deployment or deployment
    )
    if args.out:
        args.out.write_text(json.dumps(assessment, indent=2, sort_keys=False) + "\n")
        s = assessment["summary"]
        print(
            f"Wrote {args.out} — grade {s['grade']} ({s['label']}), score {s['score']}%, "
            f"{s['gaps']} open gaps ({s['critical_gaps']} critical).",
            file=sys.stderr,
        )
    else:
        print(format_report(assessment))
    if assessment["unknown_control_ids"]:
        print(
            "warning: ignored unknown control ids: "
            + ", ".join(assessment["unknown_control_ids"]),
            file=sys.stderr,
        )
    if _gate(assessment["summary"], args.fail_on):
        print(f"cinch assess: failing on --fail-on {args.fail_on}", file=sys.stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "console":
        try:
            serve_console(
                port=args.port,
                host=args.host,
                open_browser=not args.no_browser,
                assessment=args.assessment,
            )
        except (FileNotFoundError, OSError) as exc:
            print(f"cinch console: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.command == "assess":
        try:
            return _run_assess(args)
        except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"cinch assess: {exc}", file=sys.stderr)
            return 1
    if args.command == "collect":
        try:
            return _run_collect(args)
        except (NotAuthorized, FileNotFoundError, OSError, TypeError, ValueError) as exc:
            print(f"cinch collect: {exc}", file=sys.stderr)
            return 1
    if args.command == "verify":
        try:
            return _run_verify(args)
        except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"cinch verify: {exc}", file=sys.stderr)
            return 1
    # No subcommand behaves as `serve` so existing MCP client configs keep working.
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())