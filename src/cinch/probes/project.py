"""Project probes — what the deployment a running agent was launched from actually says.

Reads the agent's own configuration: MCP tool grants, container/orchestration
manifests, CI workflows, dependency pinning, SBOM and secret handling. This is the
static half of assessing a running agent — the host probes see the process, these
see the authority it was given.

Conservative by design. Positive evidence yields ``pass``; clear negative evidence
(root container, committed secret material, unpinned dependencies) yields ``fail``;
the mere absence of a config keyword yields ``unknown``, because "I did not find a
grep hit" is not proof a control is missing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import Observation, probe, unknown, verdict

# Files we are willing to read, by role. Bounded so a probe run cannot walk a
# whole filesystem, and so the evidence stays explainable.
MCP_CONFIG_NAMES = (".mcp.json", "mcp.json", "claude_desktop_config.json", ".cursor/mcp.json")
COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
LOCKFILES = (
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "Cargo.lock",
)
SBOM_GLOBS = ("*sbom*.json", "*.spdx.json", "*.cdx.json", "sbom/*")
SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)
    (secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)
    \s*[:=]\s*
    ['"]?(?!\s*$)(?!\$\{)(?!\$\()(?!<)(?!your[_-])(?!xxx)(?!changeme)(?!placeholder)
    ([A-Za-z0-9_\-/+=]{16,})
    """
)
MAX_FILE_BYTES = 512_000
# Never walk into vendored or generated trees: their contents are not this
# deployment's posture, and matching inside them produces bogus evidence.
IGNORE_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".tox",
        "vendor",
        "target",
    }
)
# Directories where deployment/orchestration manifests actually live.
MANIFEST_DIRS = ("k8s", "kubernetes", "deploy", "deployment", "manifests", "charts", "infra")


def _ignored(root: Path, path: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(p in IGNORE_DIRS for p in parts)


def _walk(root: Path, patterns: tuple[str, ...], limit: int = 200) -> list[Path]:
    """Recursively collect files matching patterns, skipping vendored trees."""
    out: list[Path] = []
    for pat in patterns:
        for p in root.rglob(pat):
            if len(out) >= limit:
                return out
            if p.is_file() and not _ignored(root, p):
                out.append(p)
    return out


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _find(root: Path, names: tuple[str, ...]) -> list[Path]:
    return [root / n for n in names if (root / n).is_file()]


def _globs(root: Path, patterns: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    for pat in patterns:
        out.extend(p for p in root.glob(pat) if p.is_file())
    return out


def _workflows(root: Path) -> list[Path]:
    wf = root / ".github" / "workflows"
    return sorted(p for p in wf.glob("*.y*ml")) if wf.is_dir() else []


# Build manifests that mark a directory as something that gets *built*.
BUILD_MANIFESTS = (
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "Dockerfile",
)


def is_build_tree(root: Path) -> bool:
    """Whether this directory is a source tree that produces artifacts.

    Supply-chain controls (SBOM, dependency scanning, provenance, signing) are
    properties of a *build*. Pointing the probes at a config or data directory and
    reporting "no SBOM" would be confidently wrong, so those probes abstain unless
    there is something here to build.
    """
    return bool(
        _find(root, BUILD_MANIFESTS)
        or _find(root, LOCKFILES)
        or _workflows(root)
        or (root / ".git").exists()
    )


def _not_a_build_tree(control_ids: tuple[str, ...], root: Path, probe_name: str) -> list[Observation]:
    return [
        unknown(
            cid,
            f"{root.name}/ is not a build tree — no build manifest, CI workflow or repository "
            "was found, so there is nothing here whose supply chain could be assessed. Point the "
            "probe at the source tree the agent is built from.",
            probe_name,
            checked_for=list(BUILD_MANIFESTS[:4]) + [".github/workflows", ".git"],
        )
        for cid in control_ids
    ]


def _rel(root: Path, paths: list[Path]) -> list[str]:
    return [str(p.relative_to(root)) for p in paths]


# ── tool authority: HE-011, AC-003 ───────────────────────────────────────────


@probe("project", "HE-011", "AC-003")
def mcp_tool_grants(root: Path, **_: Any) -> list[Observation]:
    """The agent's MCP config enumerates its servers — an explicit tool inventory."""
    name = "mcp_tool_grants"
    configs = _find(root, MCP_CONFIG_NAMES)
    if not configs:
        return [
            unknown(
                cid,
                "No MCP client config found in the deployment "
                f"({', '.join(MCP_CONFIG_NAMES)}). If tools are granted elsewhere, collect that "
                "config as evidence instead.",
                name,
                searched=list(MCP_CONFIG_NAMES),
            )
            for cid in ("HE-011", "AC-003")
        ]
    servers: dict[str, Any] = {}
    for cfg in configs:
        try:
            data = json.loads(_read(cfg) or "{}")
        except json.JSONDecodeError:
            continue
        for srv, spec in (data.get("mcpServers") or {}).items():
            servers[srv] = {
                "command": (spec or {}).get("command", ""),
                "has_allowlist": bool((spec or {}).get("allowedTools") or (spec or {}).get("tools")),
            }
    if not servers:
        return [
            verdict(
                cid,
                False,
                f"{_rel(root, configs)[0]} declares no MCP servers, so the agent's tool authority "
                "is not described anywhere reviewable.",
                name,
                configs=_rel(root, configs),
            )
            for cid in ("HE-011", "AC-003")
        ]
    with_allowlist = [s for s, v in servers.items() if v["has_allowlist"]]
    ok = len(with_allowlist) == len(servers)
    detail = (
        f"All {len(servers)} MCP server(s) declare an explicit tool allow-list: "
        + ", ".join(sorted(servers))
        + "."
        if ok
        else f"{len(servers)} MCP server(s) configured ({', '.join(sorted(servers))}); "
        f"{len(servers) - len(with_allowlist)} grant every tool the server exposes with no "
        "allow-list, so tool authority is whatever the server ships."
    )
    return [
        verdict(cid, ok, detail, name, servers=servers, configs=_rel(root, configs))
        for cid in ("HE-011", "AC-003")
    ]


# ── isolation: HE-003, AC-018, AC-023 ────────────────────────────────────────


@probe("project", "HE-003", "AC-018", "AC-023")
def container_isolation(root: Path, **_: Any) -> list[Observation]:
    """Container/pod spec runs non-root, drops capabilities, read-only root filesystem."""
    name = "container_isolation"
    files = _find(root, COMPOSE_NAMES) + _find(root, ("Dockerfile",))
    for d in MANIFEST_DIRS:
        files += [p for p in (root / d).rglob("*.y*ml") if p.is_file()] if (root / d).is_dir() else []
    if not files:
        return [
            unknown(
                cid,
                "No container or orchestration manifest found (Dockerfile, compose, k8s/, "
                "deploy/) — isolation posture cannot be read from this deployment.",
                name,
            )
            for cid in ("HE-003", "AC-018", "AC-023")
        ]
    text = "\n".join(_read(p) for p in files)
    non_root = bool(re.search(r"(?im)^\s*(USER\s+(?!root|0\b)\S+|user:\s*['\"]?[1-9])", text)) or bool(
        re.search(r"runAsNonRoot:\s*true", text)
    )
    read_only = bool(re.search(r"(read_only:\s*true|readOnlyRootFilesystem:\s*true)", text))
    cap_drop = bool(re.search(r"(cap_drop|capabilities:\s*\n\s*drop)", text, re.IGNORECASE))
    no_new_privs = bool(re.search(r"(no-new-privileges|allowPrivilegeEscalation:\s*false)", text))
    privileged = bool(re.search(r"(privileged:\s*true)", text))
    found = {
        "non_root": non_root,
        "read_only_root": read_only,
        "cap_drop": cap_drop,
        "no_new_privileges": no_new_privs,
        "privileged": privileged,
    }
    files_rel = _rel(root, files)
    out = []
    # HE-003 / AC-018 — is the runtime boxed in?
    hardened = non_root and (cap_drop or no_new_privs) and not privileged
    if privileged:
        detail = "A container in this deployment is declared `privileged: true` — isolation is off."
    elif hardened:
        detail = (
            "Runtime is confined: non-root user"
            + (", capabilities dropped" if cap_drop else "")
            + (", privilege escalation disabled" if no_new_privs else "")
            + "."
        )
    else:
        missing = [k for k in ("non_root", "cap_drop", "no_new_privileges") if not found[k]]
        detail = "Runtime confinement is incomplete — missing: " + ", ".join(missing) + "."
    out += [
        verdict(cid, hardened, detail, name, findings=found, files=files_rel)
        for cid in ("HE-003", "AC-018")
    ]
    # AC-023 — can changes persist?
    out.append(
        verdict(
            "AC-023",
            read_only,
            "Root filesystem is declared read-only, so agent-made changes do not persist."
            if read_only
            else "No read-only root filesystem is declared — changes the agent writes survive "
            "the task.",
            name,
            findings=found,
            files=files_rel,
        )
    )
    return out


# ── egress: HE-004, AC-019 ───────────────────────────────────────────────────


@probe("project", "HE-004", "AC-019")
def egress_manifest(root: Path, **_: Any) -> list[Observation]:
    """A network policy or proxy allow-list constrains where the agent can talk."""
    name = "egress_manifest"
    manifests: list[Path] = []
    for d in MANIFEST_DIRS:
        manifests += [p for p in (root / d).rglob("*.y*ml") if p.is_file()] if (root / d).is_dir() else []
    files = [p for p in manifests if re.search(r"kind:\s*NetworkPolicy", _read(p))][:10]
    proxy_hits = []
    for cand in (*_find(root, COMPOSE_NAMES), *_globs(root, ("*.env", ".env.example"))):
        if re.search(r"(HTTPS?_PROXY|egress|allowlist|allow_list)", _read(cand), re.IGNORECASE):
            proxy_hits.append(cand)
    if not files and not proxy_hits:
        return [
            unknown(
                cid,
                "No NetworkPolicy manifest or proxy/egress allow-list configuration found in the "
                "deployment — egress posture must come from the host probes or the network layer.",
                name,
            )
            for cid in ("HE-004", "AC-019")
        ]
    text = "\n".join(_read(p) for p in files)
    default_deny = bool(re.search(r"policyTypes:[\s\S]{0,200}Egress", text)) and bool(
        re.search(r"egress:\s*(\[\]|\n\s*-\s*to:)", text)
    )
    detail = (
        "Egress is constrained by a NetworkPolicy with an explicit egress section ("
        + ", ".join(_rel(root, files))
        + ")."
        if default_deny
        else "Egress configuration exists ("
        + ", ".join(_rel(root, files + proxy_hits))
        + ") but no default-deny egress policy is declared."
    )
    return [
        verdict(
            cid,
            default_deny,
            detail,
            name,
            network_policies=_rel(root, files),
            proxy_config=_rel(root, proxy_hits),
        )
        for cid in ("HE-004", "AC-019")
    ]


# ── secrets: HE-005, SC-012, AC-016 ──────────────────────────────────────────


@probe("project", "HE-005", "SC-012", "AC-016")
def secret_handling(root: Path, **_: Any) -> list[Observation]:
    """No credential material committed into the deployment's own configuration.

    Records file and variable names only — never the matched value.
    """
    name = "secret_handling"
    candidates = [
        p
        for p in (
            *_globs(root, ("*.env", ".env", ".env.*", "*.cfg", "*.ini", "*.toml", "*.json")),
            *_find(root, COMPOSE_NAMES),
            *_workflows(root),
        )
        if p.is_file() and ".example" not in p.name and "lock" not in p.name and not _ignored(root, p)
    ][:60]
    hits: list[dict[str, str]] = []
    for p in candidates:
        for m in SECRET_ASSIGN_RE.finditer(_read(p)):
            hits.append({"file": str(p.relative_to(root)), "key_pattern": m.group(1).lower()})
    broker = any(
        re.search(r"(vault|secretsmanager|secret_manager|sops|1password|azure_key_vault|OIDC)", _read(p), re.IGNORECASE)
        for p in candidates
    )
    if hits:
        files = sorted({h["file"] for h in hits})
        detail = (
            f"Credential-shaped literals are committed in {len(files)} file(s): "
            + ", ".join(files[:6])
            + ("…" if len(files) > 6 else "")
            + ". Values were not recorded; rotate them and move to a broker."
        )
        return [
            verdict(cid, False, detail, name, matches=hits[:40], broker_referenced=broker)
            for cid in ("HE-005", "SC-012", "AC-016")
        ]
    if not candidates:
        return [
            unknown(cid, "No configuration files to inspect for embedded secrets.", name)
            for cid in ("HE-005", "SC-012", "AC-016")
        ]
    detail = (
        f"No credential literals in {len(candidates)} inspected config file(s)"
        + ("; a secret broker/vault is referenced." if broker else "; no broker reference found either.")
    )
    return [
        verdict(cid, True, detail, name, files_scanned=len(candidates), broker_referenced=broker)
        for cid in ("HE-005", "SC-012", "AC-016")
    ]


# ── supply chain: SC-001, SC-002, SC-003, SC-008, SC-011 ─────────────────────


@probe("project", "SC-001")
def sbom_present(root: Path, **_: Any) -> list[Observation]:
    """An SBOM ships with the deployment or is generated by CI."""
    name = "sbom_present"
    if not is_build_tree(root):
        return _not_a_build_tree(("SC-001",), root, name)
    files = _globs(root, SBOM_GLOBS)
    ci = [p for p in _workflows(root) if re.search(r"(sbom|cyclonedx|spdx|syft)", _read(p), re.IGNORECASE)]
    ok = bool(files or ci)
    detail = (
        "SBOM present: " + ", ".join(_rel(root, files) or _rel(root, ci)) + "."
        if ok
        else "No SBOM file and no SBOM-generating CI step found."
    )
    return [verdict("SC-001", ok, detail, name, sbom_files=_rel(root, files), ci=_rel(root, ci))]


@probe("project", "SC-002")
def vulnerability_scanning(root: Path, **_: Any) -> list[Observation]:
    """CI scans dependencies for known vulnerabilities."""
    name = "vulnerability_scanning"
    if not is_build_tree(root):
        return _not_a_build_tree(("SC-002",), root, name)
    ci = [
        p
        for p in _workflows(root)
        if re.search(r"(pip-audit|npm audit|trivy|grype|snyk|dependency-review|osv-scanner)", _read(p), re.IGNORECASE)
    ]
    ok = bool(ci)
    detail = (
        "Dependency vulnerability scanning runs in CI: " + ", ".join(_rel(root, ci)) + "."
        if ok
        else "No dependency vulnerability scanner found in CI workflows."
    )
    return [verdict("SC-002", ok, detail, name, workflows=_rel(root, ci))]


@probe("project", "SC-003")
def dependencies_pinned(root: Path, **_: Any) -> list[Observation]:
    """Dependencies resolve to pinned versions, ideally with integrity hashes."""
    name = "dependencies_pinned"
    if not is_build_tree(root):
        return _not_a_build_tree(("SC-003",), root, name)
    locks = _find(root, LOCKFILES)
    if not locks:
        pyproject = root / "pyproject.toml"
        if pyproject.is_file() and re.search(r"dependencies\s*=", _read(pyproject)):
            return [
                verdict(
                    "SC-003",
                    False,
                    "Dependencies are declared in pyproject.toml with version bounds but no "
                    "lockfile carries integrity hashes, so a tampered artifact resolves silently.",
                    name,
                    manifest="pyproject.toml",
                )
            ]
        return [unknown("SC-003", "No dependency manifest or lockfile found.", name)]
    hashed = [p for p in locks if re.search(r"(sha256|sha512|integrity|--hash=)", _read(p))]
    floating = []
    for p in locks:
        if p.name == "requirements.txt":
            for line in _read(p).splitlines():
                s = line.strip()
                if s and not s.startswith("#") and not re.search(r"[=<>~!]=|@|--hash", s):
                    floating.append(f"{p.name}:{s[:40]}")
    ok = bool(hashed) and not floating
    if ok:
        detail = "Dependencies are pinned with integrity hashes in " + ", ".join(_rel(root, hashed)) + "."
    elif floating:
        detail = f"{len(floating)} unpinned dependency line(s), e.g. " + "; ".join(floating[:3]) + "."
    else:
        detail = (
            "Lockfile(s) present ("
            + ", ".join(_rel(root, locks))
            + ") but without integrity hashes, so a tampered artifact resolves silently."
        )
    return [
        verdict(
            "SC-003",
            ok,
            detail,
            name,
            lockfiles=_rel(root, locks),
            hashed=_rel(root, hashed),
            unpinned=floating[:20],
        )
    ]


@probe("project", "SC-006", "SC-008")
def artifact_provenance(root: Path, **_: Any) -> list[Observation]:
    """Release artifacts carry provenance attestation and image signatures are verified."""
    name = "artifact_provenance"
    if not is_build_tree(root):
        return _not_a_build_tree(("SC-006", "SC-008"), root, name)
    wf = _workflows(root)
    prov = [p for p in wf if re.search(r"(slsa|attest-build-provenance|provenance)", _read(p), re.IGNORECASE)]
    sign = [p for p in wf if re.search(r"(cosign|sigstore|notation|image.*sign)", _read(p), re.IGNORECASE)]
    return [
        verdict(
            "SC-006",
            bool(prov),
            "Build provenance attestation runs in CI: " + ", ".join(_rel(root, prov)) + "."
            if prov
            else "No build provenance attestation step found in CI.",
            name,
            workflows=_rel(root, prov),
        ),
        verdict(
            "SC-008",
            bool(sign),
            "Artifact/image signing runs in CI: " + ", ".join(_rel(root, sign)) + "."
            if sign
            else "No image signing or signature verification step found in CI.",
            name,
            workflows=_rel(root, sign),
        ),
    ]


@probe("project", "SC-011")
def ephemeral_ci(root: Path, **_: Any) -> list[Observation]:
    """CI runs on ephemeral, least-privilege runners."""
    name = "ephemeral_ci"
    wf = _workflows(root)
    if not wf:
        return [unknown("SC-011", "No CI workflows found in .github/workflows.", name)]
    text = "\n".join(_read(p) for p in wf)
    hosted = bool(re.search(r"runs-on:\s*(ubuntu|windows|macos)-", text))
    self_hosted = "self-hosted" in text
    least_priv = bool(re.search(r"permissions:\s*\n\s*contents:\s*read", text))
    ok = hosted and not self_hosted and least_priv
    detail = (
        "CI runs on ephemeral hosted runners with read-only default permissions."
        if ok
        else "CI runner posture is weaker than ephemeral+least-privilege: "
        + ", ".join(
            filter(
                None,
                [
                    "self-hosted runners in use" if self_hosted else "",
                    "" if hosted else "no hosted runner declared",
                    "" if least_priv else "no read-only default permissions block",
                ],
            )
        )
        + "."
    )
    return [
        verdict(
            "SC-011",
            ok,
            detail,
            name,
            hosted=hosted,
            self_hosted=self_hosted,
            least_privilege_permissions=least_priv,
        )
    ]


# ── harness runtime bounds: HE-014, HE-016, HE-017, HE-019 ───────────────────

_KEYWORD_CONTROLS = (
    ("HE-014", r"(rate[_-]?limit|ratelimit|throttle|max_requests_per)", "rate limiting"),
    ("HE-016", r"(timeout|deadline|max_duration|execution_timeout)", "execution timeout"),
    ("HE-017", r"(token_budget|max_tokens|cost_budget|budget)", "token/cost budget"),
    ("HE-019", r"(opentelemetry|otel|structlog|trace_id|correlation_id|audit_log)", "traced logging"),
)


@probe("project", *[c[0] for c in _KEYWORD_CONTROLS])
def runtime_bounds(root: Path, **_: Any) -> list[Observation]:
    """Rate limits, timeouts, budgets and traced logging appear in the agent's config/code."""
    name = "runtime_bounds"
    texts: list[tuple[str, str]] = []
    for p in _walk(root, ("*.toml", "*.yaml", "*.yml", "*.json", "*.env", "*.py", "*.ts", "*.js"), 300):
        texts.append((str(p.relative_to(root)), _read(p)))
    out = []
    for cid, pattern, label in _KEYWORD_CONTROLS:
        hits = [f for f, t in texts if re.search(pattern, t, re.IGNORECASE)]
        # A keyword hit shows where to look; it does not prove the limit is enforced at
        # runtime. Both outcomes stay `unknown` so a lead never inflates the grade —
        # the reviewer confirms it and marks the control themselves.
        out.append(
            unknown(
                cid,
                f"Possible {label} configuration to confirm: "
                + ", ".join(hits[:4])
                + ("…" if len(hits) > 4 else "")
                + ". Check the value is enforced at runtime, then mark this control."
                if hits
                else f"No {label} configuration found in the deployment. Absence of a keyword is "
                "not proof the control is missing — verify where this is enforced.",
                name,
                files=hits[:20],
            )
        )
    return out


# ── documentation controls: HE-002, HE-024 ───────────────────────────────────


@probe("project", "HE-002", "HE-024")
def safety_documentation(root: Path, **_: Any) -> list[Observation]:
    """A threat model and an incident-response playbook exist in the deployment."""
    name = "safety_documentation"
    if not is_build_tree(root):
        return _not_a_build_tree(("HE-002", "HE-024"), root, name)
    threat = _walk(root, ("*threat*model*.md",), 5)
    ir = _walk(root, ("*incident*.md", "*runbook*.md"), 5)
    return [
        verdict(
            "HE-002",
            bool(threat),
            "Threat model documented: " + ", ".join(_rel(root, threat)) + "."
            if threat
            else "No threat-model document found in the deployment.",
            name,
            files=_rel(root, threat),
        ),
        verdict(
            "HE-024",
            bool(ir),
            "Incident-response material present: " + ", ".join(_rel(root, ir)) + "."
            if ir
            else "No incident-response playbook or runbook found.",
            name,
            files=_rel(root, ir),
        ),
    ]


# ── driver ───────────────────────────────────────────────────────────────────


def collect(path: Path) -> tuple[list[Observation], dict]:
    """Run every project probe against a deployment directory."""
    from . import probes_for

    root = Path(path).resolve()
    target = {"kind": "project", "path": str(root), "exists": root.is_dir()}
    if not root.is_dir():
        return [], target
    observations: list[Observation] = []
    for fn in probes_for("project"):
        try:
            observations.extend(fn(root=root))
        except Exception as exc:  # noqa: BLE001 - one bad probe must not sink the run
            observations.extend(
                unknown(cid, f"Probe raised {type(exc).__name__}: {exc}", fn.probe_name)
                for cid in fn.control_ids
            )
    return observations, target
