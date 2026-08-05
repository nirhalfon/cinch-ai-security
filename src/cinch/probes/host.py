"""Host probes — the AE-001..AE-011 evidence from ``protocols/evidence-collect.md``.

These read the kernel's own view of the agent process (``/proc``, ``/sys``,
mountinfo, cgroups) rather than asking the agent anything. Everything here is
read-only, and nothing records a secret *value* — only which variable names look
like credential material.

On a non-Linux host almost every probe returns ``unknown``: that is the correct
answer, not a failure of the deployment and not a pass.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess  # nosec B404
from pathlib import Path
from typing import Any

from . import UNKNOWN, Observation, probe, unknown, verdict

PROC = Path("/proc")
# Capabilities that let a holder step outside its intended box entirely.
DANGEROUS_CAPS = {
    "cap_sys_admin": 21,
    "cap_sys_ptrace": 19,
    "cap_sys_module": 16,
    "cap_setuid": 7,
    "cap_setgid": 6,
    "cap_dac_override": 1,
    "cap_sys_chroot": 18,
    "cap_net_admin": 12,
    "cap_net_raw": 13,
    "cap_bpf": 39,
}
SECRET_KEY_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL|SESSION_KEY)",
    re.IGNORECASE,
)
# Broker/vault-issued material is the control, not the violation.
BROKER_HINT_RE = re.compile(r"(VAULT|STS|_TTL|_EXPIR|OIDC|WEB_IDENTITY|IMDS)", re.IGNORECASE)
METADATA_IP = "169.254.169.254"


def is_linux() -> bool:
    return platform.system() == "Linux"


def _read(path: Path) -> str | None:
    """Read a proc/sys file, returning None if absent or not permitted."""
    try:
        return path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def _run(argv: list[str], timeout: float = 4.0) -> str | None:
    """Run a fixed-argv inspection command. No shell, no user-supplied words."""
    if not shutil.which(argv[0]):
        return None
    try:
        # argv is a literal list in this module, never agent-supplied.
        out = subprocess.run(  # nosec B603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else (out.stdout or out.stderr)


def proc_status(pid: int) -> dict[str, str]:
    """Parse ``/proc/<pid>/status`` into a field -> value map."""
    text = _read(PROC / str(pid) / "status") or ""
    fields = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()
    return fields


def decode_caps(hexmask: str) -> list[str]:
    """Decode a /proc capability bitmask into the dangerous capability names it holds."""
    try:
        mask = int(hexmask, 16)
    except ValueError:
        return []
    return sorted(name for name, bit in DANGEROUS_CAPS.items() if mask & (1 << bit))


def _no_linux(control_id: str, name: str) -> Observation:
    return unknown(
        control_id,
        f"Host is {platform.system()}, not Linux — this control's evidence "
        "(/proc, cgroups, netfilter) is not available here. Run the collector on the "
        "host or inside the container that actually runs the agent.",
        name,
        platform=platform.system(),
    )


# ── AE-001 · privilege escalation ────────────────────────────────────────────


@probe("host", "AE-001")
def privilege_posture(pid: int, **_: Any) -> list[Observation]:
    """Non-root UID + NO_NEW_PRIVS + no boundary-crossing file capabilities."""
    name = "privilege_posture"
    if not is_linux():
        return [_no_linux("AE-001", name)]
    st = proc_status(pid)
    if not st:
        return [unknown("AE-001", f"Cannot read /proc/{pid}/status.", name, pid=pid)]
    uid = st.get("Uid", "").split()[0] if st.get("Uid") else ""
    nnp = st.get("NoNewPrivs", "")
    non_root = uid not in ("", "0")
    nnp_set = nnp == "1"
    ok = non_root and nnp_set
    reasons = []
    if not non_root:
        reasons.append(f"process runs as UID {uid or 'unknown'} (root)")
    if not nnp_set:
        reasons.append("NoNewPrivs is not set, so a setuid binary can raise privileges")
    detail = (
        f"Agent PID {pid} runs as UID {uid} with NoNewPrivs={nnp or 'unknown'}."
        if ok
        else "Privilege boundary is weak: " + "; ".join(reasons) + "."
    )
    return [verdict("AE-001", ok, detail, name, uid=uid, no_new_privs=nnp, pid=pid)]


# ── AE-002 · capability surface ──────────────────────────────────────────────


@probe("host", "AE-002")
def capability_surface(pid: int, **_: Any) -> list[Observation]:
    """Effective and bounding capability sets hold nothing that escapes the box."""
    name = "capability_surface"
    if not is_linux():
        return [_no_linux("AE-002", name)]
    st = proc_status(pid)
    if not st.get("CapEff"):
        return [unknown("AE-002", f"Cannot read capability sets for PID {pid}.", name, pid=pid)]
    held = {k: decode_caps(st.get(k, "0")) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd")}
    risky = sorted({c for caps in held.values() for c in caps})
    detail = (
        "No boundary-crossing capabilities in any of the four sets "
        "(inheritable, permitted, effective, bounding)."
        if not risky
        else "Agent holds capabilities that can cross its boundary: " + ", ".join(risky) + "."
    )
    return [verdict("AE-002", not risky, detail, name, capabilities=held, risky=risky)]


# ── AE-003 · mandatory access control ───────────────────────────────────────


@probe("host", "AE-003")
def mac_confinement(pid: int, **_: Any) -> list[Observation]:
    """AppArmor profile enforcing, or SELinux in enforcing mode, for this process."""
    name = "mac_confinement"
    if not is_linux():
        return [_no_linux("AE-003", name)]
    aa = (_read(PROC / str(pid) / "attr" / "current") or "").strip()
    selinux = (_read(Path("/sys/fs/selinux/enforce")) or "").strip()
    aa_confined = bool(aa) and aa not in ("unconfined", "unconfined\x00") and "(enforce)" in aa
    aa_complain = "(complain)" in aa
    se_enforcing = selinux == "1"
    ok = aa_confined or se_enforcing
    if ok:
        detail = (
            f"Process is confined by AppArmor profile {aa!r}."
            if aa_confined
            else "SELinux is in enforcing mode for this host."
        )
    elif aa_complain:
        detail = f"AppArmor profile {aa!r} is in complain mode — it logs but does not block."
    else:
        detail = (
            f"No mandatory access control confines this process (AppArmor label "
            f"{aa or 'absent'!r}, SELinux enforce={selinux or 'absent'})."
        )
    return [verdict("AE-003", ok, detail, name, apparmor=aa, selinux_enforce=selinux)]


# ── AE-004 · syscall filtering ───────────────────────────────────────────────


@probe("host", "AE-004")
def seccomp_filter(pid: int, **_: Any) -> list[Observation]:
    """Seccomp mode 2 (filter) is attached to the agent process."""
    name = "seccomp_filter"
    if not is_linux():
        return [_no_linux("AE-004", name)]
    st = proc_status(pid)
    mode = st.get("Seccomp", "")
    if mode == "":
        return [unknown("AE-004", f"Cannot read Seccomp mode for PID {pid}.", name, pid=pid)]
    modes = {"0": "disabled", "1": "strict", "2": "filter"}
    ok = mode == "2"
    detail = (
        "A seccomp filter (mode 2) is attached, so syscalls outside the allowed set are refused."
        if ok
        else f"Seccomp is {modes.get(mode, mode)} — the syscall surface is unfiltered."
    )
    return [
        verdict(
            "AE-004",
            ok,
            detail,
            name,
            seccomp_mode=mode,
            filters=st.get("Seccomp_filters", ""),
        )
    ]


# ── AE-005 · egress control ──────────────────────────────────────────────────


@probe("host", "AE-005")
def egress_policy(**_: Any) -> list[Observation]:
    """OUTPUT policy is default-deny with an explicit allowlist."""
    name = "egress_policy"
    if not is_linux():
        return [_no_linux("AE-005", name)]
    nft = _run(["nft", "list", "ruleset"])
    ipt = _run(["iptables", "-S"])
    if nft is None and ipt is None:
        return [
            unknown(
                "AE-005",
                "Neither nft nor iptables output is readable (tool missing or the collector "
                "lacks CAP_NET_ADMIN). Re-run the collector with network-inspection privilege.",
                name,
            )
        ]
    text = "\n".join(t for t in (nft, ipt) if t)
    drop = bool(
        re.search(r"^-P OUTPUT (DROP|REJECT)", text, re.MULTILINE)
        or re.search(r"type filter hook output.*policy (drop|reject)", text, re.IGNORECASE)
    )
    accepts = len(re.findall(r"^-A OUTPUT .*-j ACCEPT", text, re.MULTILINE))
    detail = (
        f"Egress is default-deny with {accepts} explicit allow rule(s)."
        if drop
        else "Egress OUTPUT policy is not DROP/REJECT — the agent can reach arbitrary hosts."
    )
    return [verdict("AE-005", drop, detail, name, output_policy_drop=drop, allow_rules=accepts)]


# ── AE-006 · lateral movement / metadata API ─────────────────────────────────


@probe("host", "AE-006")
def lateral_reach(pid: int, **_: Any) -> list[Observation]:
    """Network namespace is separate and the cloud metadata endpoint is unreachable."""
    name = "lateral_reach"
    if not is_linux():
        return [_no_linux("AE-006", name)]
    agent_ns = os.readlink(PROC / str(pid) / "ns" / "net") if (PROC / str(pid)).exists() else ""
    try:
        own_ns = os.readlink(PROC / "self" / "ns" / "net")
    except OSError:
        own_ns = ""
    separate = bool(agent_ns) and bool(own_ns) and agent_ns != own_ns
    reachable = _metadata_reachable()
    ok = (separate or reachable is False) and reachable is not True
    if reachable is True:
        detail = (
            f"The cloud metadata endpoint {METADATA_IP} answered — an agent that reaches it can "
            "mint instance credentials."
        )
    elif reachable is False:
        detail = f"{METADATA_IP} is unreachable" + (
            " and the agent runs in its own network namespace." if separate else " from this host."
        )
    else:
        detail = "Could not determine whether the metadata endpoint is reachable."
    if reachable is None:
        return [unknown("AE-006", detail, name, agent_netns=agent_ns, separate_netns=separate)]
    return [
        verdict(
            "AE-006",
            ok,
            detail,
            name,
            agent_netns=agent_ns,
            collector_netns=own_ns,
            separate_netns=separate,
            metadata_reachable=reachable,
        )
    ]


def _metadata_reachable(timeout: float = 0.6) -> bool | None:
    """True/False if the metadata endpoint answers; None if the check is inconclusive."""
    try:
        with socket.create_connection((METADATA_IP, 80), timeout=timeout):
            return True
    except (TimeoutError, ConnectionRefusedError, OSError):
        return False
    except Exception:  # noqa: BLE001 # pragma: no cover - defensive
        return None


# ── AE-007 · tamper-evident audit trail ──────────────────────────────────────


@probe("host", "AE-007")
def audit_trail(pid: int, **_: Any) -> list[Observation]:
    """Audit log destination is external/append-only and not writable by the agent UID."""
    name = "audit_trail"
    if not is_linux():
        return [_no_linux("AE-007", name)]
    st = proc_status(pid)
    uid = st.get("Uid", "").split()[0] if st.get("Uid") else ""
    forwarding = False
    conf_hits = []
    rsyslog_d = Path("/etc/rsyslog.d")
    extra = sorted(rsyslog_d.glob("*.conf")) if rsyslog_d.is_dir() else []
    for conf in [Path("/etc/rsyslog.conf"), Path("/etc/systemd/journald.conf"), *extra]:
        text = _read(conf) or ""
        if re.search(r"^\s*\*\.\*\s+@@?|ForwardToSyslog=yes|action\(type=\"omfwd\"", text, re.MULTILINE):
            forwarding = True
            conf_hits.append(str(conf))
    auditd = bool(_run(["systemctl", "is-active", "auditd"]))
    local_writable = _agent_can_write(Path("/var/log"), uid)
    ok = forwarding and local_writable is False
    if ok:
        detail = (
            "Audit records are forwarded off-host ("
            + ", ".join(conf_hits)
            + ") and /var/log is not writable by the agent UID."
        )
    elif not forwarding:
        detail = (
            "No off-host log forwarding is configured, so the only audit trail lives on the "
            "host the agent can influence."
        )
    else:
        detail = "Logs are forwarded, but the agent UID can write to /var/log — records are tamperable."
    return [
        verdict(
            "AE-007",
            ok,
            detail,
            name,
            forwarding=forwarding,
            forward_configs=conf_hits,
            auditd_active=auditd,
            log_dir_agent_writable=local_writable,
        )
    ]


def _agent_can_write(path: Path, uid: str) -> bool | None:
    """Whether a process with this UID could write to path, from the mode bits alone."""
    if not uid.isdigit():
        return None
    try:
        st = path.stat()
    except OSError:
        return None
    if st.st_uid == int(uid):
        return bool(st.st_mode & 0o200)
    return bool(st.st_mode & 0o002)


# ── AE-008 · credential handling ─────────────────────────────────────────────


@probe("host", "AE-008")
def credential_exposure(pid: int, **_: Any) -> list[Observation]:
    """No long-lived secrets materialised in the agent's environment.

    Records the *names* of secret-looking variables and never their values.
    """
    name = "credential_exposure"
    if not is_linux():
        return [_no_linux("AE-008", name)]
    raw = _read(PROC / str(pid) / "environ")
    if raw is None:
        return [
            unknown(
                "AE-008",
                f"Cannot read /proc/{pid}/environ (the collector needs to run as an identity "
                "permitted to inspect the agent process).",
                name,
                pid=pid,
            )
        ]
    keys = [entry.split("=", 1)[0] for entry in raw.split("\0") if "=" in entry]
    secretish = [k for k in keys if SECRET_KEY_RE.search(k)]
    brokered = [k for k in secretish if BROKER_HINT_RE.search(k)]
    static = sorted(set(secretish) - set(brokered))
    ok = not static
    detail = (
        "No static credential material in the agent's environment"
        + (f" (brokered/TTL-scoped variables present: {', '.join(sorted(brokered))})." if brokered else ".")
        if ok
        else "Credential material is materialised in the agent's environment: "
        + ", ".join(static)
        + ". These outlive the task and can be read by anything sharing the process view."
    )
    return [
        verdict(
            "AE-008",
            ok,
            detail,
            name,
            secret_variable_names=static,  # names only, never values
            brokered_variable_names=sorted(brokered),
            env_var_count=len(keys),
        )
    ]


# ── AE-009 · runtime integrity ───────────────────────────────────────────────


@probe("host", "AE-009")
def runtime_integrity(pid: int, **_: Any) -> list[Observation]:
    """Image digest is pinned and an SBOM is present alongside the runtime."""
    name = "runtime_integrity"
    if not is_linux():
        return [_no_linux("AE-009", name)]
    cgroup = _read(PROC / str(pid) / "cgroup") or ""
    digest = re.search(r"sha256[-:]([0-9a-f]{64})", cgroup)
    sboms = [
        str(p)
        for p in (
            Path("/usr/share/sbom"),
            Path("/var/lib/sbom"),
            Path("/sbom.spdx.json"),
            Path("/sbom.cdx.json"),
        )
        if p.exists()
    ]
    if not digest and not sboms:
        return [
            unknown(
                "AE-009",
                "No image digest is visible in the process cgroup and no SBOM was found at a "
                "conventional path. Image signature verification happens in the registry/admission "
                "layer — record that evidence from the deploy pipeline instead.",
                name,
                cgroup_has_digest=False,
            )
        ]
    ok = bool(digest) and bool(sboms)
    detail = (
        f"Runtime is pinned to image digest sha256:{digest.group(1)[:16]}… with an SBOM at "
        + ", ".join(sboms)
        + "."
        if ok
        else (
            f"Image digest sha256:{digest.group(1)[:16]}… is pinned but no SBOM accompanies it."
            if digest
            else "An SBOM is present but the running image is not identified by digest."
        )
    )
    return [
        verdict(
            "AE-009",
            ok,
            detail,
            name,
            image_digest=digest.group(0) if digest else "",
            sbom_paths=sboms,
        )
    ]


# ── AE-010 · immutable runtime ───────────────────────────────────────────────


@probe("host", "AE-010")
def immutable_root(pid: int, **_: Any) -> list[Observation]:
    """Root filesystem read-only; only the working directory writable, ideally tmpfs."""
    name = "immutable_root"
    if not is_linux():
        return [_no_linux("AE-010", name)]
    mountinfo = _read(PROC / str(pid) / "mountinfo")
    if mountinfo is None:
        return [unknown("AE-010", f"Cannot read /proc/{pid}/mountinfo.", name, pid=pid)]
    root_ro, writable = None, []
    for line in mountinfo.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        target, opts = parts[4], parts[5]
        ro = "ro," in opts + "," or opts.split(",")[0] == "ro"
        if target == "/":
            root_ro = ro
        elif not ro and not target.startswith(("/proc", "/sys", "/dev")):
            writable.append(target)
    tmpfs_writable = [
        m for m in writable if re.search(rf"tmpfs {re.escape(m)} ", mountinfo) or " tmpfs" in mountinfo
    ]
    ok = root_ro is True
    detail = (
        "Root filesystem is mounted read-only; writable paths: "
        + (", ".join(sorted(writable)) or "none")
        + "."
        if ok
        else "Root filesystem is writable — changes the agent makes survive the task."
    )
    return [
        verdict(
            "AE-010",
            ok,
            detail,
            name,
            root_read_only=root_ro,
            writable_mounts=sorted(writable),
            tmpfs_writable=sorted(set(tmpfs_writable)),
        )
    ]


# ── AE-011 · resource bounds ─────────────────────────────────────────────────


@probe("host", "AE-011")
def resource_limits(pid: int, **_: Any) -> list[Observation]:
    """cgroup limits set for memory, CPU and pids."""
    name = "resource_limits"
    if not is_linux():
        return [_no_linux("AE-011", name)]
    cg = (_read(PROC / str(pid) / "cgroup") or "").strip()
    rel = ""
    for line in cg.splitlines():
        parts = line.split(":")
        if len(parts) == 3 and parts[1] in ("", "cpu,cpuacct", "memory"):
            rel = parts[2]
            break
    base = Path("/sys/fs/cgroup") / rel.lstrip("/")
    limits = {
        "memory.max": (_read(base / "memory.max") or "").strip(),
        "pids.max": (_read(base / "pids.max") or "").strip(),
        "cpu.max": (_read(base / "cpu.max") or "").strip(),
    }
    if not any(limits.values()):
        return [
            unknown(
                "AE-011",
                f"No cgroup v2 limit files readable under {base} — record the limits from the "
                "container/systemd unit definition instead.",
                name,
                cgroup=rel,
            )
        ]
    unbounded = [
        k
        for k, v in limits.items()
        if v in ("", "max") or (k == "cpu.max" and v.startswith("max"))
    ]
    ok = not unbounded
    detail = (
        f"cgroup limits are set: memory={limits['memory.max']}, pids={limits['pids.max']}, "
        f"cpu={limits['cpu.max']}."
        if ok
        else "Unbounded resources: " + ", ".join(unbounded) + " — a runaway loop reaches the host."
    )
    return [verdict("AE-011", ok, detail, name, cgroup=rel, limits=limits, unbounded=unbounded)]


# ── driver ───────────────────────────────────────────────────────────────────


def resolve_pid(pid: int | None = None, unit: str | None = None) -> tuple[int | None, str]:
    """Resolve the agent process to inspect. Returns (pid, how_it_was_resolved)."""
    if pid is not None:
        return pid, "explicit --pid"
    if unit:
        out = _run(["systemctl", "show", "--property=MainPID", "--value", unit]) or ""
        digits = out.strip()
        if digits.isdigit() and int(digits) > 0:
            return int(digits), f"systemd unit {unit}"
        return None, f"systemd unit {unit} (no MainPID)"
    return os.getpid(), "collector process (no --pid given)"


def collect(pid: int | None = None, unit: str | None = None) -> tuple[list[Observation], dict]:
    """Run every host probe against the agent process. Returns (observations, target)."""
    resolved, how = resolve_pid(pid, unit)
    target = {
        "kind": "host",
        "pid": resolved,
        "resolved_by": how,
        "unit": unit or "",
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
    }
    observations: list[Observation] = []
    for fn in probes_for_host():
        if resolved is None:
            observations.extend(
                unknown(cid, f"Could not resolve the agent PID ({how}).", fn.probe_name)
                for cid in fn.control_ids
            )
            continue
        try:
            observations.extend(fn(pid=resolved))
        except Exception as exc:  # noqa: BLE001 - a probe must never take the collector down
            observations.extend(
                unknown(cid, f"Probe raised {type(exc).__name__}: {exc}", fn.probe_name)
                for cid in fn.control_ids
            )
    return observations, target


def probes_for_host() -> list:
    from . import probes_for

    return probes_for("host")


def unresolved_status() -> str:
    return UNKNOWN
