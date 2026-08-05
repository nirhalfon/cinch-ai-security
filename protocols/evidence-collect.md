# Protocol: Out-of-Band Evidence Collection for Agent Environment Audit

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Active |
| **Frameworks** | CUSTODY, NIST AI RMF, OWASP Agentic AI, LASM, DORA 2025 |

---

## Purpose

An AI agent that audits the host it runs on is a **self-audit**: the auditor
and the audited are the same actor. A compromised or simply wrong agent can
mark every control "pass" without verifying it. This protocol removes that
conflict of interest by collecting environment evidence **out of band** —
from the host, not from the agent — and emitting a signed JSON bundle an
external auditor (a human, a separate agent, or a separate MCP server)
consumes instead of trusting the running agent's narrative.

It pairs with the `agent-environment.yaml` checklist (AE-001 through AE-011).
Each evidence field maps to one or more AE controls.

**References:**

- CUSTODY Framework — Operational Controls, Traceability, Yield, Dependency
- NIST AI RMF 1.0 — MEASURE function (independent verification)
- OWASP Agentic AI — Excessive Agency, self-attestation limits
- LASM — L6 Environment layer
- DORA 2025 — auditability of automated processes

## Prerequisites

- The collector runs as an identity **independent of the agent** — a sidecar,
  a CI runner, a human operator, or a separate privileged process. It must not
  share the agent's credentials, filesystem namespace, or network policy.
- A signing key available only to the collector (not to the agent), e.g. an
  age/GPG/cosign key or a KMS-backed key, to produce a detached signature.
- `jq` and the standard host inspection tools (`id`, `getcap`, `aa-status`,
  `iptables`/`nft`, `findmnt`, `systemctl`, `cat /proc/...`).

## Steps

1. **Record collector identity and provenance** — Capture who is collecting,
   where, and when (ISO-8601 UTC, from the collector's clock, not the agent's):
   ```json
   { "collector": "<name>", "host": "<hostname>", "collected_at": "<UTC>", "agent_unit": "<systemd unit / container id>" }
   ```

2. **Identity & privilege (AE-001, AE-002)** — Record the agent process's UID/GID
   and `NO_NEW_PRIVS`:
   - `id -u <agent-user>`; the effective UID of the agent process.
   - `systemctl show <agent-unit> | grep -i NoNewPrivileges` (or the container's
     `no-new-privileges` flag).
   - `getcap -r / 2>/dev/null` — file capabilities that could bypass the
     bounding set.
   - `/proc/<pid>/status` lines `CapBnd`, `CapEff`, `CapPrm`, `CapInh`.

3. **Mandatory access control (AE-003, AE-004)** — Record the confinement
   posture:
   - `aa-status` (profiles loaded + mode: enforce vs complain).
   - `ps -Z <pid>` (SELinux label) or `ps -p <pid> -o apparmor` (AppArmor
     profile).
   - The seccomp mode: `/proc/<pid>/status | grep Seccomp` (2 = filter).

4. **Network & egress (AE-005, AE-006)** — Record the egress policy:
   - `iptables -L OUTPUT -n -v` (or `nft list ruleset`).
   - A connectivity probe to a non-allowlisted host — it must **fail**.
   - A probe to the cloud metadata endpoint (`169.254.169.254`) — it must
     **fail** for the agent namespace.

5. **Audit logging (AE-007)** — Record where audit events land:
   - The audit/log destination (remote syslog, object store) and whether the
     agent UID can write to it (it must not be able to).
   - `find /var/log -user <agent-user>` — must be empty.

6. **Secrets delivery (AE-008)** — Record how secrets are materialized:
   - Whether a broker/vault is the source; token TTL at collection time.
   - `grep -RIn -E '(AKIA|ghp_|xoxb|-----BEGIN)' /proc/<pid>/environ` and the
     agent's env — must be empty (no static long-lived secrets).

7. **Image & artifact provenance (AE-009)** — Record the image attestation:
   - Image digest and signature verification result (`cosign verify` or
     equivalent).
   - Presence and hash of the SBOM/AIBOM; the running digest matches the
     signed digest.

8. **Filesystem state (AE-010)** — Record mount options:
   - `findmnt -o TARGET,FSTYPE,OPTIONS` — root and system paths mounted
     read-only; only the working directory is writable and it is `tmpfs`.

9. **Runtime limits (AE-011)** — Record the cgroup limits:
   - `systemctl show <unit> | grep -iE 'CPU|Memory|Tasks|Limit'` or
     `cat /sys/fs/cgroup/<path>/{cpu.max,memory.max,pids.max}`.
   - The configured execution timeout.

10. **Emit and sign the bundle** — Assemble all captured fields into a single
    JSON object keyed by AE control, write it to
    `agent-environment-evidence.json`, and produce a **detached signature** with
    the collector's key:
    ```sh
    jq -S . agent-environment-evidence.json > agent-environment-evidence.canonical.json
    <signer> sign --key <collector-key> agent-environment-evidence.canonical.json \
      > agent-environment-evidence.sig
    ```
    The signature is over the **canonical (sorted-key) JSON** so verification is
    reproducible.

## Verification

An external auditor consumes the bundle by:

1. Verifying the detached signature against the collector's **public** key
   (which the auditor obtained independently, not via the agent).
2. Checking `collector` is an identity distinct from the agent and that
   `collected_at` is recent and from the collector's clock.
3. For each AE control, evaluating the captured field against the control's
   `verification` criterion in `agent-environment.yaml` and recording pass/fail
   with the evidence reference.

A control passes only when the **captured host evidence** satisfies the
criterion — never when the agent asserts it does.

## Rollback

Evidence collection is read-only; no host state changes. If a probe side-effect
is undesirable (e.g. a deliberate failed connection to a non-allowlisted host
appears in logs), note it in the bundle under `probes` so the auditor can
distinguish probe noise from real traffic.

## Separation of Duties (binding rule)

- An agent running on host X **must not** self-audit host X via the
  `agent-audit` skill by default. It consumes a signed `agent-environment-
  evidence.json` produced by an independent collector.
- The `agent-audit` skill refuses a self-audit unless `--self-audit` is
  explicitly passed; a self-audit result is labeled **advisory only** and never
  treated as verified evidence.
- Evidence older than a defined freshness window (e.g. 24 hours, set per
  deployment) is invalid; the auditor must request a fresh collection.