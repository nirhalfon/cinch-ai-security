# AI Agent Security Review Template

> Copy this template for each security review of an AI agent or AI-assisted
> development harness. Maps findings to Cinch checklist controls (AC/AE/HE/RT/SC/SH)
> and the LASM 7-layer model. Produces an evidence-backed, auditable review.

## 1. Review Scope

| Field | Value |
|---|---|
| System / agent reviewed | [NAME] |
| Version / commit | [VERSION / SHA] |
| Review date | [DATE] |
| Reviewer(s) | [NAME(S)] |
| Review type | [Self / Peer / External / Red Team] |
| Environment | [Dev / Staging / Production] |
| Risk tolerance | [Low / Medium / High] |

## 2. System Summary

- **What the agent does:** [read data / call tools / execute code / initiate
  business processes — describe]
- **Granted authority:** [tools, data sources, APIs, credentials the agent holds]
- **Effective authority (inherited):** [trust relationships, delegated
  credentials, transitive access — what it can actually reach]
- **Capability accretion risks:** [newly added tools, changed scopes, delegation
  chains since last review]

## 3. Threat Assessment (LASM 7 Layers)

For each layer, record the threat surface, identified threats, and the controls
applied. Cite the Cinch control IDs that mitigate each threat.

| Layer | Threat Surface | Identified Threats | Controls Applied (IDs) | Residual Risk |
|---|---|---|---|---|
| L1 Foundation | | | | |
| L2 Cognitive | | | | |
| L3 Memory | | | | |
| L4 Tool Execution | | | | |
| L5 Integration | | | | |
| L6 Environment | | | | |
| L7 Governance | | | | |

## 4. Controls Applied

### 4.1 Agent Containment (CUSTODY pillars — `agent-containment.yaml`)

- [ ] Conditions of Release: machine-readable authorization artifact (AC-001)
- [ ] Untrusted Input: input isolation / prompt-injection defenses (AC-xxx)
- [ ] Supervision: human-in-the-loop gates for high-impact actions (AC-xxx)
- [ ] Traceability: full audit trail of tool calls and decisions (AC-xxx)
- [ ] Operational Controls: rate limits, budgets, egress deny (AC-xxx)
- [ ] Dependency: pinned deps, provenance verification (AC-xxx)
- [ ] Yield: ephemeral state, auto-revoke on completion (AC-xxx)

### 4.2 Harness Engineering (`harness-engineering.yaml`)

- [ ] Least-privilege enforced in harness design (HE-001)
- [ ] Tool boundaries mechanically enforced (HE-xxx)
- [ ] Runtime controls and observability in place (HE-xxx)
- [ ] Prompt-engineering safeguards (HE-xxx)

### 4.3 System Hardening (`system-hardening.yaml`)

- [ ] OS / host hardening (SH-xxx)
- [ ] Network segmentation, default-deny egress (SH-xxx)
- [ ] Access control and identity (SH-xxx)
- [ ] Container security (SH-xxx)

### 4.4 Supply Chain (`supply-chain.yaml`)

- [ ] Dependency management and pinning (SC-xxx)
- [ ] Provenance and integrity (SBOM, signatures) (SC-xxx)
- [ ] Build pipeline security (SC-xxx)

### 4.5 Red Team Coverage (`red-team.yaml`)

- [ ] Prompt-injection testing (RT-xxx)
- [ ] Tool-abuse / excessive-agency testing (RT-xxx)
- [ ] Data-exfiltration testing (RT-xxx)
- [ ] Resilience / failure-mode testing (RT-xxx)

### 4.6 Agent Environment (`agent-environment.yaml`)

> Verify these host/container controls **out of band** via the `evidence-collect`
> protocol — never by trusting the agent's own narrative. A self-audit is
> advisory only.

- [ ] Dedicated non-root UID with no-new-privileges (AE-001)
- [ ] Reduced Linux capability bounding set (AE-002)
- [ ] MAC profile enforced (AppArmor/SELinux) (AE-003)
- [ ] seccomp syscall allowlist (AE-004)
- [ ] Default-deny egress through allowlisted gateway (AE-005)
- [ ] Network namespace isolation; metadata endpoint blocked (AE-006)
- [ ] Append-only external audit log (AE-007)
- [ ] Just-in-time brokered secrets with TTL (AE-008)
- [ ] Signed, verified image + SBOM/AIBOM (AE-009)
- [ ] Read-only rootfs; ephemeral writable state (AE-010)
- [ ] cgroup resource + execution-timeout limits (AE-011)

## 5. Verification Evidence

For each checked control, attach or link the evidence that proves it is
*enforced by architecture*, not merely promised by prompt.

| Control ID | Verification Method | Evidence (link / artifact) | Verified By | Date |
|---|---|---|---|---|
| | | | | |
| | | | | |

> Reminder: functional correctness ≠ security. A control passes only when the
> environment prevents a bad decision from becoming an unrestricted action.

## 6. Gaps and Remediation

| Gap | Affected Control(s) | Severity | Remediation Plan | Owner | Due Date |
|---|---|---|---|---|---|
| | | | | | |

## 7. Sign-off

| Role | Name | Decision | Date |
|---|---|---|---|
| Reviewer | | [Approved / Approved with conditions / Rejected] | |
| System owner | | | |
| Security lead | | | |

## 8. References

- [Cinch checklists](../checklists/) — AC / AE / HE / RT / SC / SH control IDs
- [Cinch mappings](../mappings/) — NIST AI RMF, OWASP, ATLAS, CUSTODY, LASM crosswalks
- [Evidence collection protocol](../protocols/evidence-collect.md) — out-of-band host evidence for AE controls
- [Threat model](../docs/threat-model.md) — LASM 7×4 matrix
- [Incident response protocol](../protocols/incident-response.md)