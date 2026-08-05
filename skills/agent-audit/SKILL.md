---
name: agent-audit
description: >
  Audit an AI agent deployment against the CUSTODY containment framework and
  LASM threat model. Checks identity, input handling, supervision, traceability,
  operational controls, dependency management, and yield/teardown.
  Maps findings to NIST AI RMF, OWASP, CUSTODY pillars, and LASM layers.
triggers:
  - audit the ai agent
  - check agent containment
  - review agent security
  - assess agent deployment
  - custody audit
  - agent security review
tools:
  - read_file
  - search_files
  - terminal
  - patch
  - write_file
---

# Agent Audit Skill

Audit an AI agent deployment against the CUSTODY containment framework and LASM threat model.

## Separation of Duties

An agent auditing the host it runs on is a **self-audit**: the auditor and the
audited are the same actor. A compromised or wrong agent can mark every control
"pass" without verifying it. This skill enforces separation of duties:

- **Default: no self-audit.** When the target host is the host this skill is
  running on, the skill **refuses** the audit unless `--self-audit` is
  explicitly passed. A self-audit result is labeled **advisory only** and is
  never treated as verified evidence.
- **Verify the environment out of band.** The host/container controls in
  `checklists/agent-environment.yaml` (AE-001 through AE-011) **must** be
  verified using a signed `agent-environment-evidence.json` bundle produced by
  an independent collector running the `evidence-collect` protocol — not by
  asking the agent about its own posture.
- **Verify the signature, not the narrative.** Consume the evidence bundle
  only after verifying its detached signature against a collector public key
  obtained independently of the agent. Reject any bundle older than the
  deployment's freshness window (default 24 hours).

## Steps

1. **Identify the target** — Confirm the agent deployment to audit. Collect:
   - Agent name, version, and purpose
   - Deployment environment (OS, container, cloud)
   - Connected tools, APIs, and data sources
   - Identity and credential configuration
   - Network and egress configuration
   - Logging and monitoring setup

2. **Load the agent-containment checklist** — Read `checklists/agent-containment.yaml` and use it as the audit framework. Each item has an ID (AC-001 through AC-025), CUSTODY pillar, LASM layer, threat, control, severity, and verification.

3. **Audit Conditions of Release (AC-001 to AC-004)**:
   - Does a machine-readable authorization artifact exist?
   - Are task scope boundaries explicit and enforced?
   - Is a tool allowlist in place and enforced by a policy engine?
   - Is a data inventory defined and is access restricted to authorized sources?

4. **Audit Untrusted Input (AC-005 to AC-008)**:
   - Is instruction hierarchy enforced (system > user > data)?
   - Are data and instructions separated in the agent context?
   - Is model provenance verified (hashes, signatures)?
   - Is memory write access controlled with source labels and retention limits?

5. **Audit Supervision (AC-009 to AC-012)**:
   - Are human-in-the-loop approval gates enforced for high-impact actions?
   - Is the Agent Rule of One in effect (one agent, one task, one operator)?
   - Are approval gates enforced by external infrastructure, not agent logic?
   - Are explicit goals, stop conditions, and confidence thresholds defined?

6. **Audit Traceability (AC-013 to AC-015)**:
   - Are all actions logged to an immutable append-only store with trace IDs?
   - Is delegation fully logged with delegator, delegate, action, and result?
   - Are agent runtime, approval engine, and log store separate systems?

7. **Audit Operational Controls (AC-016 to AC-020)**:
   - Are credentials obtained through a secret broker with time-limited scope?
   - Are rate limits, quotas, and circuit breakers in place and externally enforced?
   - Does the agent run as a dedicated non-root account with no-new-privileges?
   - Is egress default-deny with an allowlisted gateway and DLP?
   - Is the workload network-segmented with mTLS and per-service authorization?

8. **Audit Dependency (AC-021 to AC-022)**:
   - Does each agent class have a separate identity, credentials, and network policy?
   - Are tool artifacts signed, verified, and run in isolated contexts?

9. **Audit Yield (AC-023 to AC-025)**:
   - Does the agent run from an immutable image with read-only system paths?
   - Is the environment ephemeral and recreated from a trusted image after each task?
   - Are credentials automatically revoked on task completion or security event?

10. **Score the audit** — For each CUSTODY pillar, calculate compliance:
    - Conditions of Release: AC-001 to AC-004 (4 items)
    - Untrusted Input: AC-005 to AC-008 (4 items)
    - Supervision: AC-009 to AC-012 (4 items)
    - Traceability: AC-013 to AC-015 (3 items)
    - Operational Controls: AC-016 to AC-020 (5 items)
    - Dependency: AC-021 to AC-022 (2 items)
    - Yield: AC-023 to AC-025 (3 items)

11. **Map to LASM layers** — Identify which architectural layers (L1-L7) have gaps and which temporal classes (Immediate, Session, Cross-session, Persistent) are at risk.

12. **Generate the audit report** — Present:
    - Overall compliance score by CUSTODY pillar
    - LASM layer heatmap (L1-L7 × pass/fail)
    - Critical findings requiring immediate remediation
    - Per-item pass/fail with verification evidence
    - Prioritized remediation plan
    - Framework mapping to NIST AI RMF, OWASP, and MITRE ATLAS

13. **Audit the agent environment (AE-001 to AE-011)** — Load
    `checklists/agent-environment.yaml`. These host/container controls must be
    verified **out of band**: consume a signed `agent-environment-evidence.json`
    produced by an independent collector running the `evidence-collect`
    protocol, verify its signature against a collector public key you obtained
    independently of the agent, and confirm it is within the freshness window.
    If the target host is the host this skill runs on and `--self-audit` was not
    passed, **stop** — a self-audit cannot verify AE controls. Record each AE
    item as pass/fail with the evidence field reference, and roll the AE
    results into the report alongside the CUSTODY/LASM findings.

## Pitfalls

- The agent's own configuration is NOT a reliable security boundary. Verify that controls are enforced by infrastructure external to the agent.
- Do not accept "the agent prompt says not to do X" as a control. Controls must be enforced by SELinux, AppArmor, policy engines, network policies, or similar infrastructure.
- Verify credentials are actually time-limited and scoped, not just documented as such.
- Check that logging is actually immutable and append-only, not just "logs exist."
- The audit must cover all 25 items. Skipping items creates blind spots.