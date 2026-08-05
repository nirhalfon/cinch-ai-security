# Architecture Decision Record: AI Agent Deployment

> Template for documenting architecture decisions about AI agent deployments.
> Based on the ADR format from michaelnygard/adr and Cinch.

## Title

[Short title describing the decision]

## Status

[Proposed | Accepted | Deprecated | Superseded by ADR-XXX]

## Date

[YYYY-MM-DD]

## Decision Drivers

- [ ] CUSTODY containment requirements
- [ ] NIST AI RMF compliance
- [ ] CISA Secure AI Development Guidelines
- [ ] OWASP Top 10 for LLM Applications
- [ ] Organizational risk tolerance

## Context

Describe the technical and business context that motivates this decision. Include:

- What AI agent or system is being deployed
- What tools, APIs, data sources, and actions it will access
- What users or systems it will interact with
- What environment it will run in (OS, container, cloud)

## Decision

Describe the decision made. Include:

- Authorization artifact details (AC-001)
- Tool allowlist (AC-003)
- Data inventory (AC-004)
- Supervision model (AC-009, AC-010)
- Operational controls (AC-016–AC-020)
- Yield and teardown plan (AC-023–AC-025)

## CUSTODY Classification

| Axis | Value | Rationale |
|---|---|---|
| **Level** | L1–L6 | [How much behavior can be fixed at design time?] |
| **Mandate** | Observational / Operational / Adversarial | [What is the agent's purpose?] |
| **Reach** | R0 Isolated / R1 Internal / R2 Partner / R3 External | [What can the agent affect?] |

## LASM Threat Model

| Layer | Threat | Control |
|---|---|---|
| L1 Foundation | [e.g., Model poisoning] | [e.g., Hash verification, signed artifacts] |
| L2 Cognitive | [e.g., Goal hijacking] | [e.g., Explicit goals, stop conditions] |
| L3 Memory | [e.g., Memory poisoning] | [e.g., Source labels, retention limits] |
| L4 Tool Execution | [e.g., Indirect injection] | [e.g., Data-instruction separation] |
| L5 Integration | [e.g., Hidden delegation] | [e.g., Delegation logging] |
| L6 Environment | [e.g., Privilege escalation] | [e.g., Non-root, no-new-privileges] |
| L7 Governance | [e.g., Audit evasion] | [e.g., Immutable logging] |

## Consequences

### Positive

- [List benefits of this decision]

### Negative

- [List risks and trade-offs]

### Risks and Mitigations

| Risk | Severity | Mitigation | Checklist Reference |
|---|---|---|---|
| [e.g., Prompt injection] | Critical | [e.g., Instruction hierarchy enforcement] | AC-005 |

## Checklist Compliance

| Checklist Item | Status | Notes |
|---|---|---|
| AC-001 Authorization artifact | [ ] | |
| AC-003 Tool allowlist | [ ] | |
| AC-005 Instruction hierarchy | [ ] | |
| AC-009 Human approval gates | [ ] | |
| AC-016 Secret broker | [ ] | |
| AC-018 Non-root execution | [ ] | |
| AC-019 Default-deny egress | [ ] | |
| AC-024 Ephemeral environment | [ ] | |

## References

- [Cinch Checklists](../checklists/)
- [CUSTODY Framework](https://github.com/malwarejake/CUSTODY-framework)
- [LASM](https://github.com/yuval14/Artificial-Intelligence-Cyber-Shield)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)