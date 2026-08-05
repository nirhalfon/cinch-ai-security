# AI Agent Usage Policy Template

> Copy this template and customize for your organization. Replace `[ORGANIZATION]` with your org name.

## 1. Purpose

This policy establishes security requirements for deploying and operating AI agents within [ORGANIZATION]. It implements the Cinch framework, grounded in NIST AI RMF, CISA Secure AI Development Guidelines, OWASP, and the CUSTODY containment framework.

**Core principle:** The model proposes; the architecture authorizes and enforces. Prompts are not a security boundary.

## 2. Scope

This policy applies to all AI agents, AI assistants, and autonomous AI systems that:
- Access [ORGANIZATION] data, systems, or networks
- Execute code, invoke tools, call APIs, or modify infrastructure
- Operate on behalf of [ORGANIZATION] employees or customers
- Process sensitive, confidential, or regulated information

## 3. Definitions

| Term | Definition |
|---|---|
| **AI Agent** | Any system that can reason across steps, use tools, call APIs, retrieve data, maintain memory, delegate tasks, or perform actions |
| **Authorization Artifact** | A machine-readable document defining what an agent may access, change, invoke, or delegate |
| **CUSTODY** | Vendor-neutral control framework for containing autonomous AI agents |
| **LASM** | Layered Attack Surface Model — 7 architectural layers × 4 temporal classes for threat modeling |
| **Granted Authority** | Permissions and scope intentionally assigned to an agent |
| **Effective Authority** | Everything the agent can actually reach or control during execution |
| **Capability Accretion** | The gap between granted and effective authority, expanding over time |

## 4. Agent Deployment Requirements

### 4.1 Conditions of Release (CUSTODY Pillar 1)

Every agent deployment MUST have:
- [ ] A machine-readable authorization artifact (AC-001)
- [ ] Explicit task scope with start and end conditions (AC-002)
- [ ] A tool allowlist enforced by a policy engine (AC-003)
- [ ] A data inventory listing minimum required data sources (AC-004)

### 4.2 Input Handling (CUSTODY Pillar 2)

- [ ] Instruction hierarchy enforced: system > user > data (AC-005)
- [ ] Data and instructions separated in agent context (AC-006)
- [ ] Model provenance verified (hashes, signatures) (AC-007)
- [ ] Memory write access controlled with source labels and retention limits (AC-008)

### 4.3 Supervision (CUSTODY Pillar 3)

- [ ] Human-in-the-loop approval for high-impact actions (AC-009)
- [ ] Agent Rule of One: single agent, single task, single operator (AC-010)
- [ ] Approval gates enforced by infrastructure, not agent prompts (AC-011)
- [ ] Explicit goals, stop conditions, and confidence thresholds (AC-012)

### 4.4 Traceability (CUSTODY Pillar 4)

- [ ] All actions logged to immutable append-only store with trace IDs (AC-013)
- [ ] Delegation events logged with full chain-of-action tracing (AC-014)
- [ ] Agent runtime, approval engine, and log store are separate systems (AC-015)

### 4.5 Operational Controls (CUSTODY Pillar 5)

- [ ] Credentials obtained through secret broker, not environment variables (AC-016)
- [ ] Rate limits, quotas, and circuit breakers enforced externally (AC-017)
- [ ] Agent runs as non-root with no-new-privileges and dropped capabilities (AC-018)
- [ ] Default-deny egress with allowlisted gateway and DLP (AC-019)
- [ ] Workload network-segmented with mTLS and per-service authorization (AC-020)

### 4.6 Dependency (CUSTODY Pillar 6)

- [ ] Each agent class has separate identity, credentials, and network policy (AC-021)
- [ ] Tool artifacts signed, verified, and run in isolated contexts (AC-022)

### 4.7 Yield (CUSTODY Pillar 7)

- [ ] Agent runs from immutable container image (AC-023)
- [ ] Environment is ephemeral — destroyed and recreated after task (AC-024)
- [ ] Credentials automatically revoked on completion or security event (AC-025)

## 5. AI-Assisted Development Requirements

All repositories using AI-assisted development MUST meet AI Harness Scorecard grade C or higher:

### 5.1 Architectural Documentation (20%)
- [ ] ARCHITECTURE.md exists and is current (HE-001)
- [ ] AGENTS.md with project-specific AI instructions (HE-002)
- [ ] ADRs for major decisions (HE-003)
- [ ] Module boundary constraints documented (HE-004)
- [ ] API documentation for public interfaces (HE-005)

### 5.2 Mechanical Constraints (25%)
- [ ] CI enforces linting, formatting, and type checking as blocking gates (HE-006)
- [ ] Automated dependency auditing in CI (HE-007)
- [ ] Unsafe code policy documented and enforced by security linters (HE-008)
- [ ] Conventional commits enforced (HE-009)
- [ ] Type safety enforced in CI (HE-010)

### 5.3 Testing and Stability (25%)
- [ ] Blocking test suite in CI (HE-011)
- [ ] Feature matrix testing across supported configurations (HE-012)
- [ ] Mutation testing configured (HE-013)
- [ ] Property-based testing for critical modules (HE-014)
- [ ] Fuzz testing for security-critical inputs (HE-015)
- [ ] Contract tests for public APIs (HE-016)

### 5.4 Review and Drift Prevention (15%)
- [ ] Code review enforcement — at least one human reviewer (HE-017)
- [ ] Stale documentation detection in CI (HE-018)
- [ ] Scheduled CI runs (at least weekly) (HE-019)
- [ ] PR templates with AI usage disclosure (HE-020)

### 5.5 AI-Specific Safeguards (15%)
- [ ] Documented AI usage norms (HE-021)
- [ ] Small batch enforcement (max 400 lines) (HE-022)
- [ ] Design-before-code culture (HE-023)
- [ ] Error handling policy documented (HE-024)
- [ ] Security-critical path marking (HE-025)

## 6. Incident Response

See [AI Incident Response Protocol](../protocols/incident-response.md).

## 7. Red Team Testing

See [AI Red Team Engagement Protocol](../protocols/red-team-engagement.md).

## 8. Review and Updates

This policy is reviewed annually and updated when:
- New AI agent types are deployed
- New threat intelligence is received
- Framework mappings are updated
- After any AI security incident

## 9. References

| Reference | Description |
|---|---|
| NIST AI RMF 1.0 | AI Risk Management Framework |
| NIST AI 600-1 | Generative AI Profile |
| CISA Guidelines | Secure AI System Development |
| OWASP Top 10 LLM | LLM Application Security Risks |
| OWASP Agentic AI | Agent Threat Modeling |
| MITRE ATLAS | Adversarial Threat Landscape |
| CUSTODY Framework | Autonomous Agent Containment |
| LASM | Layered Attack Surface Model |
| AI Harness Scorecard | Engineering Safeguards for AI-Assisted Dev |

## 10. Approval

| Role | Name | Date |
|---|---|---|
| CISO | [NAME] | [DATE] |
| Engineering Lead | [NAME] | [DATE] |
| AI/ML Lead | [NAME] | [DATE] |
| Legal | [NAME] | [DATE] |