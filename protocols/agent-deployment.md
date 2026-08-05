# Protocol: Secure AI Agent Deployment

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Active |
| **Frameworks** | CUSTODY, NIST AI RMF, OWASP Agentic AI, LASM, DORA 2025 |

---

## Purpose

Define a repeatable, auditable procedure for deploying an autonomous or semi-autonomous AI agent into any environment. The protocol ensures that every deployment carries enforceable authorization, explicit scope boundaries, supervision gates, and rollback capability before the agent receives live credentials or network access.

An AI agent can be manipulated, compromised, or wrong. Its environment must prevent a bad decision from becoming an unrestricted system action. This protocol operationalises that principle across all six CUSTODY pillars and all seven LASM layers.

**References:**

- CUSTODY Framework — Conditions of Release, Supervision, Traceability, Yield
- NIST AI RMF 1.0 — GOVERN, MAP, MEASURE, MANAGE functions
- NIST AI 600-1 — Generative AI risk profile
- OWASP Top 10 for LLM Applications — LLM01, LLM06
- OWASP Agentic AI — Excessive Agency, Tool Abuse
- LASM — L1 Foundation through L7 Governance
- DORA 2025 — CI/CD stability, deployment automation

---

## Scope

This protocol covers **every** deployment of an AI agent that can read data, invoke tools, execute code, call APIs, or initiate business processes. It applies to:

- New agent deployments
- Updated agent versions or configuration changes
- Agent deployments to new environments (dev, staging, production)
- Multi-agent systems where agents delegate to or coordinate with other agents

It does **not** cover the initial development of the agent model itself (see *harness-setup.md* for the secure development environment).

---

## Phase 1 — Pre-Deployment Authorization

Before any infrastructure is provisioned or credentials issued, the deployment must pass an authorization gate.

### Step 1.1: Define the Authorization Artifact

Produce a machine-readable authorization artifact that specifies:

| Element | Required |
|---|---|
| Agent identity (name, version, image hash) | Yes |
| Permitted tools and APIs (explicit allowlist) | Yes |
| Permitted data sources and destinations | Yes |
| Scope boundaries (task, time window, data domain) | Yes |
| Impact classification (low / medium / high / critical) | Yes |
| Human operator responsible for the deployment | Yes |
| Start and end conditions | Yes |
| Re-authorization criteria for scope changes | Yes |

> **CUSTODY:** Conditions of Release (AC-001, AC-002, AC-003, AC-004)
> **NIST AI RMF:** GOVERN 1.3, MAP 1.5
> **LASM:** L7 Governance

### Step 1.2: Risk and Impact Assessment

1. Classify the agent's maximum potential impact using the CUSTODY impact taxonomy:
   - **Low** — Read-only, no external network access
   - **Medium** — Write access to non-critical systems, limited egress
   - **High** — Write access to production data or infrastructure
   - **Critical** — Can modify security controls, credentials, or financial systems
2. For **High** and **Critical** impact agents, require a formal risk assessment signed by the responsible operator and a security reviewer.
3. Document all trust relationships the agent will participate in (other agents, APIs, services).

> **NIST AI RMF:** MAP 1.1, MAP 1.5, MAP 2.3
> **OWASP:** LLM06-Excessive Agency
> **DORA 2025:** Risk-informed deployment decisions

### Step 1.3: Threat Model Review

1. Review the agent threat model (see `docs/threat-model.md`) against the proposed deployment.
2. Identify which LASM layers are exposed: L1 Foundation, L2 Cognitive, L3 Memory, L4 Tool Execution, L5 Integration, L6 Environment, L7 Governance.
3. For each exposed layer, confirm that at least one CUSTODY control is active.
4. Document residual risks and accepted risks in the deployment record.

> **LASM:** Full-layer threat review
> **CUSTODY:** All six pillars
> **OWASP:** LLM01-Prompt Injection, LLM06-Excessive Agency

---

## Phase 2 — Environment Hardening

### Step 2.1: Provision Isolated Runtime

1. Deploy the agent into an ephemeral sandbox environment (container or VM).
2. Apply immutable image — agent runtime is read-only; no persistent filesystem writes persist across restarts.
3. Set `no-new-privileges`, drop Linux capabilities, enforce SELinux/AppArmor policy.
4. Network micro-segmentation: the agent can reach only explicitly allowlisted services.
5. Default-deny egress — all outbound traffic routes through an allowlisted proxy/gateway.

> **CUSTODY:** Operational Controls (AC-018, AC-019, AC-020), Yield (AC-023, AC-024)
> **LASM:** L6 Environment
> **NIST AI RMF:** MANAGE 2.3

### Step 2.2: Configure Credential Broker

1. Issue credentials through a secret broker only — no hardcoded tokens, no shared service accounts.
2. Credentials must be scoped (least privilege), time-limited (auto-expire on task completion or after a maximum TTL), and auto-rotated.
3. Agent identity must be separate from other agents and from human operators.
4. Confirm the agent cannot read credentials belonging to other agents or users.

> **CUSTODY:** Operational Controls (AC-016), Dependency (AC-021)
> **LASM:** L5 Integration, L6 Environment

### Step 2.3: Configure Supervision Gates

1. For **High** and **Critical** impact agents, configure human-in-the-loop approval gates for every action that modifies production state.
2. For **Medium** impact agents, configure approval gates for any action that exceeds a defined threshold (number of records affected, financial value, scope change).
3. Approval gates must be enforced by an external policy engine — not by agent logic that the agent can modify.
4. Log all approval requests and outcomes to the immutable audit trail.

> **CUSTODY:** Supervision (AC-009, AC-010, AC-011)
> **LASM:** L7 Governance
> **NIST AI RMF:** GOVERN 1.3

### Step 2.4: Configure Untrusted Input Handling

1. Separate the instruction channel from the data channel in agent context.
2. System instructions must take precedence over user input (instruction hierarchy enforcement).
3. Retrieved or ingested content must be parsed in an isolated context.
4. Test with known prompt-injection payloads before granting live access.

> **CUSTODY:** Untrusted Input (AC-005, AC-006)
> **OWASP:** LLM01-Prompt Injection
> **LASM:** L4 Tool Execution

---

## Phase 3 — Logging and Traceability

### Step 3.1: Configure Immutable Audit Logging

1. All agent actions (tool calls, API requests, data accesses, delegation events) must be logged to an immutable append-only store.
2. Each log entry must carry: trace ID, session ID, task ID, agent ID, operator ID, timestamp, action, parameters, and outcome.
3. The agent must not be able to write to, modify, or delete its own audit trail.
4. Separation of duties: the agent runtime, the approval engine, and the log store are separate systems.

> **CUSTODY:** Traceability (AC-013, AC-014, AC-015)
> **NIST AI RMF:** GOVERN 1.7
> **LASM:** L7 Governance

### Step 3.2: Configure Memory Controls

1. If the agent uses session or long-term memory, apply write controls, source labeling, and retention limits.
2. Memory entries must carry provenance metadata (source, timestamp, confidence).
3. Retention policies must be enforced — stale entries are pruned on schedule.
4. Memory writes from untrusted sources must be flagged and quarantined.

> **CUSTODY:** Untrusted Input (AC-008)
> **LASM:** L3 Memory

---

## Phase 4 — Operational Controls

### Step 4.1: Configure Rate Limits and Circuit Breakers

1. Set maximum tool calls per task.
2. Set maximum execution time per task.
3. Set maximum token budget per task.
4. Set maximum recursion depth.
5. Configure circuit breakers that activate on repeated failures (N consecutive failures → pause and escalate to operator).

> **CUSTODY:** Operational Controls (AC-017)
> **OWASP Agentic AI:** Tool abuse prevention

### Step 4.2: Configure Goal Specification and Stop Conditions

1. Each task must have an explicit goal specification with measurable success criteria.
2. Define explicit stop conditions: time limit, error threshold, uncertainty threshold, scope boundary hit.
3. The agent must halt and escalate to the operator when any stop condition is met.
4. Confidence thresholds: if the agent's confidence in its next action falls below a defined level, it must pause and request guidance.

> **CUSTODY:** Supervision (AC-012)
> **LASM:** L2 Cognitive

### Step 4.3: Configure Delegation Controls

1. If the agent can delegate to other agents, all delegation events must be logged with delegator ID, delegate ID, action, and authorization.
2. Delegation must not bypass approval gates — the delegate is subject to the same authorization constraints.
3. Chain-of-action tracing must be maintained across delegation boundaries.

> **CUSTODY:** Traceability (AC-014), Dependency (AC-021)
> **LASM:** L5 Integration

---

## Phase 5 — Pre-Live Verification

### Step 5.1: Checklist Run

Run the **Agent Containment Checklist** (`checklists/agent-containment.yaml`) against the deployment configuration. Every `critical` control must pass. Every `high` control must either pass or have a documented accepted risk.

> **CUSTODY:** Full checklist
> **NIST AI RMF:** MEASURE function

### Step 5.2: Automated Security Tests

1. **Prompt injection test suite** — Run known prompt-injection payloads against the agent and verify that instruction hierarchy holds.
2. **Scope boundary test** — Attempt actions outside the authorized scope and verify they are blocked at the infrastructure level.
3. **Credential isolation test** — Verify the agent cannot read credentials belonging to other agents or users.
4. **Egress test** — Verify the agent cannot reach non-allowlisted network destinations.
5. **Privilege escalation test** — Verify the agent cannot gain root or admin privileges.
6. **Persistence test** — Verify the agent cannot create scheduled tasks, modify startup scripts, or install system packages.
7. **Audit integrity test** — Verify the agent cannot modify or delete its own audit trail.

> **CUSTODY:** All pillars
> **LASM:** All layers
> **OWASP:** LLM01, LLM06

### Step 5.3: Operator Sign-Off

1. The responsible human operator reviews and signs off on:
   - The authorization artifact
   - The risk assessment
   - The checklist results
   - The test results
2. Sign-off is recorded in the deployment record with timestamp and operator identity.
3. For **Critical** impact agents, a second security reviewer must also sign off.

> **NIST AI RMF:** GOVERN 1.3
> **CUSTODY:** Supervision (AC-009)

---

## Phase 6 — Go-Live

### Step 6.1: Deploy with Monitoring

1. Deploy the agent to the production environment with all controls active.
2. Enable real-time monitoring dashboards for: action rate, error rate, approval request rate, scope boundary hits, and circuit-breaker activations.
3. Set alerts for: scope boundary violations, credential access anomalies, unexpected egress, audit log gaps, and rate-limit thresholds.

> **CUSTODY:** Operational Controls (AC-017), Traceability (AC-013)
> **NIST AI RMF:** MANAGE function
> **DORA 2025:** Monitoring and observability

### Step 6.2: Verify Controls in Production

1. Re-run a subset of security tests against the live deployment.
2. Confirm that all controls that were verified in staging are still active in production.
3. Confirm monitoring and alerting are functional.

> **NIST AI RMF:** MEASURE function
> **DORA 2025:** Continuous verification

---

## Phase 7 — Ongoing Operations

### Step 7.1: Continuous Monitoring

1. Monitor agent actions against the authorization artifact — flag any drift.
2. Review audit logs on a schedule defined by impact classification:
   - **Critical**: continuous automated review + daily human review
   - **High**: daily automated review + weekly human review
   - **Medium**: weekly automated review + monthly human review
   - **Low**: monthly automated review
3. Track and review all scope-change requests.

> **NIST AI RMF:** MANAGE function
> **CUSTODY:** Supervision, Traceability

### Step 7.2: Incident Escalation

If a security event occurs during operation, follow the **Incident Response Protocol** (`protocols/incident-response.md`).

> **Cross-reference:** incident-response.md

### Step 7.3: Decommissioning

When the agent's task is complete or the deployment window closes:

1. Revoke all credentials immediately.
2. Destroy the sandbox environment — do not reuse for a different task.
3. Archive audit logs per retention policy.
4. Conduct a post-deployment review: did the agent stay within scope? Were there any near-misses?
5. Update the threat model if new attack vectors were discovered.

> **CUSTODY:** Yield (AC-024, AC-025)
> **LASM:** L6 Environment

---

## Verification

| Gate | Verification Method | Pass Criteria |
|---|---|---|
| Authorization artifact | Review | Exists, complete, signed |
| Risk assessment | Review | Completed, signed, residual risks documented |
| Environment hardening | Automated test suite | All tests pass |
| Checklist run | `checklist_run agent-containment` | All critical items pass; high items pass or have accepted risk |
| Security tests | Automated test suite | All 7 test categories pass |
| Operator sign-off | Deployment record | Recorded with timestamp and identity |
| Production verification | Automated test suite (subset) | Controls confirmed active |
| Monitoring | Dashboard check | Dashboards and alerts functional |

---

## Rollback

If any gate fails, or if a security event occurs during deployment:

1. **Immediate halt** — Trigger the agent's stop conditions. If the agent does not halt, the policy engine forces termination.
2. **Credential revocation** — All credentials issued to the agent are revoked immediately.
3. **Environment destruction** — The sandbox environment is destroyed and recreated from a trusted image.
4. **Audit log preservation** — All audit logs are preserved and write-protected before environment destruction.
5. **Root cause analysis** — Conduct using the preserved audit trail.
6. **Re-deployment** — After root cause is addressed, repeat from Phase 1. Do not skip phases.

> **CUSTODY:** Yield (AC-024), Supervision (AC-011)
> **DORA 2025:** Rollback capability for every deployment