# Protocol: AI Incident Response

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Active |
| **Frameworks** | CUSTODY, NIST AI RMF, OWASP Agentic AI, LASM, DORA 2025 |

---

## Purpose

Define a structured, repeatable procedure for responding to security incidents involving AI agents. AI incidents differ from traditional security incidents in three critical ways:

1. **Speed of action** — An autonomous agent can execute thousands of actions per minute, making response time critical.
2. **Novel attack surface** — Prompt injection, goal hijacking, and memory poisoning are AI-specific attack vectors that traditional incident response may not cover.
3. **Accountability ambiguity** — When an agent takes a harmful action, the causal chain spans the model, the prompt, the operator, and the infrastructure, complicating attribution.

This protocol maps each response phase to CUSTODY pillars, LASM layers, and NIST AI RMF functions so that every action is traceable to a framework control.

**References:**

- CUSTODY Framework — Supervision, Traceability, Yield
- NIST AI RMF 1.0 — MANAGE function (incident handling)
- NIST AI 600-1 — GenAI incident categories
- OWASP Top 10 for LLM Applications — LLM01, LLM06
- OWASP Agentic AI — Tool abuse, delegation abuse
- LASM — L2 Cognitive, L4 Tool Execution, L6 Environment, L7 Governance
- DORA 2025 — Incident classification, rollback, and change failure rate tracking
- MITRE ATLAS — Adversarial AI incident patterns

---

## Scope

This protocol covers **all** security events involving AI agents, including but not limited to:

- **Prompt injection** (direct or indirect) — User input or external data overrides agent instructions
- **Excessive agency** — Agent performs actions beyond its authorized scope
- **Goal hijacking** — Agent objective altered by adversarial input
- **Memory poisoning** — Agent session or long-term memory corrupted
- **Credential theft** — Agent reads or exfiltrates credentials
- **Data exfiltration** — Agent transmits sensitive data to unauthorized destinations
- **Tool abuse** — Agent uses tools in unintended ways (tool-loop DoS, privilege escalation via tool)
- **Delegation abuse** — Agent delegates actions to bypass approval gates
- **Supply chain compromise** — Compromised model weights, tool plugins, or dependencies
- **Environment compromise** — Agent modifies its runtime environment for persistence

It does **not** cover general infrastructure incidents unrelated to AI agent behavior (use your organization's existing IR procedure for those).

---

## Severity Classification

| Severity | Criteria | Response Time | Escalation |
|---|---|---|---|
| **P1 — Critical** | Agent has performed or is performing unauthorized actions affecting production data, security controls, or financial systems. Active exfiltration, privilege escalation, or persistence detected. | Immediate (< 5 min) | Incident Commander + Security Lead + Operator |
| **P2 — High** | Agent has attempted unauthorized actions that were blocked by controls, but the attempt indicates a potential compromise or misconfiguration. Scope boundary violation detected. | < 30 min | Security Lead + Operator |
| **P3 — Medium** | Anomaly detected in agent behavior (unusual tool call patterns, rate limit hits, unexpected egress attempts) but no confirmed unauthorized action. | < 4 hours | Operator + Security Review |
| **P4 — Low** | Informational events: audit log anomalies, configuration drift detected, near-miss scope boundary approaches. | < 24 hours | Operator review |

> **NIST AI RMF:** MANAGE 2.3 — Severity and priority classification
> **DORA 2025:** Incident classification and change failure rate tracking

---

## Phase 1 — Detection and Triage

### Step 1.1: Receive Alert

Alerts may arrive from:

- Automated monitoring (rate-limit hits, scope boundary violations, circuit-breaker activations)
- Human operator observation
- External notification (upstream service, user report)
- Audit log review

All alerts enter a single incident queue regardless of source.

> **CUSTODY:** Traceability (AC-013), Operational Controls (AC-017)
> **LASM:** L7 Governance

### Step 1.2: Classify Severity

1. Apply the severity classification table above.
2. Assign an incident ID.
3. Identify the LASM layers involved:
   - L1 Foundation (model compromise)
   - L2 Cognitive (goal hijacking, hallucination)
   - L3 Memory (memory poisoning, data leakage)
   - L4 Tool Execution (tool abuse, injection)
   - L5 Integration (delegation abuse, trust chain)
   - L6 Environment (credential theft, persistence, exfiltration)
   - L7 Governance (authorization bypass, audit evasion)
4. Identify the CUSTODY pillars involved:
   - Conditions of Release (scope violation)
   - Untrusted Input (injection)
   - Supervision (approval bypass, excessive agency)
   - Traceability (audit gap, hidden delegation)
   - Operational Controls (rate limit hit, credential misuse)
   - Dependency (cross-agent compromise, tool supply chain)
   - Yield (persistence, environment compromise)

> **NIST AI RMF:** MANAGE 2.3
> **MITRE ATLAS:** Incident pattern matching

### Step 1.3: Activate Incident Response Team

| Role | Responsibility |
|---|---|
| **Incident Commander** | Overall coordination, decision authority for containment actions |
| **Operator** | Agent's responsible human — knows authorization scope and intent |
| **Security Lead** | Technical investigation, forensics, containment execution |
| **Agent Engineer** | Model behavior analysis, prompt analysis, memory inspection |

For **P1** incidents, all four roles must be engaged immediately.
For **P2**, Incident Commander + Security Lead + Operator.
For **P3/P4**, Operator + Security Lead as needed.

> **NIST AI RMF:** GOVERN 1.3 — Roles and responsibilities

---

## Phase 2 — Containment

The overriding priority in containment is to **stop the agent from taking further unauthorized action** while preserving the audit trail.

### Step 2.1: Immediate Agent Containment (P1/P2)

1. **Activate the agent's stop conditions.** If the agent supports halt signals, send the halt signal.
2. **If the agent does not halt within 30 seconds, force-terminate the agent process.** The policy engine, not the agent, controls termination.
3. **Revoke all credentials** issued to the agent immediately. Confirm revocation with the secret broker.
4. **Enable network isolation** —切断 the agent's sandbox from all external services except the audit log endpoint.
5. **Set the environment to forensic mode** — prevent auto-restart, disable scheduled tasks, preserve filesystem state.

> **CUSTODY:** Supervision (AC-009, AC-011), Yield (AC-024, AC-025), Operational Controls (AC-016)
> **LASM:** L6 Environment, L7 Governance

### Step 2.2: Preserve Evidence

1. **Snapshot the agent's entire runtime state**: filesystem, memory, environment variables, network connections, running processes.
2. **Write-protect all audit logs** — make them immutable and inaccessible to the agent.
3. **Export the agent's session memory** (conversation history, tool call logs, delegation records).
4. **Capture network logs** — all inbound/outbound connections during the incident window.
5. **Record the agent's configuration and authorization artifact** at the time of the incident.

> **CUSTODY:** Traceability (AC-013, AC-014, AC-015)
> **NIST AI RMF:** MEASURE 2.6 — Forensic data preservation

### Step 2.3: Assess Blast Radius

1. Determine what the agent **accessed** (data, services, tools, credentials).
2. Determine what the agent **modified** (files, databases, API state, configuration).
3. Determine what the agent **exfiltrated** (data sent to external endpoints).
4. Determine what the agent **delegated** (actions passed to other agents or services).
5. Determine what the agent **persisted** (scheduled tasks, modified startup scripts, installed packages).
6. Check whether other agents or services were affected (cross-agent compromise — AC-021).

> **LASM:** All layers (comprehensive blast radius)
> **CUSTODY:** Dependency (AC-021, AC-022)

---

## Phase 3 — Investigation

### Step 3.1: Determine Root Cause

Classify the root cause using the following taxonomy:

| Category | Description | LASM Layer |
|---|---|---|
| **Direct prompt injection** | User input overrode agent instructions | L4 |
| **Indirect prompt injection** | External data contained malicious instructions | L4, L3 |
| **Excessive agency** | Agent performed actions beyond authorized scope | L7 |
| **Goal hijacking** | Adversarial input altered the agent's objective | L2 |
| **Memory poisoning** | Corrupted memory affected agent decisions | L3 |
| **Credential theft** | Agent accessed unauthorized credentials | L6 |
| **Tool supply chain** | Compromised tool or plugin | L5 |
| **Model compromise** | Compromised weights or checkpoints | L1 |
| **Configuration error** | Misconfigured scope, credentials, or controls | L7 |
| **Operator error** | Human error in authorization or supervision | L7 |
| **Infrastructure exploit** | Vulnerability in sandbox or runtime | L6 |

> **MITRE ATLAS:** Technique mapping
> **NIST AI RMF:** MAP function — root cause analysis

### Step 3.2: Analyze Agent Behavior

1. **Review the full audit trail** — trace every action from the triggering event forward.
2. **Analyze the agent's context** — inspect the system prompt, user input, and retrieved data at the time of the incident.
3. **Analyze the agent's memory** — check for injected, poisoned, or corrupted entries.
4. **Analyze tool calls** — verify each tool call was within the authorized scope and that the response was expected.
5. **Analyze delegation chains** — trace any delegation to other agents and verify authorization.

> **CUSTODY:** Traceability (AC-013, AC-014)
> **LASM:** L2 Cognitive, L3 Memory, L4 Tool Execution

### Step 3.3: Identify Control Gaps

For each root cause, identify which CUSTODY controls should have prevented or detected the incident:

| CUSTODY Pillar | Question |
|---|---|
| Conditions of Release | Was the authorization artifact correct and complete? |
| Untrusted Input | Were input sanitization and instruction hierarchy enforced? |
| Supervision | Were approval gates active and were they bypassed? |
| Traceability | Was the audit trail complete and immutable? |
| Operational Controls | Were rate limits, egress controls, and credential scoping effective? |
| Dependency | Were agent and tool identities properly isolated? |
| Yield | Was the environment ephemeral and was secure teardown effective? |

> **CUSTODY:** All six pillars
> **NIST AI RMF:** MEASURE function

---

## Phase 4 — Remediation

### Step 4.1: Immediate Fixes

1. **Patch the specific vulnerability** — fix the configuration, update the authorization artifact, patch the tool, or update the model.
2. **Strengthen the failed control** — if a control was bypassed, add defense in depth:
   - If injection bypassed instruction hierarchy, add input sanitization or separate instruction/data channels.
   - If scope boundary was crossed, tighten the authorization artifact and add infrastructure-level enforcement.
   - If approval gate was bypassed, move enforcement further from the agent (policy engine, infrastructure control).
3. **Rotate all credentials** that the agent had access to, even if exfiltration was not confirmed.

> **CUSTODY:** All pillars — strengthen the specific failed control
> **NIST AI RMF:** MANAGE 2.1, 2.2

### Step 4.2: Systemic Improvements

1. **Update the threat model** with the new attack vector.
2. **Update the checklist** — add new controls or strengthen existing ones based on lessons learned.
3. **Update the authorization artifact template** if the incident revealed gaps.
4. **Share findings** with the broader organization and, where appropriate, with the AI security community.

> **NIST AI RMF:** MANAGE function — continuous improvement
> **DORA 2025:** Post-incident review and process improvement

---

## Phase 5 — Recovery

### Step 5.1: Environment Recovery

1. **Destroy the compromised sandbox entirely** — do not attempt in-place remediation.
2. **Rebuild from a trusted immutable image** with the updated controls and patches.
3. **Re-issue credentials** through the secret broker with updated scope and TTL.
4. **Re-apply monitoring and alerting** and verify they are functional.

> **CUSTODY:** Yield (AC-024), Operational Controls (AC-016)
> **LASM:** L6 Environment

### Step 5.2: Agent Recovery

1. **Re-deploy the agent** following the full Agent Deployment Protocol (`protocols/agent-deployment.md`). Do not skip phases.
2. **Start in shadow mode** — agent operates but all actions are logged and none are executed in production until verified.
3. **Gradually restore production access** — progress through approval gates before full autonomy.

> **Cross-reference:** agent-deployment.md
> **DORA 2025:** Progressive rollout and rollback capability

### Step 5.3: Data Recovery

1. **Assess data integrity** — verify that data the agent accessed or modified is consistent and correct.
2. **Restore from backups** if data was corrupted or exfiltrated.
3. **Notify affected parties** if personal or sensitive data was exfiltrated, per regulatory requirements.

> **NIST AI RMF:** MANAGE 2.3
> **DORA 2025:** Data integrity verification

---

## Phase 6 — Post-Incident Review

### Step 6.1: Incident Report

Produce a structured incident report containing:

| Section | Content |
|---|---|
| Executive summary | What happened, impact severity, root cause category |
| Timeline | Detection time, containment time, remediation time, recovery time |
| Root cause analysis | Detailed technical analysis with LASM layer mapping |
| Control failure analysis | Which CUSTODY controls failed and why |
| Blast radius | What was accessed, modified, exfiltrated, or persisted |
| Remediation actions | Immediate fixes and systemic improvements |
| Lessons learned | What to change in deployment, controls, or monitoring |

> **NIST AI RMF:** MANAGE function
> **DORA 2025:** Post-incident review documentation

### Step 6.2: Metrics

Track and report the following metrics:

| Metric | Definition |
|---|---|
| Time to detect | From event occurrence to alert |
| Time to contain | From alert to agent halt and credential revocation |
| Time to remediate | From containment to patched controls |
| Time to recover | From remediation to full production operation |
| Blast radius | Number of systems, data records, or credentials affected |
| Change failure rate | Whether the remediation itself caused further incidents |

> **DORA 2025:** DORA metrics — change failure rate, recovery time
> **NIST AI RMF:** MEASURE function

### Step 6.3: Update Controls and Procedures

1. Update the **Agent Containment Checklist** with new controls or strengthened existing controls.
2. Update the **Agent Deployment Protocol** if deployment gaps contributed to the incident.
3. Update the **threat model** with the new attack vector.
4. Update **monitoring and alerting** rules to detect similar incidents earlier.
5. If the incident involved a novel attack technique, consider a **Red Team Engagement** (`protocols/red-team-engagement.md`).

> **Cross-reference:** red-team-engagement.md
> **NIST AI RMF:** MANAGE — continuous improvement

---

## Verification

| Gate | Verification Method | Pass Criteria |
|---|---|---|
| Agent halted | Process check | Agent process no longer running; no active credentials |
| Evidence preserved | Forensic snapshot | Complete filesystem, memory, network, and audit log snapshots exist and are write-protected |
| Root cause identified | Incident report | Root cause classified in taxonomy; LASM layers and CUSTODY pillars mapped |
| Controls updated | Checklist review | New or strengthened controls address the root cause |
| Environment rebuilt | Deployment verification | Fresh sandbox from trusted image; all controls active |
| Monitoring active | Dashboard check | Monitoring and alerting functional and updated with new detection rules |

---

## Rollback

If remediation fails or causes further issues:

1. **Re-halt the agent** immediately.
2. **Revoke all credentials** again.
3. **Destroy the environment** again and rebuild from the original trusted image.
4. **Escalate** to the Incident Commander and Security Lead.
5. **Consider full production freeze** if the incident affects shared infrastructure.

> **CUSTODY:** Yield (AC-024), Supervision (AC-009)
> **DORA 2025:** Rollback capability for every change