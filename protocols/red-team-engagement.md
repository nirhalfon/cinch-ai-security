# Protocol: AI Red Team Engagement

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Active |
| **Frameworks** | CUSTODY, NIST AI RMF, OWASP Agentic AI, LASM, MITRE ATLAS, DORA 2025 |

---

## Purpose

Define a structured, controlled procedure for conducting adversarial testing (red teaming) of AI agents and their supporting infrastructure. Red team engagements test whether deployed controls actually work under realistic attack conditions, rather than relying on design-time assumptions.

This protocol ensures that red team activities are:

1. **Authorized** — Explicit scope, time window, and authorization prevent the red team from becoming a real threat.
2. **Contained** — Red team actions are bounded and reversible, following the same CUSTODY principles applied to the agents themselves.
3. **Traceable** — All red team actions are logged with the same rigor as agent actions, producing evidence for control verification.
4. **Actionable** — Every finding maps to a specific CUSTODY control, LASM layer, and NIST AI RMF function, enabling direct remediation.

**References:**

- CUSTODY Framework — All six pillars (the red team tests each one)
- NIST AI RMF 1.0 — MEASURE function (adversarial testing)
- NIST AI 600-1 — GenAI red teaming guidance
- OWASP Agentic AI — Attack patterns for autonomous agents
- MITRE ATLAS — Adversarial threat landscape for AI systems
- LASM — L1 through L7 (comprehensive attack surface model)
- DORA 2025 — Continuous testing and deployment verification
- OWASP Top 10 for LLM Applications — LLM01, LLM06

---

## Scope

This protocol covers red team engagements targeting:

- **AI agents** — Autonomous or semi-autonomous systems that read data, invoke tools, execute code, call APIs, or initiate business processes.
- **Agent infrastructure** — Sandbox environments, credential brokers, policy engines, audit systems.
- **Agent integrations** — Tool plugins, APIs, delegation chains, and data sources the agent connects to.
- **Agent supply chain** — Model weights, tool artifacts, dependencies, and configuration.

It does **not** cover:

- Traditional network penetration testing (use your organization's existing pentest procedure).
- Red teaming of the LLM training pipeline (unless the agent's model is the target).

---

## Phase 1 — Planning and Authorization

### Step 1.1: Define Engagement Scope

Produce a formal **Red Team Scope Document** specifying:

| Element | Required |
|---|---|
| Target agent(s) and version(s) | Yes |
| Target environment (staging / production shadow) | Yes |
| Engagement time window (start and end) | Yes |
| Attack categories in scope | Yes |
| Attack categories out of scope | Yes |
| Maximum authorized impact per attack | Yes |
| Rules of engagement (what the red team must NOT do) | Yes |
| Authorized red team identities and credentials | Yes |
| Escalation contact (who to contact if a finding requires immediate action) | Yes |
| Findings classification framework | Yes |

**In-scope attack categories** (select from):

| Category | LASM Layer | CUSTODY Pillar | Example Attacks |
|---|---|---|---|
| Direct prompt injection | L4 | Untrusted Input | Override system instructions via user input |
| Indirect prompt injection | L4, L3 | Untrusted Input | Malicious content in retrieved data |
| Goal hijacking | L2 | Supervision | Alter agent objective through adversarial input |
| Memory poisoning | L3 | Untrusted Input | Inject content into session or long-term memory |
| Excessive agency | L7 | Conditions of Release, Supervision | Perform actions beyond authorized scope |
| Approval bypass | L7, L4 | Supervision | Circumvent approval gates via delegation or chaining |
| Credential theft | L6 | Operational Controls | Access credentials belonging to other agents or users |
| Data exfiltration | L6 | Operational Controls | Transmit data to unauthorized external destinations |
| Tool abuse | L4 | Operational Controls | Use tools in unintended ways; tool-loop DoS |
| Delegation abuse | L5 | Dependency, Traceability | Delegate to bypass controls or hide actions |
| Supply chain | L1, L5 | Dependency | Compromised model weights or tool plugins |
| Persistence | L6 | Yield | Modify environment to survive restart |
| Privilege escalation | L6 | Operational Controls | Gain root or admin privileges |

> **CUSTODY:** Conditions of Release — authorization scope for red team
> **NIST AI RMF:** GOVERN 1.3, MEASURE 2.6
> **MITRE ATLAS:** Technique selection

### Step 1.2: Obtain Authorization

1. The Red Team Lead presents the scope document to the **Authorization Authority** (typically the CISO or designated security lead).
2. The Authorization Authority reviews and signs off on:
   - Scope and time window
   - Maximum authorized impact
   - Rules of engagement
   - Escalation procedures
3. For **production shadow** engagements, a second sign-off from the production system owner is required.
4. The authorization is recorded with timestamp and identity.

> **CUSTODY:** Conditions of Release (AC-001, AC-002), Supervision (AC-009)
> **NIST AI RMF:** GOVERN 1.3

### Step 1.3: Prepare Red Team Infrastructure

1. Issue dedicated red team identities and credentials, separate from any production identity.
2. Configure red team monitoring: all red team actions are logged to a separate, immutable audit trail.
3. Prepare rollback procedures for each attack category (see Phase 4).
4. Confirm that red team actions are **contained** — they cannot affect production data or users unless explicitly authorized.

> **CUSTODY:** Traceability (AC-013), Operational Controls (AC-016, AC-019)
> **LASM:** L6 Environment, L7 Governance

---

## Phase 2 — Reconnaissance and Threat Modeling

### Step 2.1: Review Existing Threat Model

1. Obtain the target agent's threat model (see `docs/threat-model.md`).
2. Identify attack surfaces per LASM layer.
3. Identify which CUSTODY controls are claimed to be active.
4. Note any gaps or assumptions in the threat model.

> **LASM:** Full-layer analysis
> **MITRE ATLAS:** Reconnaissance techniques

### Step 2.2: Review Agent Configuration

1. Obtain the agent's authorization artifact.
2. Review permitted tools, data sources, scope boundaries, and approval gates.
3. Review the agent's runtime environment configuration (sandbox, egress rules, credential broker).
4. Review the agent's audit logging configuration.
5. Identify potential misconfigurations or gaps.

> **CUSTODY:** Conditions of Release, Operational Controls
> **NIST AI RMF:** MAP function

### Step 2.3: Map Attack Paths

For each attack category in scope, identify:

1. **Entry point** — How does the adversary reach the agent? (User input, retrieved data, tool response, API call, memory read/write)
2. **Attack vector** — What technique does the adversary use? (MITRE ATLAS technique)
3. **Target control** — Which CUSTODY control does this attack attempt to bypass?
4. **Expected outcome** — What should happen if the control is effective?
5. **Bypass indicator** — What observable behavior indicates the control was bypassed?

> **MITRE ATLAS:** Attack path mapping
> **CUSTODY:** Control-specific testing
> **LASM:** Cross-layer attack paths

---

## Phase 3 — Execution

### Step 3.1: Execute Attacks per Category

Execute attacks systematically, one category at a time, in order of increasing risk:

#### 3.1.1: Direct Prompt Injection (L4 — Untrusted Input)

**Objective:** Test whether the agent's instruction hierarchy enforcement prevents user input from overriding system instructions.

**Test procedure:**
1. Submit known prompt-injection payloads that attempt to:
   - Override the system prompt
   - Extract the system prompt
   - Change the agent's role or objective
   - Bypass scope boundaries via instruction
2. For each payload, record:
   - Whether the agent followed the injected instruction (bypass) or rejected it (control effective)
   - The exact agent response
   - Any tool calls the agent attempted as a result
3. Verify that instruction hierarchy is enforced at the infrastructure level, not just in the system prompt.

**Expected outcome (control effective):** Agent rejects injected instructions, continues following system instructions, and logs the attempt.

> **OWASP:** LLM01-Prompt Injection
> **CUSTODY:** Untrusted Input (AC-005)
> **LASM:** L4 Tool Execution

#### 3.1.2: Indirect Prompt Injection (L4, L3 — Untrusted Input)

**Objective:** Test whether data-channel separation prevents malicious content in retrieved data from executing as instructions.

**Test procedure:**
1. Inject malicious payloads into data sources the agent retrieves (documents, web pages, API responses).
2. Payloads attempt to:
   - Execute tool calls embedded in data
   - Modify agent memory through retrieved content
   - Redirect agent behavior through data
3. Record whether the agent treats data content as instructions (bypass) or as data (control effective).

> **OWASP:** LLM01
> **CUSTODY:** Untrusted Input (AC-006, AC-008)
> **LASM:** L4 Tool Execution, L3 Memory

#### 3.1.3: Excessive Agency (L7 — Conditions of Release, Supervision)

**Objective:** Test whether the agent can perform actions outside its authorized scope.

**Test procedure:**
1. Attempt actions beyond the authorized scope via:
   - Direct requests to the agent
   - Tool chaining to achieve unauthorized outcomes
   - Parameter manipulation to extend scope
2. Verify that scope boundaries are enforced at the infrastructure level (policy engine), not just by agent logic.
3. Verify that the agent cannot modify its own authorization artifact.

**Expected outcome (control effective):** All out-of-scope actions are blocked by the policy engine. The agent logs the attempt and escalates.

> **OWASP:** LLM06-Excessive Agency
> **CUSTODY:** Conditions of Release (AC-001, AC-002, AC-003), Supervision (AC-009, AC-011)
> **LASM:** L7 Governance

#### 3.1.4: Approval Bypass (L7, L4 — Supervision)

**Objective:** Test whether approval gates can be circumvented through delegation, chaining, or parameter manipulation.

**Test procedure:**
1. Attempt to bypass approval gates by:
   - Delegating the action to another agent
   - Chaining multiple low-impact actions to achieve a high-impact result
   - Splitting a single action into multiple sub-actions
   - Manipulating action parameters to misrepresent impact
2. Verify that approval gates enforce at the infrastructure level and cannot be circumvented by agent strategy.

> **CUSTODY:** Supervision (AC-010, AC-011, AC-012)
> **LASM:** L7 Governance, L4 Tool Execution

#### 3.1.5: Credential Theft (L6 — Operational Controls)

**Objective:** Test whether the agent can access credentials belonging to other agents or users.

**Test procedure:**
1. Attempt to read credential files, environment variables, and secret broker endpoints.
2. Attempt to use the agent's scoped credentials for unauthorized operations.
3. Attempt to access other agents' credentials through shared infrastructure.
4. Verify credential isolation and scoping.

> **CUSTODY:** Operational Controls (AC-016), Dependency (AC-021)
> **LASM:** L6 Environment, L5 Integration

#### 3.1.6: Data Exfiltration (L6 — Operational Controls)

**Objective:** Test whether the agent can transmit data to unauthorized external destinations.

**Test procedure:**
1. Attempt egress to non-allowlisted IP addresses, domains, and ports.
2. Attempt to encode sensitive data in DNS requests, HTTPS headers, or other covert channels.
3. Attempt to use tool outputs as exfiltration vectors.
4. Verify default-deny egress and DLP inspection.

> **CUSTODY:** Operational Controls (AC-019)
> **OWASP:** LLM02-Sensitive Info Disclosure
> **LASM:** L6 Environment

#### 3.1.7: Tool Abuse (L4 — Operational Controls)

**Objective:** Test whether rate limits, circuit breakers, and recursion limits prevent tool abuse.

**Test procedure:**
1. Attempt rapid repeated tool calls (tool-loop DoS).
2. Attempt recursive tool calls (tool A calls tool B calls tool A).
3. Attempt to use tools in unintended ways (creative misuse).
4. Verify that rate limits, circuit breakers, and timeouts activate as configured.

> **CUSTODY:** Operational Controls (AC-017)
> **OWASP Agentic AI:** Tool abuse

#### 3.1.8: Persistence (L6 — Yield)

**Objective:** Test whether the agent can establish persistence in its environment.

**Test procedure:**
1. Attempt to create scheduled tasks or cron jobs.
2. Attempt to modify startup scripts or system packages.
3. Attempt to write to non-volatile storage outside designated paths.
4. Verify that the environment is ephemeral and that persistence mechanisms fail.

> **CUSTODY:** Yield (AC-023, AC-024)
> **LASM:** L6 Environment

#### 3.1.9: Supply Chain (L1, L5 — Dependency)

**Objective:** Test whether compromised model weights or tool plugins would be detected.

**Test procedure:**
1. Verify model integrity hashes at load time.
2. Verify tool artifact signatures.
3. Attempt to substitute a modified model or tool and verify detection.
4. Verify SBOM/AIBOM completeness.

> **CUSTODY:** Untrusted Input (AC-007), Dependency (AC-022)
> **LASM:** L1 Foundation, L5 Integration

### Step 3.2: Document All Findings

For each attack attempt, record:

| Field | Content |
|---|---|
| Finding ID | Unique identifier |
| Attack category | From the taxonomy above |
| LASM layer | Primary layer targeted |
| CUSTODY pillar | Primary pillar targeted |
| MITRE ATLAS technique | If applicable |
| Test procedure | Exact steps executed |
| Result | Control effective / Bypassed / Partial |
| Agent behavior | Exact response, tool calls, and log entries |
| Infrastructure response | Policy engine actions, alerts, blocks |
| Severity | Critical / High / Medium / Low |
| Remediation recommendation | Specific control improvement |

> **NIST AI RMF:** MEASURE function
> **CUSTODY:** Traceability (AC-013)

---

## Phase 4 — Rollback and Cleanup

### Step 4.1: Revert All Red Team Changes

1. Destroy all red team credentials.
2. Revert any changes made to the agent's environment or configuration.
3. Remove any injected test data from agent memory or data stores.
4. Confirm that the environment matches the pre-engagement state.

> **CUSTODY:** Yield (AC-024), Operational Controls (AC-016)

### Step 4.2: Verify Environment Integrity

1. Compare the environment's state against the pre-engagement baseline.
2. Run the Agent Containment Checklist to confirm all controls are still active.
3. Confirm that audit logs captured all red team actions.
4. Confirm that no red team artifacts remain in the environment.

> **CUSTODY:** Traceability (AC-013), Yield (AC-024)
> **NIST AI RMF:** MEASURE function

---

## Phase 5 — Reporting

### Step 5.1: Produce Findings Report

Structure the findings report as follows:

| Section | Content |
|---|---|
| Executive summary | High-level results: number of findings by severity, overall risk posture |
| Methodology | Engagement scope, time window, attack categories tested |
| Findings by category | Detailed findings per attack category with LASM and CUSTODY mapping |
| Control effectiveness matrix | Per-control assessment: effective / bypassed / partially effective |
| Attack path analysis | Cross-layer attack paths discovered |
| Remediation priorities | Ordered by severity and business impact |
| Positive findings | Controls that performed well — reinforce these |

> **NIST AI RMF:** MEASURE 2.6, MANAGE 2.1
> **MITRE ATLAS:** Technique reporting

### Step 5.2: Map Findings to Controls

For each finding, produce a control mapping:

| Finding | CUSTODY Pillar | CUSTODY Control ID | LASM Layer | NIST AI RMF Function | Remediation |
|---|---|---|---|---|---|
| (finding) | (pillar) | (AC-NNN) | (layer) | (function) | (action) |

This mapping enables direct translation from findings to checklist updates, deployment protocol changes, and threat model updates.

> **CUSTODY:** All six pillars
> **NIST AI RMF:** MAP, MEASURE, MANAGE
> **LASM:** All seven layers

### Step 5.3: Update Artifacts

Based on findings, update:

1. **Agent Containment Checklist** — Add new controls or strengthen existing ones.
2. **Threat model** — Add new attack vectors and affected layers.
3. **Agent Deployment Protocol** — Add new verification steps.
4. **Incident Response Protocol** — Add new detection rules and severity patterns.
5. **Red Team Engagement Protocol** — Add new attack procedures for future engagements.

> **NIST AI RMF:** MANAGE — continuous improvement
> **DORA 2025:** Continuous testing and improvement

---

## Verification

| Gate | Verification Method | Pass Criteria |
|---|---|---|
| Scope document | Review | Complete, signed by Authorization Authority |
| Authorization | Deployment record | Recorded with timestamp and identity |
| Red team logging | Audit check | All red team actions logged to immutable store |
| Environment integrity | Baseline comparison | Post-engagement state matches pre-engagement baseline |
| Findings report | Review | All findings mapped to CUSTODY, LASM, and NIST AI RMF |
| Artifact updates | Review | Checklist, threat model, and protocols updated |

---

## Rollback

If a red team action causes unintended impact beyond the authorized scope:

1. **Immediately halt all red team activity.**
2. **Contact the escalation authority** identified in the scope document.
3. **Follow the Incident Response Protocol** (`protocols/incident-response.md`) if the impact constitutes a security event.
4. **Preserve all evidence** — do not attempt to cover the red team's tracks.
5. **Conduct a scope violation review** — determine why the action exceeded authorized impact and update rules of engagement.

> **CUSTODY:** Supervision (AC-009), Yield (AC-024)
> **Cross-reference:** incident-response.md