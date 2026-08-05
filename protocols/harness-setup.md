# Protocol: Secure AI Development Harness Setup

| Field | Value |
|---|---|
| **Version** | 1.0.0 |
| **Status** | Active |
| **Frameworks** | CUSTODY, NIST AI RMF, OWASP, LASM, DORA 2025 |

---

## Purpose

Define the procedure for setting up a secure development harness — the controlled environment where AI-assisted or AI-autonomous development takes place. The development harness is the first and most critical layer of defense: if the environment where AI writes, reviews, or deploys code is compromised, all downstream controls are undermined.

Research shows that while 47.5% of AI-generated code may be functionally correct, only 8.25% is also secure ([ICLR 2026 vibe-coding benchmark](https://openreview.net/forum?id=rs6rRCEixQ)). Functional correctness ≠ security. The harness must enforce this distinction at the infrastructure level, not rely on the model's judgment.

This protocol operationalizes that principle, mapping each setup step to CUSTODY pillars, LASM layers, and NIST AI RMF functions.

**References:**

- CUSTODY Framework — Conditions of Release, Operational Controls, Yield
- NIST AI RMF 1.0 — GOVERN, MAP, MEASURE, MANAGE functions
- NIST AI 600-1 — Secure development practices for GenAI
- CISA Guidelines for Secure AI System Development
- OWASP Top 10 for LLM Applications — LLM01, LLM02, LLM06
- OWASP Agentic AI — Agent development controls
- LASM — L1 Foundation, L4 Tool Execution, L6 Environment, L7 Governance
- DORA 2025 — CI/CD stability, deployment automation, change failure rate
- AI Harness Scorecard — Engineering safeguards for AI-assisted development

---

## Scope

This protocol covers the setup of a **secure development harness** — the environment where:

- AI agents write, review, test, and deploy code
- AI agents interact with version control, CI/CD pipelines, and cloud infrastructure
- Developers use AI-assisted coding tools (copilots, code generators, autonomous agents)
- AI agents manage infrastructure, configuration, or operational tasks

It applies to:

- Local development machines
- Cloud development environments (CDEs, dev containers)
- CI/CD pipelines where AI agents have write access
- Staging and testing environments where AI agents operate

It does **not** cover:

- Production deployment environments (see `protocols/agent-deployment.md`)
- Production incident response (see `protocols/incident-response.md`)

---

## Phase 1 — Foundation and Model Integrity

### Step 1.1: Verify Model Provenance

Before loading any AI model into the harness, verify its integrity and provenance.

1. **Obtain model from a trusted source** — Official distribution channel, verified repository, or trusted model hub.
2. **Verify integrity hashes** — Compare SHA-256 hashes against published values. Do not load models with hash mismatches.
3. **Verify model signatures** — If the model provider signs artifacts, verify the signature at load time.
4. **Maintain an AI Bill of Materials (AIBOM)** — Document the model name, version, source, hash, signature, and all dependencies (tokenizer, config, license, safety filters).
5. **Pin model versions** — Never use `latest` tags in production harness configurations. Pin to a specific version and hash.

> **CUSTODY:** Untrusted Input (AC-007)
> **LASM:** L1 Foundation
> **NIST AI RMF:** MAP 2.3 — Supply chain risk management
> **ETSI GR SAI 005:** Model integrity verification

### Step 1.2: Configure Model Safety Filters

1. **Enable available safety filters** — content filters, output classifiers, and refusal mechanisms provided by the model vendor.
2. **Configure guardrails** — Define input and output constraints appropriate for the development context:
   - Input: Block known injection patterns, enforce length limits, validate format.
   - Output: Block code patterns that match known vulnerabilities, enforce style and security rules.
3. **Test safety filters** — Run a validation suite of known-bad inputs and verify they are blocked or flagged.
4. **Document filter configuration** — Record which filters are active and their settings in the harness configuration.

> **OWASP:** LLM01-Prompt Injection
> **NIST AI 600-1:** Content provenance and safety

### Step 1.3: Establish Instruction Hierarchy

1. **Define instruction priority order** — System instructions > developer instructions > tool results > user input.
2. **Implement instruction hierarchy in the runtime** — Not just in the prompt, but in the agent framework's context handling:
   - System prompt is injected at the highest priority and cannot be overridden.
   - Developer instructions are injected at the next priority.
   - User input and tool results are treated as untrusted data.
3. **Test instruction hierarchy** — Attempt prompt injection via user input and verify that system instructions take precedence.
4. **Document instruction hierarchy** — Record the priority order and enforcement mechanism in the harness configuration.

> **CUSTODY:** Untrusted Input (AC-005, AC-006)
> **OWASP:** LLM01-Prompt Injection
> **LASM:** L4 Tool Execution

---

## Phase 2 — Environment Hardening

### Step 2.1: Provision Isolated Development Environment

1. **Use ephemeral, immutable environments** — Containers or VMs that are destroyed and recreated from trusted images. No persistent state between sessions.
2. **Apply principle of least privilege** — The AI agent runs as a dedicated non-root user with minimal capabilities.
3. **Set `no-new-privileges`** — Prevent privilege escalation via setuid binaries.
4. **Drop Linux capabilities** — Remove all capabilities except those explicitly required.
5. **Enforce SELinux or AppArmor policy** — Confine the agent to specific file paths, network endpoints, and system calls.
6. **Use read-only filesystem for system paths** — `/usr`, `/etc`, `/bin` are mounted read-only. Only designated workspace paths are writable.

> **CUSTODY:** Operational Controls (AC-018), Yield (AC-023, AC-024)
> **LASM:** L6 Environment
> **DORA 2025:** Immutable infrastructure

### Step 2.2: Configure Network Controls

1. **Default-deny egress** — All outbound network traffic is blocked unless explicitly allowed.
2. **Allowlist required endpoints** — Only the specific endpoints the agent needs:
   - Model API endpoints (if using remote inference)
   - Package registries (PyPI, npm, etc.) — specific domains only
   - Version control (Git) — specific organizations/repos only
   - CI/CD endpoints — specific pipelines only
3. **Block all other egress** — No direct internet access, no arbitrary URLs.
4. **Configure DLP inspection** — Inspect outbound traffic for sensitive data patterns (API keys, credentials, PII, internal URLs).
5. **Configure a host firewall** — Deny all inbound traffic except the specific ports needed for development (SSH, HTTP for local dev servers).

> **CUSTODY:** Operational Controls (AC-019, AC-020)
> **LASM:** L6 Environment
> **OWASP:** LLM02-Sensitive Info Disclosure

### Step 2.3: Configure Credential Management

1. **Use a secret broker** — All credentials are obtained through a secret broker (HashiCorp Vault, AWS Secrets Manager, etc.). No hardcoded credentials, no `.env` files with real secrets.
2. **Scope credentials to minimum privilege** — Each credential grants access only to the specific resource the agent needs, for the minimum time required.
3. **Use short-lived, auto-rotating credentials** — Maximum TTL of 1 hour for development credentials. Auto-rotate on expiration.
4. **Separate agent identity from human identity** — The agent has its own identity and credentials, separate from the developer's.
5. **Never share credentials across agents** — Each agent instance has its own scoped credentials.
6. **Revoke credentials on session end** — When the agent session ends, all credentials are immediately revoked.

> **CUSTODY:** Operational Controls (AC-016), Dependency (AC-021)
> **LASM:** L5 Integration, L6 Environment
> **DORA 2025:** Secret management best practices

---

## Phase 3 — Tool and Integration Controls

### Step 3.1: Configure Tool Allowlist

1. **Enumerate permitted tools** — Create an explicit allowlist of tools the agent may invoke: shell commands, API endpoints, file operations, network requests.
2. **Block everything not on the allowlist** — The default is deny. The agent cannot invoke any tool, command, or API that is not explicitly permitted.
3. **Implement the allowlist at the infrastructure level** — Not in the agent's prompt, but in the policy engine, shell configuration, and network firewall.
4. **Review the allowlist regularly** — At minimum, review when the agent's task changes and during security reviews.

> **CUSTODY:** Conditions of Release (AC-003), Operational Controls (AC-017)
> **LASM:** L4 Tool Execution, L7 Governance

### Step 3.2: Configure Tool Execution Controls

1. **Rate limits** — Maximum tool calls per task, per minute, and per session.
2. **Timeout rules** — Maximum execution time per tool call and per task.
3. **Recursion limits** — Maximum depth of tool-chaining (tool A → tool B → tool A).
4. **Circuit breakers** — After N consecutive failures, pause execution and escalate to the human operator.
5. **Token budgets** — Maximum token consumption per task to prevent resource exhaustion.

> **CUSTODY:** Operational Controls (AC-017)
> **OWASP Agentic AI:** Tool abuse prevention

### Step 3.3: Configure Version Control Controls

1. **Read-only access for unreviewed changes** — The agent can write code, but cannot push to protected branches without human review.
2. **Branch protection rules** — Require human approval for all merges to main/release branches. AI approvals do not satisfy this requirement.
3. **Commit signing** — All commits are signed with the agent's dedicated key. Human commits use human keys.
4. **Attribution** — Every commit, PR, and review carries metadata identifying whether it was authored, reviewed, or approved by a human or an AI agent.
5. **Audit trail** — All version control actions are logged with the agent's identity, the task context, and the authorization scope.

> **CUSTODY:** Traceability (AC-013, AC-015)
> **NIST AI RMF:** GOVERN 1.7, MANAGE 2.3
> **DORA 2025:** Code review and change tracking

### Step 3.4: Configure CI/CD Pipeline Controls

1. **Separate AI-authored pipelines from human-authored pipelines** — AI agents cannot modify CI/CD pipeline configurations without human review.
2. **Approval gates for deployments** — AI agents cannot approve their own deployments. Human approval is required for production deployments.
3. **Automated security scanning in CI** — SAST, DAST, dependency scanning, and secret detection run on every pipeline. AI-authored code is not exempt.
4. **Rollback capability for every deployment** — Every CI/CD pipeline must include a tested rollback procedure.
5. **Change failure rate tracking** — Track the rate of deployments that result in incidents, rollbacks, or failures. AI-authored changes are tagged for separate analysis.

> **CUSTODY:** Supervision (AC-009, AC-011)
> **LASM:** L7 Governance
> **DORA 2025:** CI/CD stability metrics, deployment practices

---

## Phase 4 — Logging and Observability

### Step 4.1: Configure Immutable Audit Logging

1. **Log all agent actions** — Every tool call, API request, file operation, shell command, and network request.
2. **Log with structured metadata** — Each log entry carries: trace ID, session ID, task ID, agent ID, operator ID, timestamp, action, parameters, and outcome.
3. **Use an append-only log store** — The agent cannot modify or delete its own audit trail.
4. **Separate logging system** — The agent runtime, the policy engine, and the audit log store are separate systems. No single compromise can affect all three.
5. **Log retention** — Retain logs per organizational policy (minimum 90 days for development environments).

> **CUSTODY:** Traceability (AC-013, AC-014, AC-015)
> **NIST AI RMF:** GOVERN 1.7
> **LASM:** L7 Governance

### Step 4.2: Configure Real-Time Monitoring

1. **Action rate monitoring** — Alert on unusual tool call rates, execution times, or token consumption.
2. **Scope boundary monitoring** — Alert on any action that hits or approaches the authorized scope boundary.
3. **Credential monitoring** — Alert on credential access patterns that deviate from the baseline.
4. **Egress monitoring** — Alert on any outbound traffic to non-allowlisted destinations.
5. **Audit gap detection** — Alert on any gap in the audit trail (missing log entries, out-of-order timestamps).

> **CUSTODY:** Operational Controls (AC-017), Traceability (AC-013)
> **LASM:** L7 Governance
> **DORA 2025:** Monitoring and observability

### Step 4.3: Configure Memory Controls

1. **Session memory controls** — Agent conversation history and context are scoped to the current task and cleared on session end.
2. **Long-term memory controls** — If the agent uses persistent memory (vector store, database), apply write controls:
   - Source labeling: every entry carries provenance (who/what wrote it, when, from what source).
   - Retention limits: stale entries are pruned on a defined schedule.
   - Write access controls: only authorized sources can write to memory.
   - Quarantine: entries from untrusted sources are flagged and isolated.
3. **Memory isolation** — Each agent instance has its own memory namespace. Agents cannot read each other's memory.

> **CUSTODY:** Untrusted Input (AC-008), Dependency (AC-021)
> **LASM:** L3 Memory, L5 Integration

---

## Phase 5 — Supervision and Governance

### Step 5.1: Configure Approval Gates

1. **High-impact action approval** — Actions that modify production state, deploy code, change infrastructure, or affect user data require explicit human approval.
2. **Approval at the infrastructure level** — Approval gates are enforced by the policy engine, not by agent logic. The agent cannot modify, bypass, or deactivate approval rules.
3. **Approval logging** — Every approval request and decision is logged with the approver's identity, timestamp, and rationale.
4. **Timeout on approval requests** — If an approval request is not resolved within a defined time window, the action is denied by default.

> **CUSTODY:** Supervision (AC-009, AC-011)
> **LASM:** L7 Governance
> **NIST AI RMF:** GOVERN 1.3

### Step 5.2: Configure Goal Specification and Stop Conditions

1. **Explicit task definition** — Each agent task has a defined goal with measurable success criteria and explicit boundaries.
2. **Stop conditions** — The agent halts and escalates when:
   - The task goal is achieved (success).
   - The time budget is exceeded.
   - The error threshold is reached (N consecutive failures).
   - The scope boundary is approached or crossed.
   - The agent's confidence in its next action falls below a defined threshold.
   - An approval request is denied.
3. **Human escalation** — When a stop condition triggers, the agent does not continue autonomously. It pauses and requests human guidance.

> **CUSTODY:** Supervision (AC-012), Conditions of Release (AC-002)
> **LASM:** L2 Cognitive, L7 Governance

### Step 5.3: Define Authorization Artifacts for Development Tasks

1. **Per-task authorization** — Each development task the agent performs is governed by an authorization artifact specifying:
   - Permitted tools and APIs
   - Permitted file paths and repositories
   - Permitted data sources
   - Maximum impact level
   - Human operator responsible
   - Time window
2. **Scope change requires re-authorization** — If the agent determines that the task requires tools, data, or actions outside the original scope, it must request re-authorization from the human operator.
3. **Authorization artifact versioning** — Changes to the authorization artifact are versioned and logged.

> **CUSTODY:** Conditions of Release (AC-001, AC-002, AC-003, AC-004)
> **LASM:** L7 Governance

---

## Phase 6 — Code Security Controls

### Step 6.1: Configure Automated Security Scanning

1. **SAST (Static Application Security Testing)** — Run on every commit. Scan for known vulnerability patterns (SQL injection, XSS, path traversal, etc.).
2. **DAST (Dynamic Application Security Testing)** — Run on every deployment to a test environment. Test running applications for security vulnerabilities.
3. **Dependency scanning** — Run on every build. Check all dependencies against known vulnerability databases (CVE, NVD).
4. **Secret detection** — Run on every commit. Detect accidentally committed secrets (API keys, passwords, tokens).
5. **AI-specific code review** — Flag patterns known to be insecure when generated by AI (hardcoded credentials, disabled certificate validation, overly permissive access controls, missing input validation).

> **CUSTODY:** Operational Controls
> **NIST AI RMF:** MEASURE function
> **DORA 2025:** Continuous security testing

### Step 6.2: Configure Code Review Requirements

1. **All AI-authored code requires human review** — No AI-authored code is merged without human review and approval.
2. **Security-focused review** — In addition to functional review, all AI-authored code receives a security review that specifically checks for:
   - Known AI generation patterns that are insecure (from SlopCodeBench and similar benchmarks)
   - Missing input validation
   - Hardcoded credentials or secrets
   - Overly permissive access controls
   - Disabled security features (certificate verification, authentication)
   - Logic errors that pass functional tests but create security vulnerabilities
3. **Attribution in review** — Code reviews clearly identify which portions were AI-authored and which were human-authored.

> **CUSTODY:** Supervision (AC-009)
> **NIST AI RMF:** GOVERN 1.3, MANAGE 2.3
> **DORA 2025:** Code review practices

### Step 6.3: Configure Testing Requirements

1. **Unit tests required** — All AI-authored code must have unit tests before merge.
2. **Security tests required** — Security test cases must cover the specific vulnerability patterns flagged by SAST and AI-specific review.
3. **Integration tests required** — Changes that affect API contracts, data flows, or inter-service communication must have integration tests.
4. **AI-specific test patterns** — Include tests for:
   - Prompt injection resistance (input validation, instruction hierarchy)
   - Scope boundary adherence (agent stays within authorized scope)
   - Error handling (agent fails safely, does not expose sensitive data in errors)
   - Edge cases that AI commonly gets wrong (off-by-one, null handling, boundary conditions)

> **NIST AI RMF:** MEASURE function
> **DORA 2025:** Testing automation and coverage

---

## Phase 7 — Verification

### Step 7.1: Run the Harness Engineering Checklist

Run the **Harness Engineering Checklist** (`checklists/harness-engineering.yaml`) against the harness configuration. Every `critical` control must pass. Every `high` control must either pass or have a documented accepted risk.

> **Cross-reference:** checklists/harness-engineering.yaml
> **NIST AI RMF:** MEASURE function

### Step 7.2: Run Security Verification Tests

1. **Model integrity verification** — Confirm model hashes match published values.
2. **Instruction hierarchy test** — Attempt prompt injection and verify system instructions take precedence.
3. **Scope boundary test** — Attempt actions outside the authorized scope and verify they are blocked at the infrastructure level.
4. **Credential isolation test** — Verify the agent cannot access credentials belonging to other agents or users.
5. **Egress test** — Verify the agent cannot reach non-allowlisted network destinations.
6. **Persistence test** — Verify the agent cannot create scheduled tasks, modify startup scripts, or install packages.
7. **Approval bypass test** — Verify that approval gates cannot be circumvented through delegation, chaining, or parameter manipulation.
8. **Audit integrity test** — Verify the agent cannot modify or delete its own audit trail.
9. **Memory isolation test** — Verify the agent cannot access another agent's memory.
10. **Code security test** — Run SAST, DAST, dependency scanning, and secret detection on AI-authored code and verify all findings are addressed.

> **CUSTODY:** All pillars
> **LASM:** All layers
> **DORA 2025:** Continuous verification

### Step 7.3: Document the Harness Configuration

Produce a **Harness Configuration Document** that records:

| Element | Content |
|---|---|
| Model provenance | Name, version, source, hash, signature |
| Environment configuration | Container/VM image, network rules, filesystem layout |
| Credential management | Secret broker, scoping, TTL, rotation |
| Tool allowlist | Permitted tools, APIs, and endpoints |
| Approval gates | Actions requiring approval, approval engine, timeout |
| Monitoring | Metrics, alerts, dashboards |
| Logging | Log store, retention, access controls |
| Security scanning | SAST, DAST, dependency scanning, secret detection |
| Code review | Review requirements, security checklist |
| Authorization artifact template | Per-task authorization format |

> **NIST AI RMF:** GOVERN function — documentation and accountability
> **CUSTODY:** Conditions of Release, Traceability

---

## Phase 8 — Ongoing Maintenance

### Step 8.1: Regular Reviews

1. **Weekly** — Review monitoring dashboards, audit logs, and alert summaries.
2. **Monthly** — Review tool allowlist, credential scoping, and authorization artifacts for drift.
3. **Quarterly** — Full harness security review including:
   - Re-run the Harness Engineering Checklist
   - Re-run security verification tests
   - Review threat model for new attack vectors
   - Update authorization artifacts and scope definitions
4. **On change** — Whenever the agent's task, tools, or environment change, update the authorization artifact and re-verify controls.

> **NIST AI RMF:** MANAGE function — continuous monitoring
> **DORA 2025:** Continuous improvement

### Step 8.2: Update on New Threat Intelligence

1. When new vulnerability patterns, attack techniques, or model weaknesses are disclosed:
   - Update the threat model.
   - Add new test cases to the security verification suite.
   - Update SAST/DAST rules to detect new patterns.
   - Consider a Red Team Engagement (`protocols/red-team-engagement.md`) to test the new threats.

> **Cross-reference:** red-team-engagement.md
> **NIST AI RMF:** MANAGE — threat-informed updates

### Step 8.3: Environment Rotation

1. **Rebuild environments on a regular schedule** — Destroy and recreate development environments from trusted images at least weekly (daily for high-sensitivity environments).
2. **Rebuild on security events** — After any security event, immediately rebuild the environment from a trusted image.
3. **Never reuse environments across agents or tasks** — Each agent task gets a fresh environment.

> **CUSTODY:** Yield (AC-024)
> **LASM:** L6 Environment

---

## Verification

| Gate | Verification Method | Pass Criteria |
|---|---|---|
| Model integrity | Hash comparison | Model hashes match published values |
| Instruction hierarchy | Injection test suite | System instructions take precedence over all injected inputs |
| Environment hardening | Automated test suite | All hardening tests pass (privilege, egress, persistence) |
| Credential management | Isolation test | Agent cannot access other credentials; TTL enforced |
| Tool allowlist | Scope boundary test | Agent cannot invoke non-allowlisted tools |
| Approval gates | Bypass test | Approval gates cannot be circumvented |
| Audit logging | Integrity test | Agent cannot modify or delete its audit trail |
| Code security | SAST/DAST/dependency scan | No unresolved critical or high findings |
| Harness checklist | `checklist_run harness-engineering` | All critical items pass; high items pass or have accepted risk |
| Configuration document | Review | Complete, current, and signed by operator |

---

## Rollback

If a security verification test fails or a security event occurs during harness setup:

1. **Do not proceed to use the harness** — A failed security test means the harness is not safe to use.
2. **Diagnose the failure** — Identify the root cause using the test output and audit logs.
3. **Fix the issue** — Update the harness configuration to address the failure.
4. **Re-run all security verification tests** — A fix for one issue may introduce or reveal another.
5. **If the issue cannot be resolved** — Escalate to the Security Lead and follow the Incident Response Protocol (`protocols/incident-response.md`).

If a security event occurs during harness operation:

1. **Immediately halt the agent** and revoke all credentials.
2. **Preserve the environment and audit logs** for forensic analysis.
3. **Follow the Incident Response Protocol** (`protocols/incident-response.md`).
4. **Rebuild the environment from a trusted image** after the incident is resolved.
5. **Re-verify all controls** before resuming operation.

> **CUSTODY:** Yield (AC-024), Supervision (AC-009)
> **DORA 2025:** Rollback capability for every configuration change