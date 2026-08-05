---
name: ai-red-team
description: >
  Plan and execute AI red team engagements using the OWASP AI Red Teaming Guide,
  MITRE ATLAS, PyRIT, and garak. Covers scoping, threat modeling, prompt injection,
  jailbreak, data exfiltration, tool misuse, agent autonomy, and multi-agent attacks.
  Produces structured findings mapped to OWASP, ATLAS, and NIST AI RMF.
triggers:
  - red team the ai
  - test ai security
  - ai adversarial testing
  - prompt injection test
  - jailbreak test
  - ai security assessment
tools:
  - read_file
  - search_files
  - terminal
  - patch
  - write_file
---

# AI Red Team Skill

Plan and execute AI red team engagements against AI systems and agents.

## Steps

1. **Define scope** — Confirm:
   - Target system (model, application, agent)
   - Authorized scope (tools, APIs, data sources, actions)
   - Out-of-scope activities (destructive actions, production data exfiltration, social engineering)
   - Rules of engagement (notification, rollback, data handling)
   - Success criteria (specific threats to test)

2. **Load the red-team checklist** — Read `checklists/red-team.yaml` and use it as the engagement framework. Each item has an ID (RT-001 through RT-020), category, threat, control, severity, and verification.

3. **Threat model the target** — Using the LASM 7×4 matrix:
   - L1 Foundation: Model weights, training, fine-tuning artifacts
   - L2 Cognitive: Planning, reasoning, goal formation
   - L3 Memory: Short/long-term memory, RAG, vector stores
   - L4 Tool Execution: APIs, plugins, browsers, code interpreters
   - L5 Integration: Agent-to-agent, orchestration, delegation
   - L6 Environment: OS, network, identity, filesystem
   - L7 Governance: Policy, compliance, oversight, audit

4. **Select test cases** — Based on the threat model, select from:
   - **Prompt injection**: Direct and indirect injection payloads
   - **Jailbreak**: Known jailbreak techniques and novel variants
   - **Data exfiltration**: Extraction of training data, PII, system prompts
   - **Tool misuse**: Unauthorized tool invocation, parameter manipulation
   - **Excessive agency**: Testing scope boundaries and approval gates
   - **Memory poisoning**: Injecting content into agent memory or RAG
   - **Multi-agent attack**: Cross-agent influence, trust chain abuse
   - **Supply chain**: Compromised model, plugin, or dependency

5. **Execute tests** — For each test case:
   - Document the test payload and expected behavior
   - Execute the test against the target
   - Record the actual behavior
   - Classify the finding (critical/high/medium/low)
   - Map to OWASP Top 10 LLM, MITRE ATLAS, and NIST AI RMF

6. **Document findings** — For each finding, record:
   - Finding ID and title
   - Threat category (LASM layer and temporal class)
   - Test payload and reproduction steps
   - Observed behavior vs expected behavior
   - Impact assessment
   - Recommended remediation with checklist item references
   - Framework mappings (OWASP, ATLAS, NIST AI RMF, CUSTODY)

7. **Generate the report** — Present:
   - Executive summary with risk rating
   - LASM layer heatmap (L1-L7 × findings)
   - Detailed findings table sorted by severity
   - Framework mapping table
   - Prioritized remediation plan
   - Evidence appendix (sanitized for sensitive data)

## Testing Tools Reference

| Tool | Purpose | Install |
|---|---|---|
| PyRIT | Automated LLM red teaming | pip install pyrit |
| garak | LLM vulnerability scanner | pip install garak |
| Inspect (UK AISI) | Model evaluation framework | pip install inspect-ais |
| ART (IBM) | Adversarial robustness testing | pip install adversarial-robustness-toolbox |
| CyberSecEval (Meta) | Cybersecurity misuse evaluation | pip install cyberseceval |

## Pitfalls

- Never test against production systems without explicit authorization and rollback plans.
- Sanitize all test data before including in reports. Do not include actual PII, credentials, or sensitive content.
- Prompt injection testing can produce harmful output. Always test in isolated environments.
- Jailbreak testing may produce content that violates safety policies. Document findings responsibly.
- The goal is to find real security gaps, not to prove the system is insecure. Report what you find accurately.