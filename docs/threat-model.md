# Threat Model — AI Agents and AI-Assisted Development

This document provides a LASM-based threat model for AI agents and AI-assisted development environments.

## Core Assumption

**An AI agent can be manipulated, compromised, or wrong. Its operating environment must prevent a bad decision from becoming an unrestricted system action.**

Prompts are not a security boundary. High-impact restrictions must be enforced by external mechanisms (SELinux, AppArmor, policy engines, network controls, approval services, credential brokers, quotas, and independent monitoring).

## LASM: Layered Attack Surface Model

The Layered Attack Surface Model (LASM) by Kexin Chu (2026) provides a 7×4 matrix for mapping threats across architectural layers and temporal classes.

### Seven Architectural Layers

| Layer | Surface | Key Threats | Primary Controls |
|---|---|---|---|
| **L1 Foundation** | Model weights, training, fine-tuning, embeddings | Jailbreaks, adversarial examples, model poisoning, backdoors, compromised checkpoints | Model provenance, integrity verification, adversarial testing, secure training |
| **L2 Cognitive** | Planning, reasoning, goal formation, task decomposition | Goal hijacking, reasoning manipulation, objective drift, unsafe decomposition | Explicit goals, bounded planning, policy checks, stop conditions |
| **L3 Memory** | Short-term state, long-term memory, RAG, vector stores | Memory poisoning, cross-session manipulation, stale memory, retrieval corruption | Memory provenance, controlled writes, trust labels, expiry, rollback |
| **L4 Tool Execution** | APIs, plugins, browsers, code interpreters, databases | Indirect prompt injection, tool misuse, parameter manipulation, data exfiltration | Tool allowlists, parameter validation, execution sandbox, human approval |
| **L5 Integration** | Agent-to-agent, orchestration, delegation, MCP | Cross-agent compromise, hidden delegation, trust chain abuse | Agent isolation, signed messages, trust labels, policy enforcement |
| **L6 Environment** | OS, network, identity, filesystem, credentials | Privilege escalation, lateral movement, persistence, credential theft | SELinux, AppArmor, namespaces, cgroups, network segmentation, secret brokers |
| **L7 Governance** | Policy, compliance, oversight, audit | Audit evasion, policy circumvention, accountability gaps | Remote immutable logging, append-only storage, signed events, separation of duties |

### Four Temporal Classes

| Class | Duration | Example Threats |
|---|---|---|
| **Immediate** | Single interaction | Direct prompt injection, jailbreak, parameter manipulation |
| **Session** | Single session | Goal hijacking, tool-loop DoS, data exfiltration within one task |
| **Cross-session** | Multiple sessions | Memory poisoning, stale memory, RAG injection |
| **Persistent** | Long-lived | Model poisoning, persistence mechanisms, credential accumulation |

### Key Insight

A control placed at one layer does not detect an attack at another. For example:
- Prompt filtering does not validate a compromised model checkpoint (L1)
- Package signing does not prevent memory poisoning (L3)
- Output moderation does not prevent an authorized but harmful tool sequence (L4)
- Session-level monitoring may miss a payload activated weeks later (L3→Persistent)

This is why **cross-layer defense in depth** is essential.

## CUSTODY: Seven Pillars of Agent Containment

The CUSTODY framework addresses **capability accretion** — the gap between what an agent is *granted* and what it can *actually* do.

| Pillar | Security Objective | Key Controls |
|---|---|---|
| **Conditions of Release** | Define what the agent may access, change, invoke, or delegate | Authorization artifact, scope boundaries, tool allowlist, data inventory |
| **Untrusted Input** | Protect the agent from hostile content, injection, and supply-chain compromise | Instruction hierarchy, data separation, model provenance, memory validation |
| **Supervision** | Ensure human oversight for high-impact decisions | Approval gates, Agent Rule of One, infrastructure enforcement, stop conditions |
| **Traceability** | Enable attribution and forensic reconstruction | Immutable logging, delegation tracing, separation of duties |
| **Operational Controls** | Constrain operational authority | Secret broker, rate limits, non-root execution, default-deny egress, segmentation |
| **Dependency** | Prevent capability accretion through delegation and trust chains | Per-agent isolation, tool isolation, signed artifacts |
| **Yield** | Enable secure teardown and recovery | Immutable images, ephemeral environments, credential revocation |

## Attack Trees

### Prompt Injection → Data Exfiltration

```
Prompt Injection
├── Direct injection (user input)
│   └── Agent follows malicious instructions
│       └── Exfiltrates data via tool calls
│           └── Blocked by: AC-005 (instruction hierarchy), AC-019 (default-deny egress)
└── Indirect injection (retrieved content)
    └── Retrieved content overrides developer intent
        └── Agent sends data to attacker-controlled endpoint
            └── Blocked by: AC-006 (data separation), AC-019 (default-deny egress)
```

### Excessive Agency → Infrastructure Modification

```
Excessive Agency
└── Agent has broad tool access
    ├── Modifies infrastructure without approval
    │   └── Blocked by: AC-003 (tool allowlist), AC-009 (human approval)
    └── Chains tools to escalate privileges
        └── Blocked by: AC-011 (infrastructure enforcement), AC-018 (no-new-privileges)
```

### Credential Theft → Lateral Movement

```
Credential Theft
└── Agent reads credentials from environment
    ├── Uses credentials to access other services
    │   └── Blocked by: AC-016 (secret broker, no direct secret access)
    └── Moves laterally to other hosts
        └── Blocked by: AC-020 (micro-segmentation, mTLS)
```

## Threat-to-Control Matrix

See `checklists/agent-containment.yaml` for the complete threat-to-control mapping with verification steps.