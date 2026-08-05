# Cinch — Design Rationale

## Why this project exists

AI agents can read data, invoke tools, execute code, call APIs, and initiate business processes. When they go wrong — through prompt injection, excessive autonomy, credential theft, or model error — the consequences are only as severe as the environment allows.

Existing frameworks provide excellent guidance but in different formats and different contexts:
- **NIST AI RMF** provides governance structure but not enforceable checklists
- **OWASP** provides threat catalogs but not deployment protocols
- **CUSTODY** provides containment pillars but not implementation verification
- **LASM** provides threat modeling but not day-to-day checklists
- **AI Harness Scorecard** grades repos but doesn't give you an MCP server

**Cinch** bridges these gaps by providing:
1. **Enforceable checklists** with threat-to-control mappings and verification steps
2. **An MCP server** any compatible agent can query for controls and protocols
3. **Cross-harness skills** for Hermes, Claude, OpenClaw, and NanoClaw
4. **Framework mappings** that let you trace any control to NIST, OWASP, CUSTODY, or LASM

## Design decisions

### Why YAML for checklists?

YAML is:
- Human-readable and editable
- Machine-parseable for the MCP server
- Validatable in CI
- Compatible with any tool that reads structured data

### Why an MCP server?

The Model Context Protocol (MCP) is the emerging standard for tool-calling in AI systems. By providing an MCP server, any MCP-compatible agent (Claude, Hermes, OpenClaw, NanoClaw, etc.) can query the checklists, protocols, and mappings at runtime without embedding them in its prompt.

This means:
- Controls stay up-to-date without changing agent configuration
- The same controls are available across all agent platforms
- Agents can search for relevant controls by threat

### Why CUSTODY as the primary containment model?

CUSTODY addresses the core security problem of AI agents: **capability accretion** — the gap between what an agent is granted and what it can actually do. This is distinct from model alignment or prompt safety. CUSTODY focuses on enforceable, infrastructure-level controls that the agent cannot bypass.

### Why LASM for threat modeling?

LASM's 7×4 matrix (7 architectural layers × 4 temporal classes) is the most complete threat model for AI agents. It shows that a control at one layer doesn't detect an attack at another — a critical insight for defense in depth.

### Why separate checklists from protocols?

Checklists define **what** controls must be in place. Protocols define **how** to implement and operate them. Separating them allows:
- Checklists to be used for assessment and auditing
- Protocols to be used for step-by-step deployment
- Both to be updated independently

### Why framework mappings?

Organizations have different compliance requirements. A healthcare org needs HIPAA+NIST. A finance org needs SOC2+OWASP. A defense org needs CISA+ATLAS. The mappings let you trace any control to the framework you need to comply with.

## How to use this project

1. **Assessment**: Use the checklists to assess your current state
2. **Gap analysis**: Use the mappings to find controls you're missing
3. **Implementation**: Follow the protocols to deploy controls
4. **Automation**: Install the MCP server for runtime control queries
5. **Skills**: Add Hermes skills for guided security reviews
6. **Cross-harness**: Copy CLAUDE.md, OpenClaw, or NanoClaw configs to your agents
7. **Templates**: Use policy, ADR, and risk assessment templates for documentation
8. **CI**: Add validate.yaml to your CI pipeline to keep checklists valid