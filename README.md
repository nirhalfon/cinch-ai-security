# Cinch

> **MCP server + cross-harness skills for building and operating AI agents safely.**
> Grounded in NIST AI RMF, CISA Secure AI Development Guidelines, OWASP, CUSTODY, LASM, and DORA 2025.

📖 **Docs & explorers:** <https://nirhalfon.github.io/cinch-ai-security/> — browse every checklist, mapping, protocol, skill, and template; read the threat model; and see the MCP tools.

AI agents can read data, invoke tools, execute code, call APIs, and initiate business processes. When they go wrong — through prompt injection, excessive autonomy, credential theft, or model error — the consequences are only as severe as the environment allows.

**Cinch** provides:
- 📋 **Checklists** — YAML security checklists mapped to frameworks (NIST, OWASP, CUSTODY, LASM)
- 📡 **MCP Server** — Tool-calling server any MCP-compatible agent can query for controls, protocols, and mappings
- 🧠 **Skills** — Drop-in skill definitions for Hermes, Claude, OpenClaw, NanoClaw
- 📐 **Protocols** — Step-by-step deployment and incident response procedures
- 🔗 **Mappings** — Cross-references between NIST AI RMF, OWASP, MITRE ATLAS, CUSTODY, LASM

## Philosophy

1. **The model proposes; the architecture authorizes and enforces.** Prompts are not a security boundary.
2. **An AI agent can be manipulated, compromised, or wrong.** Its environment must prevent a bad decision from becoming an unrestricted system action.
3. **Functional correctness ≠ security.** 47.5% of AI-generated code may be functionally correct, but only 8.25% is also secure ([ICLR 2026 vibe-coding benchmark](https://openreview.net/forum?id=rs6rRCEixQ)).
4. **Capability accretion is the core risk.** Agents silently gain practical authority through inherited credentials, trust relationships, tool access, and delegation chains.
5. **Defense in depth maps to architecture layers.** A control at one layer does not detect an attack at another (LASM principle).

## Quick start

### Install and run the MCP server

```bash
# From PyPI (coming soon)
pip install cinch

# Or from source
git clone https://github.com/nirhalfon/cinch-ai-security.git
cd cinch-ai-security
pip install -e .
cinch serve
```

### Add to your MCP config

```json
{
  "mcpServers": {
    "cinch": {
      "command": "cinch",
      "args": ["serve"]
    }
  }
}
```

### Use as a Hermes skill

```bash
cp -r skills/ai-harness-review ~/.hermes/skills/
```

### Use with Claude (CLAUDE.md)

Copy `cross-harness/claude/CLAUDE.md` into your project root. Claude will automatically follow the harness security protocols.

### Use with OpenClaw / NanoClaw

See `cross-harness/openclaw/` and `cross-harness/nanoclaw/` for agent configuration files.

## MCP Tools

The server exposes these tools for any MCP-compatible agent:

| Tool | Description |
|---|---|
| `checklist_run` | Run a named checklist against a description of your deployment |
| `checklist_list` | List available checklists and their item counts |
| `checklist_get` | Get a specific checklist item by ID |
| `protocol_get` | Get a step-by-step protocol by name |
| `mapping_lookup` | Look up controls mapped to a framework (NIST, OWASP, CUSTODY, LASM, ATLAS) |
| `threat_search` | Search all checklists for controls that mitigate a given threat |

## Project structure

```
cinch/
├── README.md
├── LICENSE                         # CC BY 4.0
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── pyproject.toml                  # MCP server package (MCP SDK 2.0)
├── SECURITY.md                     # Vulnerability reporting policy
├── src/cinch/
│   ├── __init__.py
│   ├── server.py                   # MCP server entry point + tool definitions
│   └── loader.py                   # YAML checklist/protocol/mapping loader
├── tests/                          # pytest: loader + server (path-traversal, dispatch)
├── scripts/
│   └── build_docs_json.py          # Regenerates docs-site/data/full.json from source
├── checklists/
│   ├── agent-containment.yaml      # CUSTODY-based agent containment
│   ├── harness-engineering.yaml    # AI dev harness safeguards
│   ├── system-hardening.yaml       # OS/infra hardening for AI workloads
│   ├── red-team.yaml               # AI red team engagement checklist
│   └── supply-chain.yaml           # AI supply chain security
├── protocols/
│   ├── agent-deployment.md         # Secure AI agent deployment
│   ├── incident-response.md        # AI incident response
│   ├── red-team-engagement.md      # AI red team engagement
│   └── harness-setup.md           # Setting up a secure AI development harness
├── skills/
│   ├── ai-harness-review/SKILL.md  # Hermes: AI harness security review
│   ├── agent-audit/SKILL.md        # Hermes: Agent security audit
│   └── ai-red-team/SKILL.md        # Hermes: AI red team operations
├── mappings/
│   ├── nist-rmf-crosswalk.yaml
│   ├── owasp-llm-crosswalk.yaml
│   ├── atlas-crosswalk.yaml
│   ├── custody-crosswalk.yaml
│   └── lasm-crosswalk.yaml
├── cross-harness/
│   ├── claude/
│   │   └── CLAUDE.md               # Claude Code instructions
│   ├── openclaw/
│   │   └── agent-config.yaml        # OpenClaw agent config
│   └── nanoclaw/
│       └── agent-config.yaml        # NanoClaw agent config
├── templates/
│   ├── agent-policy.md
│   ├── adr-agent-deployment.md
│   ├── risk-assessment.md
│   └── security-review.md
├── docs/
│   ├── threat-model.md
│   ├── research-references.md
│   └── design-rationale.md
├── docs-site/                       # GitHub Pages site (vanilla-JS SPA)
│   ├── index.html
│   ├── js/app.js
│   ├── css/brand.css
│   ├── data/full.json               # generated by scripts/build_docs_json.py
│   └── pages/                       # thin page shells rendered by app.js
└── .github/
    ├── dependabot.yml               # weekly dependency + action updates
    └── workflows/
        ├── validate.yaml            # CI: YAML, imports, ruff, bandit, pip-audit, pytest
        └── pages.yml                # deploy docs-site to GitHub Pages
```

## Research grounding

| Source | Coverage |
|---|---|
| [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework) | Risk governance (GOVERN, MAP, MEASURE, MANAGE) |
| [NIST AI 600-1 GenAI Profile](https://www.nist.gov/artificial-intelligence) | Generative AI-specific risks and controls |
| [CISA Guidelines for Secure AI System Development](https://www.cisa.gov/topics/artificial-intelligence) | Secure AI lifecycle controls |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/) | LLM application security risks |
| [OWASP Agentic AI](https://owasp.org/www-project-ai-red-teaming-guide/) | Agent threat modeling and controls |
| [MITRE ATLAS](https://atlas.mitre.org/) | Adversarial threat landscape for AI |
| [CUSTODY Framework](https://github.com/malwarejake/CUSTODY-framework) | Autonomous agent containment |
| [LASM](https://github.com/yuval14/Artificial-Intelligence-Cyber-Shield) | Layered Attack Surface Model |
| [Google SAIF](https://saif.google/) | Secure AI Framework |
| [CSA AICM](https://cloudsecurityalliance.org/) | AI Controls Matrix |
| [ETSI SAI](https://www.etsi.org/committee/sai) | AI cybersecurity standardization |
| [AI Harness Scorecard](https://github.com/markmishaev76/ai-harness-scorecard) | Engineering safeguards for AI-assisted dev |
| [DORA 2025](https://dora.dev/research/2025/) | CI/CD practices, stability metrics |
| [SlopCodeBench](https://huggingface.co/blog/slopcodebench) | Subtle correctness in AI-generated code |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every checklist item, protocol step, and mapping must cite a source.

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to share and adapt with attribution.