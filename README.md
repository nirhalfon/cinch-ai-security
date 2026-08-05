<div align="center">

# 🛡️ Cinch

**MCP server + cross-harness skills for building and operating AI agents safely.**

*The model proposes; the architecture authorizes and enforces.*

[![PyPI](https://img.shields.io/pypi/v/cinch-ai-security?color=blue&label=PyPI&logo=pypi)](https://pypi.org/project/cinch-ai-security/)
[![Python](https://img.shields.io/pypi/pyversions/cinch-ai-security?logo=python&logoColor=white)](https://pypi.org/project/cinch-ai-security/)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green?logo=creativecommons&logoColor=white)](https://creativecommons.org/licenses/by/4.0/)
[![CI](https://img.shields.io/github/actions/workflow/status/nirhalfon/cinch-ai-security/validate.yaml?label=CI&logo=githubactions&logoColor=white)](https://github.com/nirhalfon/cinch-ai-security/actions/workflows/validate.yaml)
[![Security](https://img.shields.io/github/actions/workflow/status/nirhalfon/cinch-ai-security/security-scan.yml?label=security&logo=githubactions&logoColor=white)](https://github.com/nirhalfon/cinch-ai-security/actions/workflows/security-scan.yml)
[![Docs](https://img.shields.io/badge/docs-Pages-orange?logo=githubpages&logoColor=white)](https://nirhalfon.github.io/cinch-ai-security/)

</div>

---

> Grounded in **NIST AI RMF**, **CISA Secure AI Development**, **OWASP**, **MITRE ATLAS**, **CUSTODY**, **LASM**, **Google SAIF**, and **DORA 2025**.

📖 **Live docs & explorers:** <https://nirhalfon.github.io/cinch-ai-security/> — browse every checklist, mapping, protocol, skill, and template; read the threat model; and try the MCP tools.

AI agents can read data, invoke tools, execute code, call APIs, and initiate business processes. When they go wrong — through prompt injection, excessive autonomy, credential theft, or model error — **the consequences are only as severe as the environment allows.** Cinch gives you the enforceable controls, protocols, and runtime queries to keep that environment contained.

## ✨ What's inside

| | What | Why it matters |
|---|---|---|
| 📋 | **6 checklists** (117 controls) | Enforceable, framework-mapped YAML — not advice, controls |
| 📡 | **MCP server** (7 tools) | Any MCP-compatible agent queries controls/protocols/mappings at runtime |
| 🧠 | **3 skills** | Drop-in Hermes skill definitions for security reviews & red-teaming |
| 📐 | **5 protocols** | Step-by-step deployment, incident-response, and evidence collection |
| 🔗 | **5 mappings** | Crosswalks: NIST AI RMF · OWASP LLM · MITRE ATLAS · CUSTODY · LASM |
| 📄 | **4 templates** | Security review, risk assessment, agent policy, deployment ADR |

---

## 🚀 Quick start for AI agents

> **You are an AI agent reading this repo.** This section is for you. Three commands and one config block get you operational.

### 1. Install

```bash
pip install cinch-ai-security
# or, from source:
git clone https://github.com/nirhalfon/cinch-ai-security.git
cd cinch-ai-security && pip install -e .
```

### 2. Wire it into your MCP client

Add this to your MCP config (Claude Desktop, Claude Code, Cursor, etc.):

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

### 3. Query the controls you need

Your tools (all return JSON):

| Tool | Use it to |
|---|---|
| `checklist_run` | Run a named checklist against a description of your deployment |
| `checklist_list` | List the 6 checklists and their item counts |
| `checklist_get` | Get a specific control by ID (`AC-001`, `AE-005`, …) |
| `protocol_get` | Get a step-by-step protocol by name (`agent-deployment`, `evidence-collect`, …) |
| `mapping_lookup` | Look up controls mapped to a framework (`nist-rmf`, `owasp-llm`, `atlas`, `custody`, `lasm`) |
| `threat_search` | Find every control that mitigates a given threat — scans threat + control + verification + sources |
| `checklist_diff` | Compare two checklists to surface coverage gaps and duplicated controls |

**Checklist ID prefixes:** `AC` agent-containment · `AE` agent-environment · `HE` harness-engineering · `RT` red-team · `SC` supply-chain · `SH` system-hardening.

### 30-second smoke test

```bash
cinch serve &            # start the MCP server on stdio
# then call checklist_list from your MCP client, or:
python -c "from cinch.loader import list_checklists; [print(c['name'], c['item_count']) for c in list_checklists()]"
```

### Use as a skill (Hermes / Claude / OpenClaw / NanoClaw)

```bash
# Hermes skill
cp -r skills/ai-harness-review ~/.hermes/skills/

# Claude Code — drop into your project root; it auto-loads
cp cross-harness/claude/CLAUDE.md /your/project/CLAUDE.md

# OpenClaw / NanoClaw — see cross-harness/openclaw/ and cross-harness/nanoclaw/
```

---

## 🧭 Philosophy

1. **The model proposes; the architecture authorizes and enforces.** Prompts are not a security boundary.
2. **An AI agent can be manipulated, compromised, or wrong.** Its environment must prevent a bad decision from becoming an unrestricted system action.
3. **Functional correctness ≠ security.** 47.5% of AI-generated code may be functionally correct, but only 8.25% is also secure ([ICLR 2026 vibe-coding benchmark](https://openreview.net/forum?id=rs6rRCEixQ)).
4. **Capability accretion is the core risk.** Agents silently gain practical authority through inherited credentials, trust relationships, tool access, and delegation chains.
5. **Defense in depth maps to architecture layers.** A control at one layer does not detect an attack at another (LASM principle).

## 📚 Project structure

```
cinch/
├── src/cinch/                      # MCP server (SDK 2.0)
│   ├── server.py                   # 7 tool definitions + entry point
│   └── loader.py                   # YAML checklist/protocol/mapping loader (path-traversal-safe)
├── checklists/                     # 6 checklists · 117 controls
│   ├── agent-containment.yaml      # CUSTODY-based agent containment (AC)
│   ├── agent-environment.yaml      # host/container controls, out-of-band audited (AE)
│   ├── harness-engineering.yaml    # AI dev harness safeguards (HE)
│   ├── system-hardening.yaml       # OS/infra hardening for AI workloads (SH)
│   ├── red-team.yaml               # AI red team engagement checklist (RT)
│   └── supply-chain.yaml           # AI supply chain security (SC)
├── protocols/                      # 5 how-to procedures
│   ├── agent-deployment.md
│   ├── evidence-collect.md         # out-of-band signed-JSON host evidence for AE controls
│   ├── incident-response.md
│   ├── red-team-engagement.md
│   └── harness-setup.md
├── skills/                         # 3 Hermes skills
│   ├── ai-harness-review/SKILL.md
│   ├── agent-audit/SKILL.md        # + separation-of-duties / --self-audit rule
│   └── ai-red-team/SKILL.md
├── mappings/                       # 5 framework crosswalks
│   ├── nist-rmf-crosswalk.yaml
│   ├── owasp-llm-crosswalk.yaml
│   ├── atlas-crosswalk.yaml
│   ├── custody-crosswalk.yaml
│   └── lasm-crosswalk.yaml
├── cross-harness/                  # agent platform configs
│   ├── claude/CLAUDE.md
│   ├── openclaw/agent-config.yaml
│   └── nanoclaw/agent-config.yaml
├── templates/                      # 4 review/policy/ADR templates
├── docs/                           # threat-model, research-references, design-rationale
├── docs-site/                      # GitHub Pages SPA (vanilla JS) — data/full.json is generated
├── scripts/
│   ├── build_docs_json.py          # deterministic full.json generator (run on every source change)
│   └── migrate_schema.py           # one-time Schema B → canonical Schema A migration
├── tests/                          # pytest: loader + server (path-traversal, dispatch, diff)
└── .github/
    ├── dependabot.yml              # weekly pip + github-actions updates
    └── workflows/
        ├── validate.yaml           # CI: YAML, imports, ruff, bandit, pip-audit, content gate, pytest, full.json sync
        ├── security-scan.yml       # CodeQL, semgrep, dependency-review, gitleaks, SBOM
        └── pages.yml               # deploy docs-site to GitHub Pages
```

## 🔬 Research grounding

| Source | Coverage |
|---|---|
| [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework) | Risk governance (GOVERN, MAP, MEASURE, MANAGE) |
| [NIST AI 600-1 GenAI Profile](https://www.nist.gov/artificial-intelligence) | Generative AI-specific risks and controls |
| [CISA Secure AI System Development](https://www.cisa.gov/topics/artificial-intelligence) | Secure AI lifecycle controls |
| [OWASP Top 10 for LLMs](https://genai.owasp.org/) | LLM application security risks |
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

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every checklist item, protocol step, and mapping must cite a source. To regenerate the docs bundle after any source change:

```bash
python scripts/build_docs_json.py   # then commit docs-site/data/full.json (CI verifies sync)
```

## 🔒 Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. This project dogfoods its own controls — the repo itself is scanned with CodeQL, semgrep, bandit, pip-audit, and gitleaks on every push.

## 📄 License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to share and adapt with attribution.