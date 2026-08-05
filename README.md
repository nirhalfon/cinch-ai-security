<div align="center">

# 🛡️ Cinch

### Contain your AI agents before they reach production.

**MCP server + cross-harness skills for building and operating AI agents safely.**

*The model proposes; the architecture authorizes and enforces.*

<br/>

[![Open the live console](https://img.shields.io/badge/▶%20Open%20the%20live%20console-3b82f6?style=for-the-badge&logoColor=white)](https://nirhalfon.github.io/cinch-ai-security/)
[![Install from PyPI](https://img.shields.io/badge/pip%20install-cinch--ai--security-0f172a?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/cinch-ai-security/)
[![View on GitHub](https://img.shields.io/badge/View%20on-GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/nirhalfon/cinch-ai-security)

<br/>

[![PyPI](https://img.shields.io/pypi/v/cinch-ai-security?color=blue&label=PyPI&logo=pypi&logoColor=white)](https://pypi.org/project/cinch-ai-security/)
[![Python](https://img.shields.io/pypi/pyversions/cinch-ai-security?logo=python&logoColor=white)](https://pypi.org/project/cinch-ai-security/)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-green?logo=creativecommons&logoColor=white)](https://creativecommons.org/licenses/by/4.0/)
[![CI](https://img.shields.io/github/actions/workflow/status/nirhalfon/cinch-ai-security/validate.yaml?label=CI&logo=githubactions&logoColor=white)](https://github.com/nirhalfon/cinch-ai-security/actions/workflows/validate.yaml)
[![Security](https://img.shields.io/github/actions/workflow/status/nirhalfon/cinch-ai-security/security-scan.yml?label=security&logo=githubactions&logoColor=white)](https://github.com/nirhalfon/cinch-ai-security/actions/workflows/security-scan.yml)
[![MCP](https://img.shields.io/badge/MCP-2.0-22d3ee?logo=protocolsdotio&logoColor=white)](https://modelcontextprotocol.io)

<br/>

| 117 | 6 | 9 | 5 | 5 | 4 | 3 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **controls** | **checklists** | **MCP tools** | **crosswalks** | **protocols** | **templates** | **skills** |

**Grounded in** NIST AI RMF · CISA Secure AI Development · OWASP LLM & Agentic · MITRE ATLAS · CUSTODY · LASM · Google SAIF · DORA 2025

</div>

---

AI agents can read data, invoke tools, execute code, call APIs, and initiate business processes. When they go wrong — through prompt injection, excessive autonomy, credential theft, or model error — **the consequences are only as severe as the environment allows.** Cinch gives you the enforceable controls, protocols, and runtime queries to keep that environment contained.

## ✨ What's inside

| | What | Why it matters |
|---|---|---|
| 📋 | **6 checklists** (117 controls) | Enforceable, framework-mapped YAML — not advice, controls |
| 🔎 | **Probes** (host · project · behaviour) | Assess a **running** agent: inspect its process, its deployment, and how it behaves under attack |
| 📡 | **MCP server** (9 tools) | Any MCP-compatible agent queries controls at runtime — and can collect + verify evidence |
| 🖥️ | **Assessment console** | Grade a deployment, get insights + a phased action plan, export JSON/CSV/PDF |
| 🧠 | **3 skills** | Drop-in Hermes skill definitions for security reviews & red-teaming |
| 📐 | **5 protocols** | Step-by-step deployment, incident-response, and evidence collection |
| 🔗 | **5 mappings** | Crosswalks: NIST AI RMF · OWASP LLM · MITRE ATLAS · CUSTODY · LASM |
| 📄 | **4 templates** | Security review, risk assessment, agent policy, deployment ADR |

---

## 🖥️ The assessment console

> **[▶ Try the hosted console](https://nirhalfon.github.io/cinch-ai-security/)** — no install required.

One page, two modes: a landing page for the project, and a live containment assessment dashboard. It is **not a static mockup** — it loads a real assessment result pack and renders the analysis: **letter grade, insights, ranked recommendations, and a phased action plan**. Mark a control **Enforced / Gap / N-A** and every one of those re-derives instantly.

| View | What you get |
|---|---|
| **Overview** | Grade, containment score, top insights, "do now" queue, open-gap feed, per-checklist counts |
| **Insights & plan** | Grade + why it was capped, ranked findings, one recommendation per gap (do this → verify like this), remediation phased Now / Next / Later with exit criteria |
| **Assessment** | Walk the checklist control by control, attach evidence as you go |
| **Control library** | All 117 controls across 6 checklists — searchable, filterable, assessable inline |
| **Threat model** | LASM 7×4 attack-surface grid derived live from the catalog's layer mapping |
| **Framework coverage** | NIST AI RMF, OWASP, CUSTODY, ATLAS, LASM crosswalks against your answers |
| **Export** | JSON (full result pack for CI gating and diffs), CSV (gap register with phase + rank), PDF (grade, insights, action plan, recommendations, crosswalk) |

### Where the results come from

Two ways to produce them, one engine grading both:

1. **Probe a running agent** — `cinch collect` observes the real deployment and emits an evidence bundle; `cinch verify` grades it. This is the primary path.
2. **Review by hand** — `cinch assess` grades a state file a reviewer filled in (or the console session they clicked through).

The grade itself is computed once and shown everywhere: `src/cinch/assess.py` for the CLI and CI, the dashboard for the browser, both reading their rules — severity weights, grade bands, critical-gap caps, remediation phases — from **`docs-site/data/rubric.json`**. Change a rule there and both follow.

```bash
# review by hand
cinch assess --state examples/assessment-state.json            # grade + insights + action plan
cinch assess --state examples/assessment-state.json --out pack.json
cinch console --assessment pack.json                            # open the dashboard on it
cinch assess --state pack.json --fail-on critical               # gate a release (exit 2)
```

A state file is just what a reviewer decided (see [`examples/assessment-state.json`](examples/assessment-state.json)):

```json
{
  "deployment": "checkout-agent-prod",
  "status":   { "AC-001": "pass", "AC-006": "fail", "AC-014": "na" },
  "evidence": { "AC-006": "retrieval output concatenated into the system turn" }
}
```

---

## 🔎 Assess a running agent

Nobody wants to hand-answer 117 controls. `cinch collect` observes the deployment and answers what it can prove, in the agent's own environment.

```bash
# 1. probe the agent — out of band, as an operator/sidecar/CI identity
cinch collect --host --pid $AGENT_PID \
              --project /srv/checkout-agent \
              --deployment checkout-agent-prod \
              --sign-cmd 'cosign sign-blob -' \
              --out evidence.json

# 2. grade the evidence
cinch verify --evidence evidence.json --out pack.json --fail-on critical

# 3. look at it
cinch console --assessment pack.json
```

### What each probe family observes

| Family | Flag | Reads | Controls |
|---|---|---|---|
| **Host** | `--host --pid/--unit` | The kernel's view of the agent process: UID and `NoNewPrivs`, capability sets, AppArmor/SELinux confinement, seccomp filter, netfilter egress policy, network namespace and metadata-API reachability, log forwarding and log ownership, credential-shaped env vars, image digest + SBOM, read-only root, cgroup limits | `AE-001`–`AE-011` |
| **Project** | `--project PATH` | The authority the deployment grants: MCP tool grants, container/pod security context, NetworkPolicy egress, committed secret material, dependency pinning and hashes, SBOM, vulnerability scanning, provenance attestation and image signing, CI runner posture, threat model and IR docs | `HE-*`, `SC-*`, `AC-003/016/018/019/023` |
| **Behaviour** | `--endpoint URL --authorized` | How the running agent responds to adversarial input: direct injection, injection smuggled through retrieved content, system-prompt extraction, tool enumeration, rate-limit presence | `RT-001/002/005/008/009`, `AC-005/006/017` |

Host findings are also mapped onto the containment controls that assert the same thing (`AE-005` egress → `AC-019` exfiltration), labelled `derived:` so the chain stays visible.

### Three statuses, and why `unknown` matters

`pass` demonstrably enforced · `fail` demonstrably not · `unknown` the probe could not tell.

**`unknown` is never a pass.** A probe on macOS with no `/proc`, without `CAP_NET_ADMIN`, or with no manifest to read says so and leaves the control *unreviewed* — it costs completeness instead of quietly earning credit. Keyword hits in config are reported as leads to confirm, not as proof a limit is enforced at runtime. Every observation keeps the raw evidence it was derived from, so you can check the probe's reasoning instead of trusting it. Secret **names** are recorded; secret **values** never are.

### Self-audit is detected, not assumed away

[`protocols/evidence-collect.md`](protocols/evidence-collect.md) is blunt about this: an agent auditing its own host is both auditor and audited, and a compromised or simply mistaken agent can report every control as enforced.

So collection records who collected what, where and when — and when the collector *is* the audited party (same process, or the request came in over MCP from an agent), the bundle is stamped `provenance.self_attested: true`. That becomes a **critical** finding in the assessment, is shown as a red `self-attested` banner in the console, and is never counted as assurance. Independent evidence means `cinch collect` run out of band under its own identity, signed with `--sign-cmd` using a key the agent cannot reach.

Behavioural probing sends adversarial input to a live system, so it refuses to run without `--authorized` naming the target.

### As MCP tools

An auditing agent can drive the same flow:

| Tool | Use it to |
|---|---|
| `evidence_collect` | Probe a deployment (`host`, `project_path`, `endpoint` + `authorized`) → evidence bundle |
| `evidence_verify` | Grade a bundle → score, grade, insights, recommendations, action plan |

Bundles collected through MCP are marked self-attested by construction — the requester is an agent. Use them to *find* problems fast; use an out-of-band signed run when the grade has to mean something.

Three ways to get results into the dashboard:

| Route | How |
|---|---|
| Published pack | `data/assessment.json` next to the page — the hosted console opens on one, regenerated by `scripts/build_assessment.py` |
| Served pack | `cinch console --assessment pack.json` serves any pack from anywhere on disk |
| Loaded by hand | **Load assessment** in the console header — accepts an exported pack or a plain state file; `?assessment=<url>` also works |

Exports round-trip: an exported pack feeds straight back into `cinch assess --state` or the **Load assessment** button, so re-assessments diff cleanly.

**How the grade works.** The score is severity-weighted (critical ×3, high ×2, medium/low ×1) over the controls you actually answered; unanswered controls hit *completeness*, not the score. Grade bands run A–F, but **an unenforced critical control caps the grade at D, and three or more cap it at F** — the pack says which cap fired and why.

### Serve it yourself

The console reads its catalog with `fetch('data/full.json')`, so it must be served over HTTP — opening the file directly with `file://` makes that fetch fail and falls back to a small offline subset. `cinch console` does it for you:

```bash
pip install cinch-ai-security
cinch console                  # serves on http://127.0.0.1:8787 and opens your browser
```

```bash
cinch console --port 9000      # pick another port
cinch console --no-browser     # headless / remote-friendly
cinch console --host 0.0.0.0   # expose on your LAN (read-only, but consider who can reach it)
```

The server is read-only, GET/HEAD only, bound to `127.0.0.1` by default, and rooted at the console directory. Assessment state lives in the browser only — nothing is uploaded anywhere.

From a source checkout, the same page is served straight from `docs-site/`:

```bash
git clone https://github.com/nirhalfon/cinch-ai-security.git
cd cinch-ai-security && pip install -e .
python scripts/build_docs_json.py   # regenerate the catalog bundle after editing any YAML
cinch console
```

### Turn a session into evidence

1. Assess the controls that apply to your deployment (**Control library** → expand → Enforced / Gap / N-A, plus an evidence note).
2. Read **Insights & plan** — the grade, what is actually wrong, and what to do in what order.
3. **Export evidence → Download all** — three artifacts:
   - **JSON** — the full result pack: summary + grade, coverage, insights, ranked recommendations, action plan, and every control with status and evidence. Commit it, diff the next run, gate CI with `cinch assess --fail-on critical`.
   - **CSV** — the gap register, one row per control, with remediation phase and rank, for tickets and trackers.
   - **PDF** — printable report: grade and why it was capped, insights, action plan, recommendations, CUSTODY coverage, open gaps, NIST AI RMF crosswalk.

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
| `evidence_collect` | Probe a running deployment (host / project / endpoint) and get an evidence bundle |
| `evidence_verify` | Grade an evidence bundle → score, grade, insights, recommendations, action plan |
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

### CLI reference

| Command | What it does |
|---|---|
| `cinch serve` | Run the MCP server over stdio (the default with no subcommand) |
| `cinch console` | Serve the assessment console on localhost (`--port`, `--host`, `--no-browser`, `--assessment`) |
| `cinch collect` | Probe a running agent → evidence bundle (`--host`, `--pid`, `--unit`, `--project`, `--endpoint`, `--authorized`, `--sign-cmd`, `--out`) |
| `cinch verify` | Grade an evidence bundle (`--evidence`, `--out`, `--fail-on critical\|high\|any-gap`) |
| `cinch assess` | Grade a hand-reviewed state file (`--state`, `--out`, `--deployment`, `--fail-on`) |

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
│   ├── server.py                   # 9 tool definitions + CLI (serve / console / collect / verify / assess)
│   ├── probes/                     # observe a running agent
│   │   ├── host.py                 # AE-001..AE-011 from /proc, cgroups, netfilter, mountinfo
│   │   ├── project.py              # MCP grants, manifests, CI, pinning, secrets (HE/SC/AC)
│   │   └── behaviour.py            # injection / leakage / tool / rate probes (authorization-gated)
│   ├── collect.py                  # evidence bundle: provenance, self-audit detection, signing
│   ├── verify.py                   # bundle → graded assessment (unknown never becomes a pass)
│   ├── assess.py                   # assessment engine: score, grade, insights, recommendations, plan
│   ├── console.py                  # localhost static server for the assessment console
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
├── marketing/                      # announcement copy (kept out of docs/ — docs/ is bundled)
├── docs-site/                      # the console
│   ├── index.html                  # landing page + assessment dashboard (one file)
│   └── data/
│       ├── full.json               # generated control catalog
│       ├── rubric.json             # scoring rules — shared with src/cinch/assess.py
│       └── assessment.json         # generated result pack the console opens on
├── examples/assessment-state.json  # worked assessment state (input to `cinch assess`)
├── scripts/
│   ├── build_docs_json.py          # deterministic full.json generator (run on every source change)
│   ├── build_assessment.py         # regenerate docs-site/data/assessment.json
│   └── migrate_schema.py           # one-time Schema B → canonical Schema A migration
├── tests/                          # pytest: loader, server, console, assessment engine, probes
└── .github/
    ├── dependabot.yml              # weekly pip + github-actions updates
    └── workflows/
        ├── validate.yaml           # CI: YAML, imports, ruff, bandit, pip-audit, content gate, pytest, full.json sync
        ├── security-scan.yml       # CodeQL, semgrep, dependency-review, gitleaks, SBOM
        └── pages.yml               # deploy the console to GitHub Pages
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

See [CONTRIBUTING.md](CONTRIBUTING.md). Every checklist item, protocol step, and mapping must cite a source. After any source change, regenerate both generated files — CI verifies they are in sync:

```bash
python scripts/build_docs_json.py    # docs-site/data/full.json     (control catalog)
python scripts/build_assessment.py   # docs-site/data/assessment.json (result pack the console opens on)
```

## 🔒 Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. This project dogfoods its own controls — the repo itself is scanned with CodeQL, semgrep, bandit, pip-audit, and gitleaks on every push.

## 📄 License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — free to share and adapt with attribution.
