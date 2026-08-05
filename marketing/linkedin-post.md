# LinkedIn post — Cinch v1.1.0

## Post

Everyone shipping AI agents can tell you what the agent is *supposed* to be allowed to do.

Almost nobody can show you what it can **actually** do at 3am on the production host.

That gap is the whole problem. An agent gets manipulated by a support ticket, or is simply wrong, and the damage is bounded by exactly one thing: what its environment permits. Not the system prompt. Not the policy doc. The environment.

So I built Cinch — an open-source MCP server and CLI that stops asking agents to describe their own security and goes and looks.

𝗪𝗵𝗮𝘁 𝗶𝘁 𝗱𝗼𝗲𝘀

→ **117 enforceable controls**, each mapped to a threat, a verification step, and a framework (NIST AI RMF, CISA, OWASP LLM & Agentic, MITRE ATLAS, CUSTODY, LASM).

→ **Probes a running deployment.** The host: UID, capabilities, seccomp, AppArmor/SELinux, egress policy, metadata-API reachability, read-only root, cgroup limits, credentials sitting in the environment. The project: MCP tool grants, container security context, dependency pinning, committed secrets, CI provenance. The behaviour: direct and content-borne prompt injection, prompt extraction, tool enumeration, rate limits — against the live endpoint, with authorization required.

→ **Grades it.** A–F, severity-weighted, with insights, one ranked recommendation per gap (do this → verify like this), and a Now/Next/Later plan with exit criteria. One unenforced critical control caps the grade at D no matter how good the score looks.

→ **CI-gates it.** `cinch verify --fail-on critical` exits non-zero. Evidence exports as JSON/CSV/PDF.

𝗧𝘄𝗼 𝗱𝗲𝘀𝗶𝗴𝗻 𝗱𝗲𝗰𝗶𝘀𝗶𝗼𝗻𝘀 𝗜'𝗱 𝗱𝗲𝗳𝗲𝗻𝗱 𝗶𝗻 𝗮𝗻𝘆 𝗿𝗼𝗼𝗺

**1. "Unknown" is never "pass."** If a probe can't prove a control — no privilege, wrong OS, no manifest to read — it says so and leaves the control unreviewed. It costs you completeness instead of quietly earning you credit. Most security tooling fails in the flattering direction. This one refuses to.

**2. Self-audit gets detected, not assumed away.** An agent auditing its own host is both the auditor and the audited; a compromised or mistaken agent can mark everything green. When the collector *is* the audited party, the evidence bundle is stamped `self_attested`, that becomes a critical finding, and it is never counted as assurance. Independent evidence means an out-of-band run, signed with a key the agent can't reach.

𝗪𝗵𝗼 𝘁𝗵𝗶𝘀 𝗶𝘀 𝗳𝗼𝗿

Security engineers who own an agent deployment and need evidence, not vibes. Platform teams gating agent releases in CI. AI engineers who want the controls at runtime instead of in a PDF nobody opens. GRC folks who need NIST/OWASP crosswalks that trace back to something observed.

```
pip install cinch-ai-security
cinch collect --host --pid $AGENT_PID --project /srv/agent --out evidence.json
cinch verify --evidence evidence.json --fail-on critical
```

Live console (no install): https://nirhalfon.github.io/cinch-ai-security/
Code: https://github.com/nirhalfon/cinch-ai-security

The model proposes. The architecture authorizes and enforces. Everything else is a hope.

What's the control you'd *want* verified automatically on your agents — and what's stopping you today?

#AISecurity #AIAgents #MCP #AppSec #DevSecOps #NIST #OWASP #SupplyChainSecurity #OpenSource

---

## Notes on using this

- **Length:** ~2,900 characters, inside LinkedIn's 3,000 limit. The first two lines are what shows before "see more" — they carry the hook on their own.
- **Bold** uses Unicode math sans-serif so it survives LinkedIn's plain-text editor. Paste as-is.
- **Code block:** LinkedIn strips backticks. Either delete the fence lines and leave the three commands as plain lines, or drop the commands and let the links carry it.
- **First comment:** put a concrete finding there — e.g. "First run against our own repo scored D: two critical supply-chain gaps, no SBOM, no provenance attestation. The tool failing its own audit is the point." Comments with substance lift reach more than hashtags do.
- **If you want a shorter variant:** keep the hook, the two design decisions, and the links; drop the "what it does" bullets.
