# Research References

## Frameworks and Standards

| Reference | URL | Coverage |
|---|---|---|
| NIST AI RMF 1.0 | https://www.nist.gov/itl/ai-risk-management-framework | Risk governance (GOVERN, MAP, MEASURE, MANAGE) |
| NIST AI 600-1 (GenAI Profile) | https://www.nist.gov/artificial-intelligence | Generative AI-specific risks and controls |
| CISA Secure AI System Development | https://www.cisa.gov/topics/artificial-intelligence | Secure AI lifecycle controls |
| OWASP Top 10 for LLM Applications | https://genai.owasp.org/ | LLM application security risks |
| OWASP Agentic AI | https://owasp.org/www-project-ai-red-teaming-guide/ | Agent threat modeling and controls |
| MITRE ATLAS | https://atlas.mitre.org/ | Adversarial threat landscape for AI |
| ISO/IEC 42001 | https://www.iso.org/standard/81230.html | AI management system standard |
| ETSI SAI Series | https://www.etsi.org/committee/sai | AI cybersecurity standardization (11 standards) |

## Agent Containment

| Reference | URL | Coverage |
|---|---|---|
| CUSTODY Framework | https://github.com/malwarejake/CUSTODY-framework | Autonomous agent containment |
| LASM (Layered Attack Surface Model) | https://github.com/yuval14/Artificial-Intelligence-Cyber-Shield | 7×4 threat model for agents |
| Google Secure AI Framework | https://saif.google/ | Secure AI architecture baseline |
| Microsoft AI Agent Security | https://learn.microsoft.com/en-us/azure/ai-foundry/ | Enterprise agent deployment |
| Cloud Security Alliance Agentic AI | https://cloudsecurityalliance.org/ | Enterprise agent security and red teaming |
| Pillar Security SAIL | https://www.pillar.security/ | Secure AI Lifecycle Framework |

## Red Teaming

| Reference | URL | Coverage |
|---|---|---|
| PyRIT | https://github.com/Azure/PyRIT | Automated LLM red teaming |
| garak | https://github.com/NVIDIA/garak | LLM vulnerability scanner |
| UK AISI Inspect | https://inspect.aisi.org.uk/ | Model evaluation framework |
| Meta Purple Llama | https://github.com/meta-llama/PurpleLlama | Trust and safety evaluation |
| Meta CyberSecEval | https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks | Cybersecurity misuse evaluation |
| MLCommons AILuminate | https://mlcommons.org/ailuminate/ | AI risk and reliability benchmark |
| IBM ART | https://github.com/Trusted-AI/adversarial-robustness-toolbox | Adversarial robustness testing |

## Engineering Safeguards

| Reference | URL | Coverage |
|---|---|---|
| AI Harness Scorecard | https://github.com/markmishaev76/ai-harness-scorecard | Engineering safeguards for AI-assisted dev |
| DORA 2025 | https://dora.dev/research/2025/ | CI/CD practices, stability metrics, AI impact |
| SlopCodeBench | https://huggingface.co/blog/slopcodebench | Subtle correctness in AI-generated code |
| OpenAI Harness Engineering | https://openai.com/index/harness-engineering/ | Mechanical constraints for safe AI-assisted dev |
| "Is It Safe?" (ICLR 2026) | https://openreview.net/forum?id=rs6rRCEixQ | Vibe-coding security benchmark |

## System Hardening

| Reference | URL | Coverage |
|---|---|---|
| SELinux | https://selinuxproject.org/ | Mandatory access control for Linux |
| AppArmor | https://apparmor.net/ | Mandatory access control for Linux |
| seccomp | https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html | Syscall filtering |
| Landlock | https://landlock.io/ | Unprivileged access control for Linux |
| systemd sandboxing | https://www.freedesktop.org/software/systemd/man/systemd.exec.html | Process isolation and capability restriction |
| Windows Application Control | https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/ | Code integrity and application allowlisting |

## Research Papers

| Paper | Year | Key Finding |
|---|---|---|
| "AI Code in the Wild" — Yan et al. | 2025 | AI-induced vulnerabilities propagate through shared models, creating near-identical insecure templates |
| "Is It Safe?" — Vibe Coding Security Benchmark | 2026 | 47.5% of AI tasks functionally correct, only 8.25% also secure |
| "An Empirical Evaluation of Property-Based Testing in Python" — OOPSLA | 2025 | Each PBT finds ~50x as many mutations as average unit test |
| AgentWatch — UC Berkeley CLTC | 2026 | Browser-based agents fail privacy and security scenarios |
| DORA AI Capabilities Model | 2025 | AI boosts throughput at the expense of stability without robust automated testing |

## Attribution

- CUSTODY Framework by Jake Williams (malwarejake)
- LASM by Kexin Chu (2026)
- AI Harness Scorecard by Mark Mishaev
- Artificial Intelligence Cyber Shield by Yuval Sinay
- NIST AI RMF by NIST ITL AI Program
- OWASP Top 10 for LLM Applications by OWASP
- MITRE ATLAS by MITRE