# Security Policy

Cinch is itself a security tool: an MCP server and skill library for building and
operating AI agents safely. We hold the project's own code to the same bar it
imposes on the systems it assesses.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security vulnerabilities.**

Instead, report them privately using GitHub's built-in vulnerability reporting:

1. Go to **Security → Report a vulnerability** on the
   [nirhalfon/cinch-ai-security](https://github.com/nirhalfon/cinch-ai-security/security/advisories/new)
   repository.
2. Describe the issue, the affected file(s), a proof of concept, and the impact.
3. Submit the advisory as **private**. You will be notified when it is triaged.

This creates a private, auditable channel between you and the maintainers. We
acknowledge reports within **5 business days** and aim to provide an initial
assessment within **14 days**.

## Scope

In scope:
- The MCP server (`src/cinch/`) — e.g. path traversal, input validation bypasses,
  crashes from malformed tool arguments, log injection.
- The docs site (`docs-site/`) — e.g. stored XSS via checklist/mapping/template
  content rendered by the SPA.
- CI workflows and dependency manifests.

Out of scope:
- The *content* of the checklists, mappings, and protocols (these are curated
  security guidance, not executable code). Disagreements with a control's
  wording are regular issues/PRs, not security advisories.
- Vulnerabilities in downstream agents that consume Cinch — those belong to the
  agent's own project.

## Supported Versions

Only the latest released version and the `main` branch receive security fixes.

## Security Measures Already in Place

- **Path-traversal prevention:** all MCP tool arguments that name a resource are
  validated against a strict allowlist (`^[a-z0-9][a-z0-9-]{0,63}$`) and the
  resolved path is asserted to remain inside the data directory.
- **Defense in depth:** the MCP SDK 2.0 server is configured with
  `reject_path_traversal=True` for resource parameters; the loader validates
  independently.
- **No `yaml.load`:** YAML is parsed exclusively with `yaml.safe_load`.
- **ReDoS resistance:** threat-search queries are `re.escape`d and length-capped.
- **XSS hardening:** the docs SPA HTML-escapes all data-field text before
  interpolation into `innerHTML`.
- **Audit logging:** tool calls are logged to stderr with argument key/lengths
  only — never argument values.
- **Supply chain:** `bandit`, `pip-audit`, and `ruff` run in CI on every push.

## Coordinated Disclosure

We follow coordinated disclosure. Once a fix is released, we credit the reporter
(unless they prefer to remain anonymous) and publish a GitHub Security Advisory
with a CVE if eligible.