---
name: ai-harness-review
description: >
  Review a repository or project for AI harness security engineering safeguards.
  Checks architectural documentation, mechanical constraints, testing, review processes,
  and AI-specific safeguards. Maps findings to NIST AI RMF, OWASP, CUSTODY, and LASM.
triggers:
  - review the ai harness
  - check harness security
  - assess ai development safeguards
  - run harness scorecard
  - evaluate ai engineering practices
tools:
  - read_file
  - search_files
  - terminal
  - patch
  - write_file
---

# AI Harness Review Skill

Review a repository or project for AI harness security engineering safeguards.

## Steps

1. **Identify the target** — Confirm the repository path or project directory to review.

2. **Load the harness-engineering checklist** — Read `checklists/harness-engineering.yaml` and use it as the assessment framework. Each item has an ID (HE-001 through HE-025), category, threat, control, severity, and verification step.

3. **Assess architectural documentation (20%)**:
   - HE-001: Does ARCHITECTURE.md or equivalent exist and is it current?
   - HE-002: Does AGENTS.md or equivalent AI instruction file exist?
   - HE-003: Are Architecture Decision Records (ADRs) maintained?
   - HE-004: Are module boundary constraints documented?
   - HE-005: Is API documentation available for public interfaces?

4. **Assess mechanical constraints (25%)**:
   - HE-006: Does CI enforce linting, formatting, and type checking as blocking gates?
   - HE-007: Is automated dependency auditing configured (Dependabot, Snyk, etc.)?
   - HE-008: Is an unsafe code policy documented and enforced by security linters?
   - HE-009: Are conventional commits enforced?
   - HE-010: Is type safety enforced in CI?

5. **Assess testing and stability (25%)**:
   - HE-011: Does CI run a blocking test suite?
   - HE-012: Is feature matrix testing configured?
   - HE-013: Is mutation testing in use?
   - HE-014: Is property-based testing configured?
   - HE-015: Is fuzz testing configured for security-critical inputs?
   - HE-016: Do contract tests verify API compatibility?

6. **Assess review and drift prevention (15%)**:
   - HE-017: Is code review enforced (at least one human approval)?
   - HE-018: Is stale documentation detection configured?
   - HE-019: Are scheduled CI runs configured?
   - HE-020: Do PR templates include AI usage disclosure fields?

7. **Assess AI-specific safeguards (15%)**:
   - HE-021: Are AI usage norms documented?
   - HE-022: Are small batch size limits enforced?
   - HE-023: Is a design-before-code culture in place?
   - HE-024: Is an error handling policy documented?
   - HE-025: Are security-critical code paths marked?

8. **Calculate scores** — For each category, calculate the percentage of items that pass. Apply weights:
   - Architectural Documentation: 20%
   - Mechanical Constraints: 25%
   - Testing and Stability: 25%
   - Review and Drift Prevention: 15%
   - AI-Specific Safeguards: 15%

9. **Assign a grade**:
   - A (85-100): Strong harness. AI-generated code has robust mechanical safeguards.
   - B (70-84): Good foundation. Some gaps in enforcement or feedback loops.
   - C (55-69): Basic practices present but insufficient for safe AI scaling.
   - D (40-54): Significant gaps. AI code likely accumulating undetected debt.
   - F (0-39): No meaningful harness. AI output is essentially unaudited.

10. **Map findings to frameworks** — Cross-reference failed items to NIST AI RMF, OWASP, CUSTODY, and LASM controls using the mapping files in `mappings/`.

11. **Generate remediation plan** — For each failed item, provide:
    - The item ID and description
    - The threat it addresses
    - The recommended control
    - Specific commands or config changes to implement it
    - Framework references

12. **Deliver the report** — Present the assessment as a structured report with:
    - Overall grade and numeric score
    - Category breakdown table
    - Per-item pass/fail with verification details
    - Prioritized remediation list (critical → low)
    - Framework mapping table

## Pitfalls

- Do not skip verification steps. Each item requires checking actual configuration, not just file existence.
- CI configuration must be checked for blocking behavior, not just presence.
- Security linters must be configured and blocking, not just installed.
- AI usage norms must be documented and enforced, not just informal.
- The goal is mechanical enforcement, not aspirational guidance.