# Contributing to Cinch

Thank you for contributing. Every claim must cite a source. Every control must map to a threat.

## Principles

1. **Every claim must cite a source.** Checklist items, protocol steps, and mappings must reference a specific framework, standard, research paper, or published best practice.
2. **Enforceable over aspirational.** Prefer controls that can be verified by a checklist, test, or audit over vague guidance.
3. **Threat-to-control mapping.** Every control must map to one or more threats. If you add a control, identify the threat it mitigates.
4. **Architecture-level, not model-level.** Focus on environment, infrastructure, and process — not model alignment or prompt engineering alone.

## How to contribute

### Add or modify a checklist item

1. Edit the relevant YAML file in `checklists/`
2. Every item must include: `id`, `category`, `threat`, `control`, `severity`, `verification`, `sources`
3. Validate: `python3 -c "import yaml; yaml.safe_load(open('checklists/YOUR_FILE.yaml'))"`

### Add a protocol

1. Create or edit a Markdown file in `protocols/`
2. Follow the structure: Purpose → Scope → Prerequisites → Steps → Verification → Rollback
3. Reference checklist items by ID

### Add a skill

1. Create a directory under `skills/` with a `SKILL.md` file
2. Follow the Hermes Agent SKILL.md format (YAML frontmatter + markdown body)
3. Include trigger conditions, numbered steps, pitfalls, and verification

### Add a mapping

1. Edit or create the relevant YAML file in `mappings/`
2. Each mapping entry must include: `framework`, `control_id`, `framework_control_name`, `checklist_ids`, `description`

### Add a cross-harness config

1. Create or edit the config file in `cross-harness/`
2. Follow the existing format for the target agent (Claude, OpenClaw, NanoClaw)
3. Include all relevant CUSTODY pillars and checklist items

## Formatting

- YAML files: 2-space indent, keys in snake_case
- Markdown files: ATX headers, 80-char soft wrap
- File names: kebab-case (e.g., `agent-containment.yaml`)
- Checklist IDs: uppercase prefix + number (e.g., `AC-001`, `HE-006`, `RT-015`)

## Pull request checklist

- [ ] All YAML files validate
- [ ] Every new item cites at least one source
- [ ] Every new control maps to a threat
- [ ] No duplicate IDs within a file
- [ ] Commit message follows conventional commits format

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be respectful. Be precise. Cite your sources.