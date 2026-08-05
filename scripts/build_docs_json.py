#!/usr/bin/env python3
"""Regenerate ``docs-site/data/full.json`` from the source data files.

Reads every checklist, mapping, protocol, skill, doc, and template and emits a
single JSON bundle the docs-site SPA renders from. Output is deterministic
(sorted keys, no timestamps) so CI can detect drift with ``git diff``.

Run:  python scripts/build_docs_json.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parent.parent
CHECKLISTS_DIR = REPO / "checklists"
MAPPINGS_DIR = REPO / "mappings"
PROTOCOLS_DIR = REPO / "protocols"
SKILLS_DIR = REPO / "skills"
DOCS_DIR = REPO / "docs"
TEMPLATES_DIR = REPO / "templates"
OUT = REPO / "docs-site" / "data" / "full.json"

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", re.DOTALL)
_H1_RE = re.compile(r"\A\s*#\s+(.+?)\s*\r?\n", re.MULTILINE)


def _load_yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _title_from_h1(text: str, fallback: str) -> str:
    m = _H1_RE.match(text)
    return m.group(1) if m else fallback


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body) for a markdown file with YAML frontmatter."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        fm = {}
    if not isinstance(fm, dict):
        fm = {}
    return fm, m.group(2)


def build_checklists() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(CHECKLISTS_DIR.glob("*.yaml")):
        raw = _load_yaml(path) or {}
        items = raw.get("checklist", []) or []
        # Maintainer visibility: warn on items with empty core fields so a
        # schema regression is visible before the data ships to the docs site.
        for item in items:
            if isinstance(item, dict):
                for key in ("threat", "control", "verification"):
                    if not item.get(key):
                        print(
                            f"WARNING: {path.name}/{item.get('id', '?')} has empty {key!r}",
                            file=sys.stderr,
                        )
        out[path.stem] = {
            "meta": raw.get("metadata", {}) or {},
            "items": items,
        }
    return out


def build_mappings() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(MAPPINGS_DIR.glob("*.yaml")):
        raw = _load_yaml(path) or {}
        out[path.stem] = {
            "meta": raw.get("metadata", {}) or {},
            "entries": raw.get("mappings", []) or [],
        }
    return out


def build_markdown_dir(directory: Path) -> dict[str, dict]:
    """Build {key: {title, content}} for a directory of markdown files."""
    out: dict[str, dict] = {}
    for path in sorted(directory.glob("*.md")):
        text = _read(path)
        out[path.stem] = {
            "title": _title_from_h1(text, path.stem),
            "content": text,
        }
    return out


def build_skills() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        text = _read(path)
        fm, body = _split_frontmatter(text)
        out[path.parent.stem] = {"frontmatter": fm, "content": body}
    return out


def build() -> dict[str, Any]:
    return {
        "checklists": build_checklists(),
        "mappings": build_mappings(),
        "protocols": build_markdown_dir(PROTOCOLS_DIR),
        "skills": build_skills(),
        "docs": build_markdown_dir(DOCS_DIR),
        "templates": build_markdown_dir(TEMPLATES_DIR),
    }


def main() -> int:
    data = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    # Deterministic: sorted keys, 2-space indent, ASCII-only (ensure_ascii keeps
    # it stable across locales; the SPA handles unicode in content fine).
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    counts = {k: len(v) for k, v in data.items()}
    print(f"Wrote {OUT} — {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())