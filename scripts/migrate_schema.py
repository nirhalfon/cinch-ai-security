#!/usr/bin/env python3
"""One-time migration: convert Schema B checklists to canonical Schema A.

Schema B items use ``title`` / ``description`` / ``validation{type,
evidence_required}`` / ``references``. Canonical Schema A (used by
``agent-containment.yaml`` and the loader's ``ChecklistItem``) uses ``threat``
/ ``control`` / ``verification`` / ``sources`` (+ optional ``custody_pillar``
/ ``lasm_layer`` / ``weight``).

This script rewrites each Schema B checklist in place to Schema A, preserving
the file header and section-divider comments. It is idempotent: files already
in Schema A (items that already have a ``threat`` key) are skipped.

Run:  python scripts/migrate_schema.py

The transform per item:
  threat        <- title
  control       <- description (stripped)
  verification  <- f"{validation.type} — evidence required: {validation.evidence_required}"
  sources       <- references
  custody_pillar / lasm_layer / weight  <- "" (not derivable from crosswalks today)
  id / category / severity              <- unchanged

Field order follows ``agent-containment.yaml``:
  id, category, custody_pillar, lasm_layer, threat, control, severity,
  verification, sources
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent  # type: ignore[name-defined]
CHECKLISTS_DIR = REPO / "checklists"

# Schema B files (the four that use title/description/validation/references).
SCHEMA_B_FILES = [
    "harness-engineering.yaml",
    "red-team.yaml",
    "supply-chain.yaml",
    "system-hardening.yaml",
]

# Canonical field order, matching agent-containment.yaml.
ITEM_FIELDS = [
    "id",
    "category",
    "custody_pillar",
    "lasm_layer",
    "threat",
    "control",
    "severity",
    "verification",
    "sources",
]


def _is_schema_b(raw: dict) -> bool:
    """True if the first checklist item uses Schema B keys (no ``threat``)."""
    items = raw.get("checklist") or []
    if not items or not isinstance(items[0], dict):
        return False
    return "threat" not in items[0] and "title" in items[0]


def _convert_item(item: dict) -> dict:
    """Map a Schema B item to canonical Schema A field names/order."""
    validation = item.get("validation") or {}
    vtype = validation.get("type", "") if isinstance(validation, dict) else ""
    evidence = (
        validation.get("evidence_required", "") if isinstance(validation, dict) else ""
    )
    if vtype and evidence:
        verification = f"{vtype} — evidence required: {evidence}"
    elif vtype:
        verification = vtype
    elif evidence:
        verification = f"evidence required: {evidence}"
    else:
        verification = ""
    description = item.get("description", "") or ""
    if isinstance(description, str):
        description = description.strip()
    converted = {
        "id": item.get("id", ""),
        "category": item.get("category", ""),
        "threat": item.get("title", "") or "",
        "control": description,
        "severity": item.get("severity", ""),
        "verification": verification,
    }
    # Optional framework fields: include only when present and non-empty, so
    # the output stays clean. custody_pillar/lasm_layer are not derivable from
    # the Schema B data or the current crosswalks, so they are omitted.
    sources = item.get("references", []) or []
    if sources:
        converted["sources"] = sources
    return converted


def _category_name(meta: dict, cat_id: str) -> str:
    """Look up a human category name from metadata.categories, fallback to id."""
    for c in meta.get("categories", []) or []:
        if isinstance(c, dict) and c.get("id") == cat_id:
            return str(c.get("name", cat_id))
    return cat_id


def _dump_item(item: dict) -> str:
    """Dump a single item as a YAML sequence entry under ``checklist:``.

    The first line gets the ``  - `` sequence marker; subsequent lines are
    indented 4 spaces so the keys nest under the marker.
    """
    ordered = {k: item[k] for k in ITEM_FIELDS if k in item}
    buf = io.StringIO()
    yaml.safe_dump(
        ordered,
        buf,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        indent=2,
        width=100,
    )
    lines = buf.getvalue().splitlines(True)
    out = ["  - " + lines[0]]
    out.extend("    " + line for line in lines[1:])
    return "".join(out)


def _build_file(raw: dict, header_lines: list[str]) -> str:
    """Rebuild the full file text: header + metadata + checklist with dividers."""
    meta = raw.get("metadata", {}) or {}
    items = raw.get("checklist", []) or []
    out = io.StringIO()
    # Preserve the original header comment block (lines before `metadata:`).
    out.writelines(header_lines)
    if header_lines and not header_lines[-1].endswith("\n\n"):
        out.write("\n")
    # Dump metadata block.
    meta_buf = io.StringIO()
    yaml.safe_dump(
        {"metadata": meta},
        meta_buf,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        indent=2,
        width=100,
    )
    out.write(meta_buf.getvalue())
    out.write("checklist:\n")
    last_cat = None
    for item in items:
        converted = _convert_item(item)
        cat = converted.get("category", "")
        if cat != last_cat:
            name = _category_name(meta, cat)
            out.write(f"\n  # ── {name} ──────────────────────────────────────\n\n")
            last_cat = cat
        out.write(_dump_item(converted))
        out.write("\n")
    return out.getvalue()


def _read_header(path: Path) -> list[str]:
    """Return the leading comment lines (before the first non-comment, non-blank line)."""
    header: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                break
            header.append(line)
    # Drop trailing blank lines from the header block.
    while header and header[-1].strip() == "":
        header.pop()
    if header:
        header.append("\n")
    return header


def migrate(path: Path) -> str:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return f"{path.name}: not a mapping, skipped"
    if not _is_schema_b(raw):
        return f"{path.name}: already Schema A (or empty), skipped"
    header = _read_header(path)
    new_text = _build_file(raw, header)
    path.write_text(new_text, encoding="utf-8")
    n = len(raw.get("checklist", []) or [])
    return f"{path.name}: migrated {n} items to Schema A"


def main() -> int:
    for name in SCHEMA_B_FILES:
        path = CHECKLISTS_DIR / name
        if not path.exists():
            print(f"{name}: missing, skipped", file=sys.stderr)
            continue
        print(migrate(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())