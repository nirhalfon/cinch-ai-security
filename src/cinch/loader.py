"""YAML checklist, protocol, and mapping loader."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "checklists"
MAPPINGS_DIR = Path(__file__).resolve().parent.parent.parent / "mappings"
PROTOCOLS_DIR = Path(__file__).resolve().parent.parent.parent / "protocols"

# Strict allowlist for resource names. Rejects path separators, "..", drive
# letters, whitespace, extensions, and anything that could escape a data dir.
# This is the primary defense against path-traversal via MCP tool arguments.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# Reasonable upper bound on a threat-search query to bound regex work.
MAX_QUERY_LEN = 256

# Short framework name -> on-disk mapping file stem. Lets mapping_lookup accept
# the documented short names ('nist-rmf', 'owasp-llm', ...) as well as the full
# '-crosswalk' stems. Values are hardcoded safe bare identifiers.
_MAPPING_FILES = {
    "atlas": "atlas-crosswalk",
    "custody": "custody-crosswalk",
    "lasm": "lasm-crosswalk",
    "nist-rmf": "nist-rmf-crosswalk",
    "owasp-llm": "owasp-llm-crosswalk",
}


def _validate_name(name: str) -> str:
    """Validate a resource name and return it stripped.

    Raises ValueError if the name is not a safe bare identifier. This prevents
    path-traversal: only lowercase alphanumerics and hyphens are permitted, so
    no ``/``, ``..``, leading dot, extension, or whitespace can reach the path
    builder.
    """
    if not isinstance(name, str):
        raise TypeError(f"invalid name: expected string, got {type(name).__name__}")
    name = name.strip()
    if not _NAME_RE.match(name):
        raise ValueError(
            "invalid name: must be 1-64 chars of lowercase a-z, 0-9, or '-' "
            f"(got {name!r})"
        )
    return name


def _safe_path(base: Path, name: str, suffix: str) -> Path:
    """Build a path ``base / name + suffix`` and assert it stays within ``base``.

    Defense in depth on top of ``_validate_name``: even if a caller bypasses the
    allowlist, the resolved path must resolve inside ``base`` or we refuse.
    """
    base = base.resolve()
    path = (base / f"{name}{suffix}").resolve()
    if not path.is_relative_to(base):
        raise ValueError(f"unsafe path escapes data directory: {name!r}")
    return path


@dataclass
class ChecklistItem:
    """A single security checklist item."""

    id: str
    category: str
    threat: str
    control: str
    severity: str
    verification: str
    sources: list[str] = field(default_factory=list)
    # Optional framework references
    custody_pillar: str = ""
    lasm_layer: str = ""
    weight: str = ""


@dataclass
class Checklist:
    """A named security checklist."""

    name: str
    version: str
    description: str
    items: list[ChecklistItem] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    source_repos: list[str] = field(default_factory=list)


@dataclass
class MappingEntry:
    """A single framework cross-reference mapping."""

    framework: str
    control_id: str
    framework_control_name: str
    checklist_ids: list[str]
    description: str


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def _load_yaml_or_none(path: Path) -> dict[str, Any] | None:
    """Load a YAML file, returning None on a parse/IO error (never raise)."""
    try:
        return _load_yaml(path)
    except (yaml.YAMLError, OSError):
        return None


def load_checklist(name: str) -> Checklist:
    """Load a named checklist from the checklists directory.

    Args:
        name: Checklist filename without .yaml extension (e.g. 'agent-containment')

    Returns:
        Parsed Checklist object.
    """
    name = _validate_name(name)
    path = _safe_path(DATA_DIR, name, ".yaml")
    if not path.exists():
        raise FileNotFoundError(f"Checklist not found: {path}")
    raw = _load_yaml(path)
    meta = raw.get("metadata", {})
    items = []
    for item_data in raw.get("checklist", []):
        items.append(
            ChecklistItem(
                id=item_data["id"],
                category=item_data.get("category", ""),
                threat=item_data.get("threat", ""),
                control=item_data.get("control", ""),
                severity=item_data.get("severity", ""),
                verification=item_data.get("verification", ""),
                sources=item_data.get("sources", []),
                custody_pillar=item_data.get("custody_pillar", ""),
                lasm_layer=item_data.get("lasm_layer", ""),
                weight=item_data.get("weight", ""),
            )
        )
    return Checklist(
        name=meta.get("name", name),
        version=meta.get("version", "0.0.0"),
        description=meta.get("description", ""),
        items=items,
        frameworks=meta.get("frameworks", []),
        source_repos=meta.get("source_repos", []),
    )


def list_checklists() -> list[dict[str, Any]]:
    """List all available checklists with metadata."""
    results = []
    for path in sorted(DATA_DIR.glob("*.yaml")):
        raw = _load_yaml_or_none(path)
        if not isinstance(raw, dict):
            results.append({"name": path.stem, "error": "invalid or unreadable YAML"})
            continue
        meta = raw.get("metadata", {}) or {}
        items = raw.get("checklist", []) or []
        results.append(
            {
                "name": path.stem,
                "display_name": meta.get("name", path.stem),
                "version": meta.get("version", "0.0.0"),
                "description": (meta.get("description", "") or "")[:200],
                "item_count": len(items),
                "frameworks": meta.get("frameworks", []) or [],
            }
        )
    return results


def get_checklist_item(checklist_name: str, item_id: str) -> ChecklistItem | None:
    """Get a specific checklist item by ID."""
    checklist = load_checklist(checklist_name)
    if not isinstance(item_id, str):
        raise TypeError(f"invalid item_id: expected string, got {type(item_id).__name__}")
    if not re.match(r"^[A-Za-z0-9-]{1,32}$", item_id):
        raise ValueError(f"invalid item_id: {item_id!r}")
    for item in checklist.items:
        if item.id == item_id:
            return item
    return None


def load_mapping(name: str) -> list[MappingEntry]:
    """Load a framework cross-reference mapping.

    Accepts either the short framework name (e.g. 'nist-rmf', 'owasp-llm',
    'atlas', 'custody', 'lasm') or the full file stem (e.g. 'nist-rmf-crosswalk').
    """
    name = _validate_name(name)
    # Map short framework names to their on-disk file stems. Both the short
    # name and the full stem are valid bare identifiers, so this stays within
    # the allowlist; no traversal surface is introduced.
    file_stem = _MAPPING_FILES.get(name, name)
    path = _safe_path(MAPPINGS_DIR, file_stem, ".yaml")
    if not path.exists():
        raise FileNotFoundError(f"Mapping not found: {path}")
    raw = _load_yaml(path)
    entries = []
    for entry_data in raw.get("mappings", []):
        entries.append(
            MappingEntry(
                framework=entry_data.get("framework", ""),
                control_id=entry_data.get("control_id", ""),
                framework_control_name=entry_data.get("framework_control_name", ""),
                checklist_ids=entry_data.get("checklist_ids", []),
                description=entry_data.get("description", ""),
            )
        )
    return entries


def load_protocol(name: str) -> str:
    """Load a protocol document by name."""
    name = _validate_name(name)
    path = _safe_path(PROTOCOLS_DIR, name, ".md")
    if not path.exists():
        raise FileNotFoundError(f"Protocol not found: {path}")
    return path.read_text()


def search_by_threat(query: str) -> list[dict[str, Any]]:
    """Search all checklists for controls that mitigate a given threat.

    Matches against the item's ``threat``, ``control``, ``verification``,
    ``category``, and ``sources`` text (case-insensitive substring), so a
    query like ``"data poisoning"`` matches items that mention it in their
    verification steps or source references even when the threat/control
    fields use different wording.

    Args:
        query: Search term to match (1-256 chars).

    Returns:
        List of matching checklist items with their source checklist.
    """
    if not isinstance(query, str):
        raise TypeError(f"invalid query: expected string, got {type(query).__name__}")
    query = query.strip()
    if not query or len(query) > MAX_QUERY_LEN:
        raise ValueError(
            f"invalid query: must be 1-{MAX_QUERY_LEN} chars (got {len(query)})"
        )
    pattern = re.compile(re.escape(query), re.IGNORECASE)
    results = []
    for path in sorted(DATA_DIR.glob("*.yaml")):
        raw = _load_yaml_or_none(path)
        if not isinstance(raw, dict):
            continue
        for item_data in raw.get("checklist", []) or []:
            if not isinstance(item_data, dict):
                continue
            if pattern.search(_item_haystack(item_data)):
                results.append(
                    {
                        "checklist": path.stem,
                        **item_data,
                    }
                )
    return results


# Cap each field's contribution to the search haystack so a pathologically long
# field cannot dominate regex cost. 1000 chars is far above any real field.
_HAYSTACK_FIELD_CAP = 1000


def _normalize_control(text: str) -> str:
    """Normalize a control string for cross-checklist dedup comparison.

    Lowercases and collapses whitespace so the same control stated slightly
    differently in two checklists (spacing, case) still matches. Comparison is
    by control text, not by item ID — IDs differ across checklists (AC vs HE).
    """
    return " ".join(str(text).lower().split())


def diff_checklists(name_a: str, name_b: str) -> dict[str, Any]:
    """Return items present in checklist A but missing from B, and vice versa.

    An item in A is "missing from B" when no item in B has a matching
    normalized ``control`` text (lowercased, whitespace-collapsed). This is a
    text-based dedup, not an ID-based one, because item IDs differ across
    checklists (e.g. AC-003 vs HE-011). Useful for spotting coverage gaps and
    duplicated controls as the catalog grows.

    Args:
        name_a: First checklist name.
        name_b: Second checklist name.

    Returns:
        ``{"a_only": [...], "b_only": [...]}`` where each entry is the item dict
        (with its source checklist name) that has no match in the other list.
    """
    a = load_checklist(name_a)
    b = load_checklist(name_b)
    b_controls = {_normalize_control(it.control) for it in b.items if it.control}
    a_controls = {_normalize_control(it.control) for it in a.items if it.control}
    a_only = [
        {"checklist": a.name, **_item_to_dict(it)}
        for it in a.items
        if it.control and _normalize_control(it.control) not in b_controls
    ]
    b_only = [
        {"checklist": b.name, **_item_to_dict(it)}
        for it in b.items
        if it.control and _normalize_control(it.control) not in a_controls
    ]
    return {"a_only": a_only, "b_only": b_only}


def _item_to_dict(item: ChecklistItem) -> dict[str, Any]:
    """Serialize a ChecklistItem to a plain dict for JSON output."""
    return {
        "id": item.id,
        "category": item.category,
        "threat": item.threat,
        "control": item.control,
        "severity": item.severity,
        "verification": item.verification,
        "sources": item.sources,
        "custody_pillar": item.custody_pillar,
        "lasm_layer": item.lasm_layer,
    }


def _item_haystack(item_data: dict[str, Any]) -> str:
    """Build a bounded, lowercase search haystack from an item's text fields."""
    parts: list[str] = []
    for key in ("threat", "control", "verification", "category"):
        val = item_data.get(key, "")
        if isinstance(val, str):
            parts.append(val[:_HAYSTACK_FIELD_CAP])
    sources = item_data.get("sources", [])
    if isinstance(sources, list):
        parts.append(" ".join(str(s) for s in sources)[:_HAYSTACK_FIELD_CAP])
    return " ".join(parts)