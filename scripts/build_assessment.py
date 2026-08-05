#!/usr/bin/env python3
"""Generate ``docs-site/data/assessment.json`` — the assessment the console opens on.

The dashboard loads real results rather than a hardcoded demo: this runs the same
engine ``cinch assess`` uses over ``examples/assessment-state.json`` and writes the
pack next to the page. Deterministic (fixed ``generated`` stamp) so CI can verify
the committed file is in sync.

Usage:
    python scripts/build_assessment.py [state.json] [-o out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

DEFAULT_STATE = REPO / "examples" / "assessment-state.json"
DEFAULT_OUT = REPO / "docs-site" / "data" / "assessment.json"
# Fixed stamp: the pack is a committed artifact, so it must not change on every run.
GENERATED = "example-assessment"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("state", nargs="?", type=Path, default=DEFAULT_STATE)
    ap.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    from cinch.assess import build_assessment, read_state  # after sys.path is set

    status, evidence, deployment = read_state(args.state)
    pack = build_assessment(status, evidence, deployment=deployment, generated=GENERATED)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(pack, indent=2) + "\n")
    s = pack["summary"]
    print(
        f"Wrote {args.out.relative_to(REPO)} — grade {s['grade']} ({s['label']}), "
        f"score {s['score']}%, {s['gaps']} gaps, {len(pack['recommendations'])} recommendations."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
