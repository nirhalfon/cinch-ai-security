"""Tests for the `cinch console` local dashboard server.

Covers asset resolution, the CLI wiring, and that a real HTTP request gets the
console page plus the catalog bundle the page fetches at runtime.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from cinch.console import _free_port, console_dir, serve_console
from cinch.server import build_parser, main

EXPECTED_CONTROLS = 117
EXPECTED_CHECKLISTS = 6


def test_console_dir_contains_page_and_bundle():
    root = console_dir()
    assert (root / "index.html").is_file()
    assert (root / "data" / "full.json").is_file()


def test_bundle_holds_the_full_catalog():
    """The console renders from this bundle, so it must carry every control."""
    bundle = json.loads((console_dir() / "data" / "full.json").read_text())
    checklists = bundle["checklists"]
    assert len(checklists) == EXPECTED_CHECKLISTS
    assert sum(len(c["items"]) for c in checklists.values()) == EXPECTED_CONTROLS


def test_parser_defaults_to_serve_and_parses_console_flags():
    parser = build_parser()
    assert parser.parse_args([]).command is None  # falls through to serve()
    assert parser.parse_args(["serve"]).command == "serve"
    args = parser.parse_args(["console", "--port", "9001", "--no-browser"])
    assert (args.command, args.port, args.no_browser) == ("console", 9001, True)


def test_console_command_reports_bind_failure(monkeypatch, capsys):
    def boom(**kwargs):
        raise OSError("port busy")

    monkeypatch.setattr("cinch.server.serve_console", boom)
    assert main(["console", "--no-browser"]) == 1
    assert "port busy" in capsys.readouterr().err


@pytest.fixture()
def running_console():
    """Serve the console on an ephemeral port for the duration of a test."""
    port = _free_port()
    thread = threading.Thread(
        target=serve_console,
        kwargs={"port": port, "open_browser": False},
        daemon=True,
    )
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):  # wait for the socket to accept
        try:
            urllib.request.urlopen(base + "/index.html", timeout=1).read()
            break
        except (urllib.error.URLError, ConnectionError):
            threading.Event().wait(0.05)
    else:
        pytest.fail("console server did not start")
    yield base


def test_serves_page_and_bundle(running_console):
    page = urllib.request.urlopen(running_console + "/", timeout=5)
    body = page.read().decode()
    assert page.status == 200
    assert "Cinch" in body and "data/full.json" in body

    data = urllib.request.urlopen(running_console + "/data/full.json", timeout=5)
    assert data.status == 200
    assert data.headers["Cache-Control"] == "no-store"
    assert len(json.loads(data.read())["checklists"]) == EXPECTED_CHECKLISTS


def test_serves_the_published_assessment_pack(running_console):
    """The dashboard fetches this on open — it is how real results reach the page."""
    pack = json.loads(
        urllib.request.urlopen(running_console + "/data/assessment.json", timeout=5).read()
    )
    assert pack["schema"] == "cinch-assessment/1"
    assert pack["summary"]["grade"]
    assert pack["recommendations"] and pack["action_plan"]


def test_assessment_override_is_served_from_any_path(tmp_path):
    """`cinch console --assessment pack.json` serves a pack living outside the site dir."""
    pack = tmp_path / "mine.json"
    pack.write_text(json.dumps({"deployment": "elsewhere", "results": []}))
    port = _free_port()
    threading.Thread(
        target=serve_console,
        kwargs={"port": port, "open_browser": False, "assessment": pack},
        daemon=True,
    ).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            body = urllib.request.urlopen(base + "/data/assessment.json", timeout=1).read()
            break
        except (urllib.error.URLError, ConnectionError):
            threading.Event().wait(0.05)
    else:
        pytest.fail("console server did not start")
    assert json.loads(body)["deployment"] == "elsewhere"


def test_missing_assessment_override_is_reported():
    with pytest.raises(FileNotFoundError, match="assessment pack not found"):
        serve_console(port=_free_port(), open_browser=False, assessment="nope.json")


@pytest.mark.parametrize(
    "path",
    ["/../pyproject.toml", "/..%2fpyproject.toml", "/data/../../pyproject.toml"],
)
def test_rejects_traversal_outside_console_root(running_console, path):
    """The static root must not be escapable — nothing outside it is served."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(running_console + path, timeout=5)
    assert exc.value.code in (400, 404)
