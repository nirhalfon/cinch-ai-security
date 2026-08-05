"""Local static server for the Cinch assessment console.

``cinch console`` serves the single-page console (``docs-site/index.html`` plus
the generated ``data/full.json`` catalog bundle) from localhost so the dashboard
can ``fetch()`` the real 117-control catalog. Opening the HTML file directly via
``file://`` makes that fetch fail and silently drops the page onto its small
offline fallback, which is why a server is needed at all.

Deliberately narrow: bound to 127.0.0.1 by default, read-only, GET/HEAD only
(``SimpleHTTPRequestHandler`` implements nothing else), and rooted at the console
directory so nothing outside it can be reached.
"""

from __future__ import annotations

import contextlib
import functools
import http.server
import socket
import sys
import threading
import webbrowser
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _PKG_DIR.parent.parent

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


def console_dir() -> Path:
    """Return the directory holding the console page and its data bundle.

    Prefers the copy bundled into the wheel (``cinch/data/console/``); falls back
    to ``docs-site/`` in a source checkout or editable install.
    """
    bundled = _PKG_DIR / "data" / "console"
    if (bundled / "index.html").is_file():
        return bundled
    return _REPO_ROOT / "docs-site"


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Quiet, no-cache static handler rooted at the console directory.

    ``assessment_path`` (when set) is served at ``/data/assessment.json`` so a
    result pack living anywhere on disk can be loaded by the dashboard without
    copying it into the package directory.
    """

    assessment_path: Path | None = None

    def do_GET(self) -> None:
        if self._serve_assessment(body=True):
            return
        super().do_GET()

    def do_HEAD(self) -> None:
        if self._serve_assessment(body=False):
            return
        super().do_HEAD()

    def _serve_assessment(self, body: bool) -> bool:
        if self.assessment_path is None or self.path.split("?")[0] != "/data/assessment.json":
            return False
        try:
            payload = self.assessment_path.read_bytes()
        except OSError:
            self.send_error(404, "assessment not readable")
            return True
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)
        return True

    def end_headers(self) -> None:
        # The catalog bundle is regenerated from source data; never let a browser
        # serve a stale assessment from cache.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        pass  # request-by-request noise is not useful here


def serve_console(
    port: int = DEFAULT_PORT,
    host: str = DEFAULT_HOST,
    open_browser: bool = True,
    assessment: Path | None = None,
) -> None:
    """Serve the console over HTTP until interrupted.

    ``assessment`` is an optional path to an assessment result pack; when given
    it is served as ``/data/assessment.json`` and the dashboard loads it on open.

    Raises FileNotFoundError if the console assets are missing, and OSError if
    the port is already in use.
    """
    root = console_dir()
    page = root / "index.html"
    data = root / "data" / "full.json"
    if not page.is_file():
        raise FileNotFoundError(
            f"console page not found at {page}. Reinstall cinch-ai-security, or run "
            "from a repo checkout where docs-site/index.html exists."
        )
    if not data.is_file():
        raise FileNotFoundError(
            f"catalog bundle not found at {data}. Run 'python scripts/build_docs_json.py' "
            "to generate it."
        )

    if assessment is not None:
        assessment = Path(assessment)
        if not assessment.is_file():
            raise FileNotFoundError(f"assessment pack not found: {assessment}")

    handler = functools.partial(
        type("_BoundHandler", (_Handler,), {"assessment_path": assessment}),
        directory=str(root),
    )
    try:
        httpd = http.server.ThreadingHTTPServer((host, port), handler)
    except OSError as exc:
        raise OSError(
            f"cannot bind {host}:{port} ({exc}). Pass --port to pick another port."
        ) from exc

    url = f"http://{host}:{httpd.server_port}/"
    print(f"Cinch console serving {root} at {url}", file=sys.stderr)
    if assessment is not None:
        print(f"Loading assessment results from {assessment}", file=sys.stderr)
    print("Press Ctrl-C to stop.", file=sys.stderr)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    with contextlib.suppress(KeyboardInterrupt):
        httpd.serve_forever()
    httpd.server_close()
    print("Cinch console stopped.", file=sys.stderr)


def _free_port() -> int:
    """Return an OS-assigned free port (used by tests)."""
    with socket.socket() as s:
        s.bind((DEFAULT_HOST, 0))
        return s.getsockname()[1]
