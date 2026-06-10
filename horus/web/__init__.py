"""Horus web UI — Flask app factory + module-level `app` for WSGI servers.

Production: `gunicorn horus.web:app`.
Local dev:  `python -m horus.web --port 8080`.
"""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask

from .queries import DB_PATH
from .routes import ALL_BLUEPRINTS


def create_app() -> Flask:
    """Build a Flask app. Templates + static dir live alongside this package."""
    here = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(here / "templates"),
        static_folder=str(here / "static"),
        static_url_path="/static",
    )
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)
    return app


# Module-level WSGI app for gunicorn / uvicorn / mod_wsgi.
app = create_app()


def main() -> None:
    """`python -m horus.web` — dev server only. Use gunicorn in production."""
    import argparse

    p = argparse.ArgumentParser(description="Horus web interface (dev server)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    if not DB_PATH.exists():
        print(f"[ERROR] Database not found at {DB_PATH}", file=sys.stderr)
        print("Run 'python3 -m horus' first to populate the database.", file=sys.stderr)
        sys.exit(1)

    print(
        f"Horus web starting at http://{args.host}:{args.port} (dev server — use gunicorn for prod)"
    )
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
