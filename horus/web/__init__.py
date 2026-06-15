"""Horus web UI — Flask app factory + module-level `app` for WSGI servers.

Production: `gunicorn horus.web:app`.
Local dev:  `python -m horus.web --port 8080`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask

from . import csrf as _csrf
from .queries import DB_PATH
from .routes import ALL_BLUEPRINTS


def create_app() -> Flask:
    """Build a Flask app. Templates + static dir live alongside this package."""
    import secrets

    here = Path(__file__).parent
    app = Flask(
        __name__,
        template_folder=str(here / "templates"),
        static_folder=str(here / "static"),
        static_url_path="/static",
    )
    secret_key = os.environ.get("HORUS_SECRET_KEY")
    if not secret_key:
        # Persist a generated key so sessions survive restarts
        key_file = Path.home() / ".horus" / "secret_key"
        if key_file.exists():
            secret_key = key_file.read_text().strip()
        else:
            import warnings

            warnings.warn(
                "HORUS_SECRET_KEY not set — generating a persistent key at "
                f"{key_file}. Set HORUS_SECRET_KEY in production.",
                stacklevel=2,
            )
            secret_key = secrets.token_hex(32)
            key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            key_file.write_text(secret_key)
            key_file.chmod(0o600)
    app.secret_key = secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        TELEGRAM_BOT_USERNAME=os.environ.get("TELEGRAM_BOT_USERNAME", ""),
    )
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)
    _csrf.init_app(app)
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
