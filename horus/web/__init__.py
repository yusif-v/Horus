"""Horus web UI — Flask app factory + module-level `app` for WSGI servers.

Production: `gunicorn horus.web:app`.
Local dev:  `python -m horus.web --port 8080`.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request

from . import csrf as _csrf
from .queries import DB_PATH
from .routes import ALL_BLUEPRINTS


def _load_dotenv() -> None:
    """Populate os.environ from a local `.env` file (stdlib, no dependency).

    Looks for `.env` in the current working directory, then the repo root.
    Existing environment variables always win, so explicit exports override
    the file. Lines are `KEY=VALUE`; blanks and `#` comments are ignored.
    Used to supply secrets like TELEGRAM_BOT_USERNAME / TELEGRAM_BOT_TOKEN
    without exporting them on every launch.
    """
    candidates = [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        break


def create_app() -> Flask:
    """Build a Flask app. Templates + static dir live alongside this package."""
    import secrets

    _load_dotenv()
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
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    )

    @app.errorhandler(413)
    def _request_entity_too_large(error):
        if request.path.startswith("/api"):
            return jsonify({"error": "Request too large. Maximum size is 1MB."}), 413
        from ._render import error_page

        return error_page("Request too large. Maximum size is 1MB."), 413

    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)
    _csrf.init_app(app)

    # Security headers on every response
    @app.after_request
    def _set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self' https://cdn.jsdelivr.net;",
        )
        if request.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

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
