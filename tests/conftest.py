"""Shared pytest fixtures.

We isolate every test from the user's real `state/horus.db` by pointing
STATE_DIR at a tempdir BEFORE the storage layer reads its module-level
DB_PATH constants. The hook runs at import time so any subsequent
`from horus.storage import db` sees the tmp path.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Set the override BEFORE any horus.* import inside tests.
_TMP_STATE = Path(tempfile.mkdtemp(prefix="horus-tests-"))
os.environ.setdefault("HORUS_STATE_DIR", str(_TMP_STATE))

# Patch the config module's STATE_DIR to the tempdir.
import horus.config.paths as _paths  # noqa: E402

_paths.STATE_DIR = _TMP_STATE

import horus.config as _config  # noqa: E402

_config.STATE_DIR = _TMP_STATE

# Re-point the DB module at the new STATE_DIR.
from horus.storage import db as _db  # noqa: E402

_db.DB_PATH = _TMP_STATE / "horus.db"


# Importing horus.web builds a module-level Flask app (for gunicorn), which
# calls _load_dotenv() and leaks the repo's real .env values (e.g.
# HORUS_WEB_PORT) into os.environ for the rest of the test session — making
# server.load_config() see them as an intentional Docker-style env override.
# Snapshot and strip anything the import adds so tests stay isolated from
# the developer's local .env.
_env_before = set(os.environ)

from horus.web import queries as _q  # noqa: E402

_q.DB_PATH = _TMP_STATE / "horus.db"

for _leaked_key in set(os.environ) - _env_before:
    os.environ.pop(_leaked_key, None)
