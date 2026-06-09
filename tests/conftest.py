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
import horus.config.paths as _paths     # noqa: E402
_paths.STATE_DIR = _TMP_STATE

import horus.config as _config           # noqa: E402
_config.STATE_DIR = _TMP_STATE

# Re-point the DB module at the new STATE_DIR.
from horus.storage import db as _db      # noqa: E402
_db.DB_PATH = _TMP_STATE / "horus.db"

from horus.web import queries as _q      # noqa: E402
_q.DB_PATH = _TMP_STATE / "horus.db"
