"""Minimal .env loader.

Deliberately not python-dotenv: this runs in the viewer environment where each
dependency is something a person has to approve, and the job is thirty lines.

Values already present in the real environment are never overwritten. That
ordering matters - it means an operator can override a single setting for one
run without editing the file, and a scheduled job's explicit configuration
cannot be silently replaced by a stale .env someone left in the directory.
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_NAME = ".env"


def load(path: str | os.PathLike | None = None, *, override: bool = False) -> list[str]:
    """Load KEY=VALUE pairs into os.environ. Returns the names that were set.

    A missing file is not an error: the environment may be configured by other
    means (systemd, a container, an export in the shell).
    """
    target = Path(path) if path else Path.cwd() / DEFAULT_NAME
    if not target.is_file():
        return []

    applied = []
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue

        value = value.strip()
        # Strip one layer of matching quotes, so a password containing '#' or
        # spaces can be written as PGPASSWORD="a b#c".
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]

        if not override and key in os.environ:
            continue
        if not value:
            # An empty assignment is an unfilled template line, not an
            # instruction to blank out a value that is already set.
            continue

        os.environ[key] = value
        applied.append(key)

    return applied
