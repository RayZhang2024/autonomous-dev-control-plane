"""Temporary external SQLite root-store fixture; never selects authoritative state."""

from __future__ import annotations

from contextlib import AbstractContextManager
import sqlite3
from tempfile import TemporaryDirectory
from pathlib import Path


class TemporaryRootStore(AbstractContextManager["TemporaryRootStore"]):
    """Ephemeral CAS store used only by tests; its database path is private."""

    def __init__(self) -> None:
        self._directory: TemporaryDirectory[str] | None = None
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> "TemporaryRootStore":
        self._directory = TemporaryDirectory(prefix="autodev-g9-fixture-")
        db = Path(self._directory.name) / "root-fixture.sqlite3"
        self._connection = sqlite3.connect(db, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("CREATE TABLE root_state (key TEXT PRIMARY KEY, revision INTEGER NOT NULL, value BLOB NOT NULL)")
        return self

    def create_if_absent(self, key: str, value: bytes) -> bool:
        cursor = self._conn().execute(
            "INSERT OR IGNORE INTO root_state(key, revision, value) VALUES (?, 0, ?)", (key, value)
        )
        return cursor.rowcount == 1

    def compare_and_swap(self, key: str, expected_revision: int, value: bytes) -> bool:
        cursor = self._conn().execute(
            "UPDATE root_state SET revision = revision + 1, value = ? WHERE key = ? AND revision = ?",
            (value, key, expected_revision),
        )
        return cursor.rowcount == 1

    def read(self, key: str) -> tuple[int, bytes] | None:
        row = self._conn().execute(
            "SELECT revision, value FROM root_state WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else (row[0], row[1])

    def _conn(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("fixture root store is not open")
        return self._connection

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._directory is not None:
            self._directory.cleanup()
            self._directory = None
