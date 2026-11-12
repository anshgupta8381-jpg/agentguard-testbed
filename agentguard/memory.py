"""Per-user long-term memory, stored in SQLite.

The agent saves facts with the save_memory tool, and saved facts are shown to the
model at the start of every later session. That is what makes memory poisoning
(attack A9) possible: one bad save keeps affecting future sessions.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path


class MemoryStore:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                fact TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'agent',
                created_at REAL NOT NULL)""")

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def save(self, user: str, fact: str, source: str = "agent") -> int:
        with self._conn() as c:
            cur = c.execute("INSERT INTO memories (user, fact, source, created_at) VALUES (?, ?, ?, ?)",
                            (user, fact.strip(), source, time.time()))
            return cur.lastrowid

    def list(self, user: str) -> list[str]:
        with self._conn() as c:
            rows = c.execute("SELECT fact FROM memories WHERE user = ? ORDER BY id", (user,)).fetchall()
        return [r[0] for r in rows]

    def clear(self, user: str | None = None) -> None:
        with self._conn() as c:
            if user is None:
                c.execute("DELETE FROM memories")
            else:
                c.execute("DELETE FROM memories WHERE user = ?", (user,))
