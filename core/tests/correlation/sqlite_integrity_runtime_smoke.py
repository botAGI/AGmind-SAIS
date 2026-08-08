from __future__ import annotations

import sqlite3


def main() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            """
            CREATE TABLE runtime_integrity_probe (
                evidence_event_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                PRIMARY KEY(candidate_id, evidence_event_id)
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            "INSERT INTO runtime_integrity_probe VALUES (?, ?)",
            ("evidence", "candidate"),
        )
        results = {
            pragma: connection.execute(f"PRAGMA {pragma}").fetchall()
            for pragma in ("quick_check", "integrity_check")
        }
        if any(result != [("ok",)] for result in results.values()):
            raise AssertionError(
                f"SQLite {sqlite3.sqlite_version} integrity results: {results!r}"
            )
    finally:
        connection.close()


if __name__ == "__main__":
    main()
