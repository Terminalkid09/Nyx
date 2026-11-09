"""A fresh database built only from Alembic must contain every model table.

``authorization_profiles`` used to exist only because ``create_all`` created it
after the migrations. A real deployment that runs ``alembic upgrade head`` and
nothing else would then fail every RoE lookup.
"""
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]


def test_alembic_head_creates_authorization_profiles(tmp_path):
    db_path = tmp_path / "migration.db"
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{db_path.as_posix()}",
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    con = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in con.execute(
                "select name from sqlite_master where type='table'"
            )
        }
        assert "authorization_profiles" in tables
        columns = {
            row[1]
            for row in con.execute("pragma table_info(authorization_profiles)")
        }
        assert {
            "id", "name", "targets", "exclusions", "window_start",
            "window_end", "max_rps", "signature", "active", "created_at",
        } <= columns
    finally:
        con.close()
