import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import aiosqlite
from src.config import settings
from src.models import LeakageFinding


class DatabaseManager:
    """Manages SQLite database with WAL mode for financial DLP leakage auditing."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path or settings.DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def init_sync_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS violation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    masked_value TEXT NOT NULL,
                    validation_rule TEXT NOT NULL,
                    source TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_viol_timestamp ON violation_logs(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_viol_type ON violation_logs(finding_type);")
            conn.commit()

    @asynccontextmanager
    async def get_connection(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            await conn.close()

    async def record_findings(self, findings: List[LeakageFinding], request_id: str, source: str = "INSPECT_API"):
        if not findings:
            return
        ts = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            for f in findings:
                await conn.execute("""
                    INSERT INTO violation_logs
                    (timestamp, request_id, finding_type, severity, masked_value, validation_rule, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ts,
                    request_id,
                    f.finding_type,
                    f.severity,
                    f.masked_value,
                    f.validation_rule,
                    source
                ))
            await conn.commit()

    async def get_recent_violations(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM violation_logs ORDER BY id DESC LIMIT ?", (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_total_violations_count(self) -> int:
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) as count FROM violation_logs;")
            row = await cursor.fetchone()
            return row["count"] if row else 0


db = DatabaseManager()
