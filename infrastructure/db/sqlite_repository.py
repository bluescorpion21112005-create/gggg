"""SQLite implementation of the Repository interface (async-safe with WAL mode)."""
import asyncio
from datetime import datetime
import json
import logging
import sqlite3
from uuid import UUID

from injector import inject

from core.exceptions import RepositoryError
from domain.entities import AnalysisResult, Severity
from domain.interfaces.repository import Repository

logger = logging.getLogger(__name__)


class SQLiteRepository(Repository):
    @inject
    def __init__(self, db_path: str = "cybrix.db"):
        # Strip SQLAlchemy-style URL prefix if present
        if db_path.startswith("sqlite:///"):
            db_path = db_path[len("sqlite:///"):]
        self._db_path = db_path
        self._init_db_sync()

    def _init_db_sync(self):
        """Initialize database tables and enable WAL mode once at startup."""
        conn = sqlite3.connect(self._db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    created_at TEXT,
                    metadata TEXT
                )
            """)
            conn.commit()
            logger.info("SQLiteRepository initialised: %s (WAL mode)", self._db_path)
        except sqlite3.Error as exc:
            raise RepositoryError(f"Database initialisation failed: {exc}") from exc
        finally:
            conn.close()

    async def _execute(self, func, *args, **kwargs):
        """Run a synchronous function in a thread pool to avoid blocking."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args, **kwargs)

    async def save_analysis(self, result: AnalysisResult) -> None:
        def _save():
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    "INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        str(result.id),
                        result.title,
                        result.description,
                        result.severity.value,
                        result.created_at.isoformat(),
                        json.dumps(result.metadata or {}, ensure_ascii=True),
                    )
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise RepositoryError(f"Failed to save analysis: {exc}") from exc
            finally:
                conn.close()
        await self._execute(_save)

    async def get_analysis(self, analysis_id: UUID) -> AnalysisResult | None:
        def _get():
            conn = sqlite3.connect(self._db_path)
            try:
                cursor = conn.execute("SELECT * FROM analyses WHERE id=?", (str(analysis_id),))
                row = cursor.fetchone()
                if not row:
                    return None
                return AnalysisResult(
                    id=UUID(row[0]),
                    title=row[1],
                    description=row[2],
                    severity=Severity(row[3]) if row[3] else Severity.INFO,
                    created_at=datetime.fromisoformat(row[4]),
                    metadata=json.loads(row[5]) if row[5] else {}
                )
            except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise RepositoryError(f"Failed to fetch analysis {analysis_id}: {exc}") from exc
            finally:
                conn.close()
        return await self._execute(_get)

    async def list_analyses(self, limit: int = 50) -> list[AnalysisResult]:
        def _list():
            conn = sqlite3.connect(self._db_path)
            try:
                cursor = conn.execute(
                    "SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                return [
                    AnalysisResult(
                        id=UUID(row[0]),
                        title=row[1],
                        description=row[2],
                        severity=Severity(row[3]) if row[3] else Severity.INFO,
                        created_at=datetime.fromisoformat(row[4]),
                        metadata=json.loads(row[5]) if row[5] else {}
                    )
                    for row in rows
                ]
            except (sqlite3.Error, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise RepositoryError(f"Failed to list analyses: {exc}") from exc
            finally:
                conn.close()
        return await self._execute(_list)