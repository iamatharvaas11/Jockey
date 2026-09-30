"""
JOCKY Database Migration and Schema Provisioning Utility
Handles schema initialization, version tracking, and schema migrations
for both SQLite (local development) and PostgreSQL (production).
"""
from datetime import datetime, timezone
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.db.base import Base
from app.models.security_scan import SecurityScan

logger = logging.getLogger("jocky.db.migrations")


async def init_database(engine: AsyncEngine):
    """
    Initialize all database tables and migration tracking tables.
    Works transparently on SQLite and PostgreSQL.
    """
    async with engine.begin() as conn:
        if conn.dialect.name == "sqlite":
            await conn.execute(text("PRAGMA journal_mode=WAL;"))
            await conn.execute(text("PRAGMA busy_timeout=30000;"))

        # Create core tables
        await conn.run_sync(Base.metadata.create_all)

        # Create schema_migrations tracking table if it doesn't exist
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(64) PRIMARY KEY,
                applied_at VARCHAR(64) NOT NULL,
                description VARCHAR(255) NOT NULL
            )
        """))

        # Check and record initial migration
        result = await conn.execute(text("SELECT version FROM schema_migrations WHERE version = '001_initial_schema'"))
        if not result.fetchone():
            now_iso = datetime.now(timezone.utc).isoformat()
            await conn.execute(text("""
                INSERT INTO schema_migrations (version, applied_at, description)
                VALUES ('001_initial_schema', :applied_at, 'Core tables: users, investigations, endpoints, artifacts, evidence, relationships, reports, audit_logs')
            """), {"applied_at": now_iso})
            logger.info("Database schema initialized and migration 001_initial_schema recorded.")

        # Check and record migration 002: evidence_hash_nullable
        res_002 = await conn.execute(text("SELECT version FROM schema_migrations WHERE version = '002_evidence_hash_nullable'"))
        if not res_002.fetchone():
            dialect = conn.dialect.name
            if dialect == "sqlite":
                try:
                    table_info = await conn.execute(text("PRAGMA table_info(evidence)"))
                    cols = table_info.fetchall()
                    hash_notnull = any(c[1] == "hash" and c[3] == 1 for c in cols)
                    if hash_notnull:
                        await conn.execute(text("PRAGMA foreign_keys=off;"))
                        await conn.execute(text("""
                            CREATE TABLE IF NOT EXISTS evidence_migration_tmp (
                                id VARCHAR PRIMARY KEY,
                                investigation_id VARCHAR REFERENCES investigations(id),
                                host VARCHAR NOT NULL,
                                timestamp VARCHAR NOT NULL,
                                type VARCHAR NOT NULL,
                                source VARCHAR,
                                collector VARCHAR,
                                status VARCHAR,
                                data_json JSON,
                                hash VARCHAR(64),
                                limitations_json JSON,
                                errors_json JSON,
                                created_at DATETIME
                            );
                        """))
                        await conn.execute(text("""
                            INSERT INTO evidence_migration_tmp
                            SELECT id, investigation_id, host, timestamp, type, source, collector, status, data_json, hash, limitations_json, errors_json, created_at
                            FROM evidence;
                        """))
                        await conn.execute(text("DROP TABLE evidence;"))
                        await conn.execute(text("ALTER TABLE evidence_migration_tmp RENAME TO evidence;"))
                        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_host ON evidence (host);"))
                        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_timestamp ON evidence (timestamp);"))
                        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_type ON evidence (type);"))
                        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_evidence_investigation_id ON evidence (investigation_id);"))
                        await conn.execute(text("PRAGMA foreign_keys=on;"))
                except Exception as e:
                    logger.warning(f"SQLite migration 002 notice: {e}")
            elif dialect == "postgresql":
                try:
                    await conn.execute(text("ALTER TABLE evidence ALTER COLUMN hash DROP NOT NULL;"))
                except Exception as e:
                    logger.warning(f"PostgreSQL migration 002 notice: {e}")

            now_iso = datetime.now(timezone.utc).isoformat()
            await conn.execute(text("""
                INSERT INTO schema_migrations (version, applied_at, description)
                VALUES ('002_evidence_hash_nullable', :applied_at, 'Allow evidence.hash to be nullable for locked/uncomputable files')
            """), {"applied_at": now_iso})
            logger.info("Database migration 002_evidence_hash_nullable recorded.")

