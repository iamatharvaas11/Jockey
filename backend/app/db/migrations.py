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

logger = logging.getLogger("jocky.db.migrations")


async def init_database(engine: AsyncEngine):
    """
    Initialize all database tables and migration tracking tables.
    Works transparently on SQLite and PostgreSQL.
    """
    async with engine.begin() as conn:
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

