"""
Implementation Note: 'Vault' is a misnomer for this MVP. 
Secrets are currently stored as plaintext within the application database (specifically the 'password_hash' column of the Connection table).

TODO: Replace with a production-grade secret manager (e.g., AWS Secrets Manager, HashiCorp Vault, or GCP Secret Manager) to ensure encryption 
at rest and proper access auditing.
"""
from __future__ import annotations

from sqlalchemy import select

from backend.db.database import async_session
from backend.models.db_models import Connection


async def store_secret(connection_id: str, secret: str) -> None:
    # Spawns dedicated DB session. Mimics an external vault call, but writes to database directly.
    # Will need to revisit this if we want to use a production-grade secret manager.
    async with async_session() as db:
        result = await db.execute(
            select(Connection).where(Connection.id == connection_id)
        )
        conn = result.scalar_one_or_none()

        if not conn:
            raise ValueError(f"Connection with ID {connection_id} not found.")

        # Implementation stores plaintext despite the misleading 'hash' field name
        # MUST DO: Implement a production-grade secret manager to encrypt secrets at rest
        conn.password_hash = secret
        await db.commit()


async def get_secret(connection_id: str) -> str | None:
    # Opens a fresh, independent DB session to ensure secret retrieval occurs in a new transaction context.
    # This isolation mimics the behavior of an external secrets provider.
    async with async_session() as db:
        result = await db.execute(
            select(Connection).where(Connection.id == connection_id)
        )
        conn = result.scalar_one_or_none()
        
        # Note: Implementation returns plaintext despite the misleading 'hash' field name
        # Returns None if connection_id is invalid, letting the caller handle the missing credential
        return conn.password_hash if conn else None