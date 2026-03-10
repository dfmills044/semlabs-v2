"""
Snowflake Connection Helper

Validates credentials, tests connectivity, fetches schemas/tables.
All Snowflake errors are caught and translated to domain-specific messages.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
import asyncio

from backend.core.config import settings

# Use logging import to log events and errors in a centralized and organized manner.
logger = logging.getLogger(__name__)

# Custom error class reusable for various Snowflake errors.
@dataclass
class SnowflakeError:
    code: int
    message: str

# Defines a block-list of system schemas. These are the schemas that are not included in the scan results by default.
SYSTEM_SCHEMAS = frozenset({
    "INFORMATION_SCHEMA",
    "PUBLIC",
    "ACCOUNT_USAGE",
})

# Function to validate the role of the user. If the role is in the blacklist, return a SnowflakeError
def validate_role(role: str | None) -> SnowflakeError | None:
    if role and role.upper() in settings.BLACKLISTED_ROLES: # Normalizes role casing to uppercase for a robust comparison against the configuration-driven deny-list.
        return SnowflakeError(
            code=403,
            message="Security alert: Administrative roles are not allowed. Please use a Read-Only role.",
        )
    return None

# Function to test the connection to Snowflake
async def test_connection(
    account_id: str,
    username: str,
    password: str,
    database: str,
    role: str | None = None,
    warehouse: str | None = None,
) -> SnowflakeError | None:
    """
    Connect to Snowflake and run SELECT 1.
    Returns None on success, SnowflakeError on failure.
    """
    # Helper function to perform the synchronous work of testing the connection to Snowflake.
    def _sync_work() -> SnowflakeError | None:
        # Initialize conn as None to avoid any potential issues with the connection.
        conn = None
        # Try to connect to Snowflake.
        try:
            import snowflake.connector # Implements a deferred import of the Snowflake SDK to reduce module overhead in environments where connectivity isn't required.
            conn_params = {
                "account": account_id,
                "user": username,
                "password": password,
                "database": database,
                "login_timeout": 15 # Hard timeout for handshake
            }
            # Optional params for role and warehouse.
            if role:
                conn_params["role"] = role
            if warehouse:
                conn_params["warehouse"] = warehouse

            conn = snowflake.connector.connect(**conn_params) # Executes a synchronous connection to Snowflake.
            cursor = conn.cursor()
            cursor.execute("SELECT 1") # Execute a simple SELECT 1 query to test the connection works.
            cursor.close()            
            # Performs a permission check using f-string SQL; note the injection vulnerability on the database identifier and the 403 fallback.
            # Note: If Snowflake changes thier driver to be incompatible with this approach, we will need to update this.
            try:
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM {database}.INFORMATION_SCHEMA.COLUMNS LIMIT 1")
                cursor.close()
            except Exception:
                return SnowflakeError(
                    code=403,
                    message=(
                        "Setup incomplete: The connected role cannot read Query History or "
                        "Information Schema. Please ensure the provided user can read QUERY_LOG "
                        "and INFORMATION_SCHEMA and try again."
                    ),
                )
            return None
        
        # Coerces the exception message to lowercase to facilitate string-based classification of common Snowflake driver errors.
        except Exception as e:
            err_str = str(e).lower()

            # Utilizes substring matching for authentication errors; potentially brittle across different versions of the Snowflake SDK.
            if "incorrect username or password" in err_str or "authentication" in err_str:
                return SnowflakeError(code=401, message="Auth failed: Invalid username or password.")

            # Parses error strings to identify missing roles or access denials, returning a structured SnowflakeError.
            if "role" in err_str and ("not exist" in err_str or "access" in err_str):
                return SnowflakeError(
                    code=403,
                    message="Access denied: User does not have access to the specified role.",
                )

            # Detects warehouse-specific failures in the error string to distinguish infrastructure issues from authentication failures.
            if "warehouse" in err_str and ("not exist" in err_str or "usage" in err_str):
                return SnowflakeError(
                    code=403,
                    message="Access denied: Warehouse does not exist or user lacks USAGE privileges.",
                )

            # Log the error for debugging purposes.
            logger.error("Snowflake connection error: %s", e)
            return SnowflakeError(code=500, message=f"Connection failed: {str(e)}")
        
        finally:
            # Check if the connection is open and close it.
            if conn:
                conn.close()


    return await asyncio.to_thread(_sync_work)