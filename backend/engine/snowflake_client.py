"""
Snowflake Connection Helper

Validates credentials, tests connectivity, fetches schemas/tables.
All Snowflake errors are caught and translated to domain-specific messages.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

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

# Function to validate the role of the user. If the role is in the blacklist, return a SnowflakeError..
def validate_role(role: str | None) -> SnowflakeError | None:
    if role and role.upper() in settings.BLACKLISTED_ROLES: # Normalizes role casing to uppercase for a robust comparison against the configuration-driven deny-list.
        return SnowflakeError(
            code=403,
            message="Security alert: Administrative roles are not allowed. Please use a Read-Only role.",
        )
    return None