from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List

# Non-negotiable blacklisted Snowflake roles
MANDATORY_ROLES = {"SYSADMIN", "ACCOUNTADMIN"}

class Settings(BaseSettings):
    APP_NAME: str = "SemLabs"

    # Needs to default to TRUE so that DEBUG actions are taken by default, unless overridden by the environment variable.
    DEBUG: bool = True

    # Must set the driver to aiosqlite so API async requests to the database don't stop the server.
    DATABASE_URL: str = "sqlite+aiosqlite:///./semlabs_v2.db"

    # Placeholder value with warning to use secrets manager in prod.
    # In production, should be str with no default value to force a secrets manager injected key from system env vars rather than have forgeable key. Fine this way right now in dev.
    # Also might want to add a field validator to ensure the secret key is at least 32 characters long.
    SECRET_KEY: str = "use-secrets-manager-in-prod"

    # Should change this to RS256 if tokens need to be verified by a 3rd party service. HS256 is fine for current architecture.
    ALGORITHM: str = "HS256"

    # Set to 1 week for dev purposes. Better to be short-lived (15 minutes to one hour) once in production.
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    SNOWFLAKE_QUERY_LIMIT: int = 100_000
    SNOWFLAKE_QUERY_DAYS: int = 30
    SCAN_STEP_TIMEOUT_MINUTES: int = 15

    # Rather define this here than in snowflake client. Allows default to be extended without a deploy if new Snowflake role types are added.
    BLACKLISTED_ROLES: list[str] = ["SYSADMIN", "ACCOUNTADMIN"]

    PASSWORD_RESET_EXPIRE_MINUTES: int = 60

    # Add a FREE_TIER_SCAN_LIMIT before going to production. This will be a limit of one (one free scan on the free plan)
    FREE_TIER_TABLE_LIMIT: int = 50 # Still needed as it will be enforced in later files right now

    GEMINI_API_KEY: str = ""

    # Ensure 'SYSADMIN' and 'ACCOUNTADMIN' are ALWAYS present in the 'BLACKLISTED_ROLES' list, regardless of the environment input.
    @field_validator("BLACKLISTED_ROLES", mode="after")
    @classmethod
    def ensure_blacklisted_roles(cls, v: List[str]) -> List[str]:
        return list(set(v) | MANDATORY_ROLES)

    class Config:
        env_file = ".env"
        extra = "ignore"

# Keeping this simple for now. Create a get_settings() function later for FastAPI dependency injection, but this makes testing harder.
settings = Settings()