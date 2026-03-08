from __future__ import annotations

import re
from datetime import datetime
from pydantic import BaseModel, field_validator, model_validator, ConfigDict, SecretStr, Field


# -- Constants ---
# TODO: Move to a global backend/core/constants.py file for sync with db_models.py and Frontend.
MAX_PROJECT_NAME_LENGTH = 50

# --- Helper Functions ---
# Centralize validation logic to avoid repetitive and redundant code.

# Email validation logic
def clean_and_validate_email(email: str) -> str:
    """Normalizes email and checks format using regex"""
    email = email.strip().lower()

    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

    if not re.match(email_regex, email):
        raise ValueError("Please enter a valid email address.")

    return email

# Password validation logic
def validate_password_strength(password: str) -> str:
    """Consolidated password rules: length, case, digit, special character"""
    error_message = "Password must be at least 8 characters and contain an uppercase letter, a lowercase letter, a number, and a special character."

    if len(password) < 8:
        raise ValueError(error_message)

    checks = [
        re.search(r"[A-Z]", password),       # Uppercase letter
        re.search(r"[a-z]", password),       # Lowercase letter
        re.search(r"\d", password),          # Number
        re.search(r"[^A-Za-z0-9]", password) # Special character
    ]

    if not all(checks):
        raise ValueError(error_message)

    return password

# --- Auth Validation Schemas ---

# Signup request schema
class SignupRequest(BaseModel):
    email: str
    password: str
    confirm_password: str

    # Validate email using helper function.
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return clean_and_validate_email(v)

    # Validate password using helper function.
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)

    # Validate that the passwords match.
    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self
    
# Login request schema
class LoginRequest(BaseModel):
    email: str
    password: str

    # Validate email using helper function. Keeps login flow consistent with signup flow.
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return clean_and_validate_email(v)

# Token response schema
# Will fully implement OAuth2.0 scopes/flows when integrating with external auth providers.
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Forgot password request schema
class ForgotPasswordRequest(BaseModel):
    email: str

    # Validate email using helper function. Keeps forgot password flow consistent with signup and login flows.
    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return clean_and_validate_email(v)

# Reset password request schema
class ResetPasswordRequest(BaseModel):
    token: str
    password: str
    confirm_password: str

    # Validate password using helper function. Keeps password rules consistent with signup and login flows.
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)

    # Validate that the passwords match.
    @model_validator(mode="after")
    def passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self

# --- Project Schemas ---

# Project create request schema
class ProjectCreateRequest(BaseModel):
    name: str

    # Validate project name. Check for empty name, length, and SQL injection risks.
    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()

        # Check if project name is empty
        if not v:
            raise ValueError("Project name is required.")

        # Check if project name is too long. Use MAX_PROJECT_NAME_LENGTH to prevent sync risks.
        if len(v) > MAX_PROJECT_NAME_LENGTH:
            raise ValueError(f"Project name must be {MAX_PROJECT_NAME_LENGTH} characters or less.")

        # Address SQL injection risks by only allowing alphanumeric, spaces, hyphens, underscores
        if not re.match(r"^[a-zA-Z0-9\s\-_]+$", v):
            raise ValueError("Project name must only contain alphanumeric characters, spaces, hyphens, and underscores.")

# Project response schema
class ProjectResponse(BaseModel):
    id: str
    name: str
    created_at: datetime

    # Allow Pydantic to read from SQLAlchemy ORM objects.
    model_config = ConfigDict(from_attributes=True)

# --- Connection Schemas ---

# Connect Snowflake request schema
class ConnectSnowflakeRequest(BaseModel):
    # Automatically strip whitespace from strings in this model.
    model_config = ConfigDict(str_strip_whitespace=True)
    
    database_name: str
    account_id: str
    username: str

    # Use SecretStr to redact password from logs/repr. Need to use request.password.get_secret_value() to get actual password value later.
    password: SecretStr
    role: str | None = None
    warehouse: str | None = None

    # Validator for checking if stripped connection strings are not just empty spaces.
    @field_validator("database_name", "account_id", "username")
    @classmethod
    def check_empty_strings(cls, v: str) -> str:
        if not v:
            raise ValueError("Connection string cannot be empty.")
        return v

# Update connection request schema
class UpdateConnectionRequest(BaseModel):
    # Automatically strip whitespace from strings in this model.
    model_config = ConfigDict(str_strip_whitespace=True)

    account_id: str
    username: str

    # Use SecretStr to redact password from logs/repr. Also explicitly document that None means keep existing password.
    # Need to account for None sentinel logic in the connections.py API route logic later.
    password: SecretStr | None = Field(
        default=None,
        description="The new password. If null or omitted, the existing password remains unchanged."
    )

    role: str | None = None
    warehouse: str | None = None

# Connection response schema
class ConnectionResponse(BaseModel):
    # Do not send password back in response. The frontend/user should never see it again after it is set.    
    id: str
    database_name: str
    account_id: str
    username: str
    role: str | None
    warehouse: str | None
    created_at: datetime

    # Allow Pydantic to read from SQLAlchemy ORM objects.
    model_config = ConfigDict(from_attributes=True)

# --- Scan Schemas ---

# Scan table scope schema
class ScanTableScope(BaseModel):
    # Automatically strip whitespace from strings in this model.
    model_config = ConfigDict(str_strip_whitespace=True)

    schema_name: str
    table_name: str

# Scan options schema
class ScanOptions(BaseModel):
    # No options currently supported. Keep for future expansion.
    pass

# Scan config request schema
class ScanConfigRequest(BaseModel):
    # Automatically strip whitespace from strings in this model.
    model_config = ConfigDict(str_strip_whitespace=True)
    
    connection_id: str
    scope: dict[str, list[str]] # { "schema": [ "table1", "table2" ] }
    options: ScanOptions = ScanOptions()
    tables: list[ScanTableScope] | None = None # Legacy support for backward compatibility.

    @model_validator(mode="after")
    def reconcile_scope(self) -> ScanConfigRequest:
        # Non-empty validation for scope
        if not self.scope and not self.tables:
            raise ValueError("Scope cannot be empty.")

        # Reconcile legacy tables into scope if needed
        if self.tables and not self.scope:
            new_scope = {}
            for item in self.tables:
                if item.schema_name not in new_scope:
                    new_scope[item.schema_name] = []
                new_scope[item.schema_name].append(item.table_name)
            self.scope = new_scope

        # Check for empty strings in scope keys/values
        for schema, tables in self.scope.items():
            if not schema.strip():
                raise ValueError("Schema names in scope cannot be empty.")
            if not tables:
                raise ValueError(f"Table list for schema '{schema}' cannot be empty.")
            for table in tables:
                if not table.strip():
                    raise ValueError(f"Table name cannot be empty for schema '{schema}'.")
        return self

# Scan start response schema
class ScanStartResponse(BaseModel):
    scan_id: str
    status: str = "QUEUED"

# Scan stats schema to be used in ScanStatusResponse to avoid loose typing.
class ScanStats(BaseModel):
    # Strict mapping of all nine total_* denomalized counters from Scan ORM model.
    # Base Discovery Stats
    schemas: int = Field(0, alias="total_schemas_scanned")
    tables: int = Field(0, alias="total_tables_scanned")
    columns: int = Field(0, alias="total_columns_indexed")

    # Logic and Relationship Stats
    queries: int = Field(0, alias="total_queries_parsed")
    relationships: int = Field(0, alias="total_relationships")

    # Contextual Processing Stats
    contextualized: int = Field(0, alias="total_columns_contexted")
    disambiguated: int = Field(0, alias="total_columns_disambiguated")

    # Final Concept Stats
    concepts_clustered: int = Field(0, alias="total_concepts_clustered")
    concepts_finalized: int = Field(0, alias="total_concepts_finalized")

    # Allow population by alias and from_attributes for ORM compatibility
    model_config = ConfigDict(populate_by_name=True, from_attributes=True)

# Scan status response schema
class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    current_step: int
    current_step_name: str
    progress_pct: float
    log_messages: list[str]
    error_message: str | None = None
    error_trace: str | None = None

    # Strict mapping of stats to ScanStats schema to avoid loose typing
    stats: ScanStats | None = None

    model_config = ConfigDict(from_attributes=True)

# Scan Concept Schema for strictly typing concepts
class ScanConcept(BaseModel):
    name: str
    description: str | None = None
    confidence: float
    member_count: int

# Scan summary response schema
class ScanSummaryResponse(BaseModel):
    scan_id: str
    total_concepts: int
    high_confidence_count: int
    low_confidence_count: int
    mapped_tables: int
    unmapped_tables: int
    mapped_fields: int
    total_fields: int

    # Normalize this to a predictable dict format
    scope_config: dict[str, list[str]] | None = None

    # Use a strictly typed list of ScanConcept objects
    concepts: list[ScanConcept]
    unmapped: list[dict]
    execution_time_seconds: float | None = None
    narrow_scope_warning: bool = False

    model_config = ConfigDict(from_attributes=True)