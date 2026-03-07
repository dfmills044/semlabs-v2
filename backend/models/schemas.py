from __future__ import annotations

import re
from datetime import datetime
from pydantic import BaseModel, field_validator, model_validator, ConfigDict


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