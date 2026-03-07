from __future__ import annotations

import re
from datetime import datetime
from pydantic import BaseModel, field_validator, model_validator 


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
    