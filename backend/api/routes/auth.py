"""
Auth Routes: Signup, Login, Logout, Forgot/Reset Password.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.config import settings
from backend.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from backend.db.database import get_db
from backend.models.db_models import PasswordResetToken, User
from backend.models.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
    TokenResponse,
)

# Estlablish "/api/auth" as prefix for all routes in this file
router = APIRouter(prefix="/api/auth", tags=["auth"])

# Signup route
@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def signup(req: SignupRequest, db: AsyncSession = Depends(get_db)):
    # Email normalization and validation is handled by Pydantic model validator.
    # Check if user already exists. If so, raise a conflict error.
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists. Please Log in.", # This is technically User Enumeration. Fine for now, but allows malicious actors to check if a user exists.
        )
    
    # Create new user with provided email and password. Encrypt password using bcrypt.
    user = User(
        email=req.email,
        hashed_password=hash_password(req.password), # Encrypt at point of write to ensure plain-text credentials never hit the persistence layer.
        auth_provider="email",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token({"sub": user.id}) # Mints a new JWT with the 'sub' claim set to the user ID, establishing the primary identity for the session.
    return TokenResponse(access_token=token)

# Login route
@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    # Reusable exception instance for unauthorized access. Keeps code consistent and DRY and prevents information leakage
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password.",
        headers={"WWW-Authenticate": "Bearer"},
    )   
    # Email normalization and validation is handled by Pydantic model validator.
    # Check if user exists. If not, raise a unauthorized error.
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()
    if user is None or not user.hashed_password:
        raise unauthorized

    # Implements timing-safe password verification and a generic 401 to prevent attackers from discovering valid emails.
    if not verify_password(req.password, user.hashed_password):
        raise unauthorized

    token = create_access_token({"sub": user.id}) # Standardizes token issuance across login and signup to maintain a consistent authentication payload.
    return TokenResponse(access_token=token)

# Logout route
@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    # Statelessness Tradeoff: The JWT remains valid until its natural expiry.
    # Consider implementing a blacklist of revoked tokens on a fast database (i.e., Redis)to prevent reuse after logout.
    return {"detail": "Successfully logged out."} # Returns a successful logout response; note that the stateless JWT remains valid until its natural expiry.

# Forgot Password route
@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    # TODO: Implement background task (Celery, FastAPI Tasks) to send reset email asyncronously
    # Always returns the same message whether or not the email exists.
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    # If the email exists, create a reset token.
    if user:
        token_value = str(uuid.uuid4()) # Generates a cryptographically unique UUID4 to prevent reset token guessing or collisions.

        # Constructs a temporary reset credential with a strict TTL to limit the window of vulnerability.
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token_value,
            expires_at=datetime.now(timezone.utc) + timedelta(
                minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES,
            ),
        )
        db.add(reset_token)
        await db.commit()

    # Defends against email enumeration by returning a constant-time success message regardless of account existence.
    return {
        "detail": f"If an account exists for {req.email}, you will receive a password reset link shortly."
    }

# Reset Password route
@router.post("/reset-password")
async def reset_password(req: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    # Reusable exception instance for invalid token. Keeps code consistent, DRY, and prevents information leakage
    invalid_token = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="The password reset link is invalid or has expired. Please request a new one.",
    )

    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token == req.token)
    )
    reset_token = result.scalar_one_or_none()

    # Check if token is valid. If not, raise a invalid token error.
    if reset_token is None or reset_token.used:
        raise invalid_token

    # Check if token has expired. If so, raise a invalid token error.
    if reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise invalid_token

    # Check if user exists. If not, raise a invalid token error.
    user_result = await db.execute(select(User).where(User.id == reset_token.user_id))
    user = user_result.scalar_one_or_none()
    if user is None:
        raise invalid_token

    user.hashed_password = hash_password(req.password) # Hashes the new password in-place on the ORM object, ensuring it is ready for the upcoming atomic commit.
    reset_token.used = True # Invalidates the reset token immediately to prevent "replay" attacks; committed atomically with the password change.
    await db.commit()

    return {"detail": "Password successfully updated."}

# Verify Reset Token route
@router.get("/verify-reset-token")
async def verify_reset_token(token: str, db: AsyncSession = Depends(get_db)):
    # Reusable exception instance for invalid token. Keeps code consistent, DRY, and prevents information leakage
    invalid_token = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="The password reset link is invalid or has expired. Please request a new one.",
    )

    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token == token)
    )
    reset_token = result.scalar_one_or_none()

    # Duplicated expiration logic from the reset flow - possible refactor candidate
    if reset_token is None or reset_token.used:
        raise invalid_token
    if reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise invalid_token

    user_result = await db.execute(select(User).where(User.id == reset_token.user_id))
    user = user_result.scalar_one_or_none()

    # Masks user existence by returning a 'valid: True' response even if the lookup returns None.
    return {"email": user.email if user else "", "valid": True}