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
    # Reusable exception instance for unauthorized access.
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
