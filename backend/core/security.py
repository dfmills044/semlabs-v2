from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from backend.core.config import settings
from backend.db.database import get_db
from backend.models.db_models import User

# "auto" passed to deprecated parameter in CryptContext flags outdated hashes for deprecation but does not automatically persist rehashed results in DB
# Need to to ensure re-hash logic is implemnted in the auth routes.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") # Use bcrypt for slow hashing to prevent brute force attacks.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login") # Verify login route is actually hosted at /api/auth/login


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    # Shallow copy - works fine for non-nested data. Need to revisit if nested data is needed (consider using deepcopy if needed)
    to_encode = data.copy() 

    # Timezone-aware expiry calculation - make sure to implement in routes that use this function
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode["exp"] = expire # Mutates only the local copy with the 'exp' claim, ensuring the original authentication data remains clean.
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM) # Generates an HS256-signed JWT using the global secret key; critical for token integrity and authenticity.


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    # Reusable exception instance for performance. Includes RFC 6750 compliant Bearer challenge headers for 401 responses.
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]) # Restrict decode to only the specified algorithm list defined in settings to prevent algorithm confusion/spoofing attacks.
        user_id: str | None = payload.get("sub") # None-safe extraction of 'sub' claim to prevent runtime KeyErrors if the token payload is malformed.
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    try:
        # Performs a DB hit on every request, effectively converting the stateless JWT into a stateful check for user existence.
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    except (SQLAlchemyError, Exception):
        # Catch DB outages to prevent masking as a 401 or surfacing as a raw 500.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service temporarily unavialable.",
            headers={"Retry-After": "30"}, # Advise client to retry after 30 seconds
        )
    

    if user is None:
        raise credentials_exception

    return user
