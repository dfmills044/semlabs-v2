from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from backend.core.config import settings

# Set up the async engine with database URL and DEBUG logging values from settings in config.py. DEBUG will be set to False in production.
# Default values for pool_size, max_overflow, pool_timeout are fine for the MVP. Should be tuned in production.
engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)

# Have to keep expire_on_commit=False to prevent async object detachment errors.
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        # Base.metadata.create_all() works for now, but does not allow table schema modifications. Not possible to have in production. Must change to alembic before prod.
        await conn.run_sync(Base.metadata.create_all)