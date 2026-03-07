import asyncio
import sys
import os

# Add the project root to the python path so we can find 'backend'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.db.database import init_db
from backend.models.db_models import Base # This import registers the models with the Metadata

async def run_init():
    print("🚀 Initializing Semantic Labs V2 Database...")
    try:
        await init_db()
        print("✅ Database tables created successfully!")
        print("📁 File: semlabs_v2.db created in the project root.")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")

if __name__ == "__main__":
    asyncio.run(run_init())