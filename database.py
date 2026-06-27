from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

db_url = os.getenv("DATABASE_URL", "").strip().strip('"').strip("'")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if not db_url:
    raise ValueError("DATABASE_URL environment variable is not set")

engine = create_engine(
    db_url,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,
    pool_pre_ping=True
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
#copyright KBCA All rights reserved 2026-2027
