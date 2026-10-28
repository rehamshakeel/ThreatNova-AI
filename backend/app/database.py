"""Database setup and session management with SQLAlchemy and SQLite."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# SQLite requires check_same_thread=False for multi-threaded FastAPI workers
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG and False,  # disable verbose SQL echoing in production
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to yield a database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables."""
    # Import all models so that Base.metadata has registered tables
    import app.models.investigation  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Safe lightweight SQLite migration for added columns
    try:
        with engine.connect() as conn:
            cursor = conn.connection.cursor()
            cursor.execute("PRAGMA table_info(investigations)")
            cols = [r[1] for r in cursor.fetchall()]
            if cols and "ai_analysis" not in cols:
                cursor.execute("ALTER TABLE investigations ADD COLUMN ai_analysis TEXT DEFAULT '{}'")
                conn.connection.commit()
    except Exception:
        pass
