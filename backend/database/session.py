"""
SQLAlchemy database session management and connection pooling
- DatabaseManager: Centralized engine and session factory management
- Support for SQLite, PostgreSQL, and MySQL with database-specific configurations
- Context manager for automatic commit/rollback/close (get_db_session())
- Flask integration functions (init_db(), get_db())
- SQLite optimizations: foreign keys, WAL mode for concurrency
- Connection pooling with pre-ping for reliability
- SQLAlchemy 2.0 style with future=True
- Thread-safe session handling
"""
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Centralized database connection and session management

    Handles engine creation, session factory, and lifecycle management.
    Supports SQLite, PostgreSQL, and MySQL with appropriate configurations.
    """

    def __init__(self, database_url: str, echo: bool = False):
        """Initialize database manager

        Args:
            database_url: SQLAlchemy database URL
            echo: Whether to echo SQL statements (for debugging)
        """
        self.database_url = database_url
        self.engine = self._create_engine(database_url, echo)
        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False  # Prevent DetachedInstanceError after commit
        )
        logger.info(f"DatabaseManager initialized with {database_url.split(':')[0]} database")

    def _create_engine(self, database_url: str, echo: bool) -> Engine:
        """Create SQLAlchemy engine with database-specific configuration

        Args:
            database_url: SQLAlchemy database URL
            echo: Whether to echo SQL statements

        Returns:
            Configured SQLAlchemy engine
        """
        # Common engine settings
        engine_kwargs = {
            'echo': echo,
            'future': True,  # Use SQLAlchemy 2.0 style
            'pool_pre_ping': True,  # Verify connections before use
        }

        # Database-specific configurations
        if database_url.startswith('sqlite'):
            # SQLite specific settings
            engine_kwargs.update({
                'connect_args': {
                    'check_same_thread': False,  # Allow multi-threading
                    'timeout': 30,  # 30 second timeout
                },
                'poolclass': pool.StaticPool,  # Single connection for SQLite
            })
            logger.info("Using SQLite database configuration")

        elif database_url.startswith('postgresql'):
            # PostgreSQL specific settings
            engine_kwargs.update({
                'pool_size': 10,
                'max_overflow': 20,
                'pool_timeout': 30,
                'pool_recycle': 3600,  # Recycle connections after 1 hour
            })
            logger.info("Using PostgreSQL database configuration")

        elif database_url.startswith('mysql'):
            # MySQL specific settings
            engine_kwargs.update({
                'pool_size': 10,
                'max_overflow': 20,
                'pool_timeout': 30,
                'pool_recycle': 3600,
            })
            logger.info("Using MySQL database configuration")

        engine = create_engine(database_url, **engine_kwargs)

        # Enable SQLite foreign keys and WAL mode (required for CASCADE and better concurrency)
        if database_url.startswith('sqlite'):
            @event.listens_for(engine, "connect")
            def set_sqlite_pragma(dbapi_conn, connection_record):
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
                cursor.close()
                logger.debug("SQLite pragmas set: foreign_keys=ON, journal_mode=WAL")

        return engine

    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions

        Automatically commits on success or rolls back on exception.
        Always closes the session in the finally block.

        Yields:
            SQLAlchemy session

        Example:
            with db_manager.get_db_session() as session:
                user = session.get(User, 1)
                user.email = 'new@example.com'
                # Automatic commit
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
            logger.debug("Database session committed successfully")
        except Exception as e:
            session.rollback()
            logger.error(f"Database error, rolling back: {e}")
            raise
        finally:
            session.close()
            logger.debug("Database session closed")

    def create_all(self):
        """Create all tables defined in Base.metadata

        Should only be called when AUTH_ENABLED=true.
        In production, use Alembic migrations instead.
        """
        from database.models import Base
        Base.metadata.create_all(self.engine)
        logger.info("Database tables created")

    def drop_all(self):
        """Drop all tables (use with caution!)

        WARNING: This will delete all data in the database.
        Only use in development or testing environments.
        """
        from database.models import Base
        Base.metadata.drop_all(self.engine)
        logger.warning("All database tables dropped")

    def check_connection(self) -> bool:
        """Check if database connection is working

        Returns:
            True if connection is successful
        """
        try:
            with self.engine.connect() as conn:
                conn.execute("SELECT 1" if not self.database_url.startswith('sqlite')
                           else "SELECT 1")
            logger.info("Database connection check successful")
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False


# Flask integration functions

def init_db(app):
    """Initialize database with Flask app

    Creates DatabaseManager and stores it in app context.
    Only called when AUTH_ENABLED=true.

    Args:
        app: Flask application instance

    Returns:
        DatabaseManager instance
    """
    from config import config

    db_manager = DatabaseManager(
        database_url=config.SQLALCHEMY_DATABASE_URI,
        echo=config.DEBUG
    )

    # Store in app context
    app.db_manager = db_manager

    logger.info("Database initialized with Flask app")
    return db_manager


def get_db() -> Generator[Session, None, None]:
    """Dependency injection function for Flask routes

    Provides a database session that is automatically managed.

    Yields:
        SQLAlchemy session

    Example:
        @app.route('/api/users')
        def get_users():
            with next(get_db()) as db:
                users = db.scalars(select(User)).all()
                return jsonify([u.to_dict() for u in users])
    """
    from flask import current_app

    if not hasattr(current_app, 'db_manager'):
        raise RuntimeError(
            "Database not initialized. "
            "Ensure AUTH_ENABLED=true and init_db() was called."
        )

    with current_app.db_manager.get_db_session() as session:
        yield session
