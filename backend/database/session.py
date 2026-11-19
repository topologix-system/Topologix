"""SQLAlchemy database session management and connection pooling"""
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Centralized database connection and session management"""

    def __init__(self, database_url: str, echo: bool = False, poolclass=None):
        """Initialize database manager"""
        self.database_url = database_url
        self.engine = self._create_engine(database_url, echo, poolclass)
        self.SessionLocal = sessionmaker(
            bind=self.engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False  # Prevent DetachedInstanceError after commit
        )
        logger.info(f"DatabaseManager initialized with {database_url.split(':')[0]} database")

    def _create_engine(self, database_url: str, echo: bool, poolclass=None) -> Engine:
        """Create SQLAlchemy engine with database-specific configuration"""
        engine_kwargs = {
            'echo': echo,
            'future': True,  # Use SQLAlchemy 2.0 style
            'pool_pre_ping': True,
        }

        if database_url.startswith('sqlite'):
            engine_kwargs.update({
                'connect_args': {
                    'check_same_thread': False,  # Allow multi-threading
                    'timeout': 30,  # 30 second timeout
                },
                'poolclass': pool.StaticPool,  # Single connection for SQLite
            })
            logger.info("Using SQLite database configuration")

        elif database_url.startswith('postgresql'):
            engine_kwargs.update({
                'pool_size': 10,
                'max_overflow': 20,
                'pool_timeout': 30,
                'pool_recycle': 3600,
            })
            logger.info("Using PostgreSQL database configuration")

        elif database_url.startswith('mysql'):
            engine_kwargs.update({
                'pool_size': 10,
                'max_overflow': 20,
                'pool_timeout': 30,
                'pool_recycle': 3600,
            })
            logger.info("Using MySQL database configuration")

        if poolclass is not None:
            for pool_option in ('pool_size', 'max_overflow', 'pool_timeout', 'pool_recycle'):
                engine_kwargs.pop(pool_option, None)
            engine_kwargs['poolclass'] = poolclass

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

    def create_null_pool_manager(self) -> 'DatabaseManager':
        """Return a manager for the same database with a NullPool engine and the same connect pragmas"""
        return DatabaseManager(self.database_url, echo=self.engine.echo, poolclass=pool.NullPool)

    @contextmanager
    def get_db_session(self) -> Generator[Session, None, None]:
        """Context manager for database sessions"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
            logger.debug("Database session committed successfully")
        except Exception as e:
            session.rollback()
            logger.error("Database error, rolling back: %s", type(e).__name__)
            raise
        finally:
            session.close()
            logger.debug("Database session closed")

    def create_all(self):
        """Create all tables defined in Base.metadata"""
        from database.models import Base, User
        Base.metadata.create_all(self.engine)
        if self.database_url.startswith('sqlite'):
            self._rebuild_sqlite_table_with_autoincrement(User.__table__)
        self._add_missing_nullable_columns(User.__table__)
        logger.info("Database tables created")

    def _add_missing_nullable_columns(self, table) -> None:
        """Add the model's nullable columns that an existing table lacks"""
        from sqlalchemy import inspect

        dialect = self.engine.dialect
        existing_columns = {column['name']: column for column in inspect(self.engine).get_columns(table.name)}
        missing_columns = [
            column for column in table.columns
            if column.name not in existing_columns and column.nullable
            and column.default is None and column.server_default is None
        ]
        whole_second_columns = [
            column for column in table.columns
            if dialect.name == 'mysql' and column.name in existing_columns and column.nullable
            and getattr(column.type.dialect_impl(dialect), 'fsp', None)
            and not getattr(existing_columns[column.name]['type'], 'fsp', None)
        ]
        if not missing_columns and not whole_second_columns:
            return

        preparer = dialect.identifier_preparer
        with self.engine.begin() as connection:
            for column in missing_columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE {preparer.format_table(table)} ADD COLUMN "
                    f"{preparer.format_column(column)} {column.type.compile(dialect=dialect)}"
                )
                logger.info(f"Added column {table.name}.{column.name}")
            for column in whole_second_columns:
                column_type = column.type.compile(dialect=dialect)
                connection.exec_driver_sql(
                    f"ALTER TABLE {preparer.format_table(table)} MODIFY "
                    f"{preparer.format_column(column)} {column_type} NULL"
                )
                logger.info(f"Changed column {table.name}.{column.name} to {column_type}")

    def _rebuild_sqlite_table_with_autoincrement(self, table) -> None:
        """Rebuild an existing SQLite table that was created without AUTOINCREMENT

        Runs in one transaction with foreign key enforcement off, so rows keep their ids and
        ON DELETE CASCADE does not remove rows that reference the table.
        """
        from sqlalchemy.schema import CreateIndex, CreateTable

        def needs_rebuild(connection) -> bool:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table.name,)
            ).fetchone()
            return row is not None and 'AUTOINCREMENT' not in row[0].upper()

        rebuild_name = f"{table.name}__autoincrement_rebuild"
        pooled_connection = self.engine.raw_connection()
        try:
            connection = pooled_connection.driver_connection
            if not needs_rebuild(connection):
                return

            previous_isolation_level = connection.isolation_level
            connection.isolation_level = None
            connection.execute("PRAGMA foreign_keys=OFF")
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    if needs_rebuild(connection):
                        existing_columns = {
                            row[1] for row in connection.execute(f'PRAGMA table_info("{table.name}")')
                        }
                        columns = ", ".join(
                            f'"{column.name}"' for column in table.columns if column.name in existing_columns
                        )
                        violations_before = len(connection.execute("PRAGMA foreign_key_check").fetchall())

                        create_sql = str(CreateTable(table).compile(dialect=self.engine.dialect))
                        connection.execute(create_sql.replace(
                            f"CREATE TABLE {table.name} (", f'CREATE TABLE "{rebuild_name}" (', 1
                        ))
                        connection.execute(
                            f'INSERT INTO "{rebuild_name}" ({columns}) SELECT {columns} FROM "{table.name}"'
                        )
                        connection.execute(f'DROP TABLE "{table.name}"')
                        connection.execute(f'ALTER TABLE "{rebuild_name}" RENAME TO "{table.name}"')
                        for index in table.indexes:
                            connection.execute(str(CreateIndex(index).compile(dialect=self.engine.dialect)))

                        if len(connection.execute("PRAGMA foreign_key_check").fetchall()) > violations_before:
                            raise RuntimeError(
                                f"Rebuilding table {table.name} with AUTOINCREMENT would break foreign keys"
                            )
                        logger.info(f"Rebuilt SQLite table {table.name} with AUTOINCREMENT")
                    connection.execute("COMMIT")
                except Exception:
                    connection.execute("ROLLBACK")
                    raise
            finally:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.isolation_level = previous_isolation_level
        finally:
            pooled_connection.close()

    def drop_all(self):
        """Drop all tables"""
        from database.models import Base
        Base.metadata.drop_all(self.engine)
        logger.warning("All database tables dropped")

    def check_connection(self) -> bool:
        """Check if database connection is working"""
        try:
            with self.engine.connect() as conn:
                from sqlalchemy import text
                conn.execute(text("SELECT 1"))
            logger.info("Database connection check successful")
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False


def init_db(app):
    """Initialize database with Flask app"""
    from config import config

    db_manager = DatabaseManager(
        database_url=config.SQLALCHEMY_DATABASE_URI,
        echo=config.SQLALCHEMY_ECHO
    )

    app.db_manager = db_manager

    logger.info("Database initialized with Flask app")
    return db_manager


def get_db() -> Generator[Session, None, None]:
    """Dependency injection function for Flask routes"""
    from flask import current_app

    if not hasattr(current_app, 'db_manager'):
        raise RuntimeError(
            "Database not initialized. "
            "Ensure init_db() was called and succeeded."
        )

    with current_app.db_manager.get_db_session() as session:
        yield session
