"""SQLAlchemy database models for authentication, authorization and snapshot versioning"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy import (
    BigInteger, String, Integer, Boolean, DateTime, ForeignKey, Table, Column, Index, Text, UniqueConstraint
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash


class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


# Many-to-many association table: User <-> Role
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('assigned_at', DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Index('idx_user_roles_user', 'user_id'),
    Index('idx_user_roles_role', 'role_id')
)


# Many-to-many association table: Role <-> Permission
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    Column('granted_at', DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Index('idx_role_perms_role', 'role_id'),
    Index('idx_role_perms_perm', 'permission_id')
)


class User(Base):
    """User model with authentication and authorization"""
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    full_name: Mapped[Optional[str]] = mapped_column(String(100))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    force_password_change: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    account_locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # Token cutoffs keep microseconds on MySQL, whose plain DATETIME stores whole seconds
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True).with_variant(mysql.DATETIME(fsp=6), "mysql")
    )
    # Tokens issued before this time are rejected (set when the user is deactivated)
    tokens_invalid_before: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True).with_variant(mysql.DATETIME(fsp=6), "mysql")
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    roles: Mapped[List["Role"]] = relationship(
        secondary=user_roles,
        back_populates="users",
        lazy="selectin"
    )

    # Indexes; SQLite AUTOINCREMENT keeps ids of deleted users from being reassigned
    __table_args__ = (
        Index('idx_users_email_active', 'email', 'is_active'),
        Index('idx_users_created', 'created_at'),
        {'sqlite_autoincrement': True},
    )

    def set_password(self, password: str) -> None:
        """Hash and set password via werkzeug"""
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.now(timezone.utc)
        self.force_password_change = False

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through their roles"""
        if self.is_superuser:
            return True

        return any(
            perm.name == permission_name
            for role in self.roles
            for perm in role.permissions
        )

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return any(role.name == role_name for role in self.roles)

    def to_dict(self, include_roles: bool = True) -> dict:
        """Convert to dictionary for JSON serialization"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'is_active': self.is_active,
            'is_superuser': self.is_superuser,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat(),
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None
        }
        if include_roles:
            data['roles'] = [role.name for role in self.roles]
        return data

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Role(Base):
    """Role model for RBAC"""
    __tablename__ = 'roles'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255))

    # System roles cannot be deleted
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    users: Mapped[List["User"]] = relationship(
        secondary=user_roles,
        back_populates="roles",
        lazy="selectin"
    )
    permissions: Mapped[List["Permission"]] = relationship(
        secondary=role_permissions,
        back_populates="roles",
        lazy="selectin"
    )

    def to_dict(self, include_permissions: bool = True) -> dict:
        """Convert to dictionary for JSON serialization"""
        data = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_system': self.is_system,
            'created_at': self.created_at.isoformat()
        }
        if include_permissions:
            data['permissions'] = [perm.name for perm in self.permissions]
        return data

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, name='{self.name}')>"


class Permission(Base):
    """Permission model for fine-grained access control"""
    __tablename__ = 'permissions'

    id: Mapped[int] = mapped_column(primary_key=True)

    # Permission name in format "resource:action"
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255))

    # Resource and action for structured queries
    resource: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    roles: Mapped[List["Role"]] = relationship(
        secondary=role_permissions,
        back_populates="permissions",
        lazy="selectin"
    )

    __table_args__ = (
        Index('idx_permissions_resource_action', 'resource', 'action'),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'resource': self.resource,
            'action': self.action,
            'created_at': self.created_at.isoformat()
        }

    def __repr__(self) -> str:
        return f"<Permission(id={self.id}, name='{self.name}')>"


class LoginAttempt(Base):
    """Login attempt record"""
    __tablename__ = 'login_attempts'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # IP address (IPv4 or IPv6)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)

    # Username attempted
    username: Mapped[Optional[str]] = mapped_column(String(50), index=True)

    attempt_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # User agent string for forensics
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))

    __table_args__ = (
        Index('idx_login_attempts_ip_time', 'ip_address', 'attempt_time'),
        Index('idx_login_attempts_ip_success', 'ip_address', 'success'),
        Index('idx_login_attempts_username_time', 'username', 'attempt_time'),
    )

    def __repr__(self) -> str:
        return f"<LoginAttempt(id={self.id}, ip={self.ip_address}, username={self.username}, success={self.success})>"


class PasswordResetToken(Base):
    """Password reset token model for secure password reset flow

    Tokens are single-use and expire after a configurable time period.
    """
    __tablename__ = 'password_reset_tokens'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    # SHA-256 hash of the token (plaintext never stored)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    user: Mapped["User"] = relationship("User", lazy="joined")

    __table_args__ = (
        Index('idx_password_reset_token_hash', 'token_hash'),
        Index('idx_password_reset_user_created', 'user_id', 'created_at'),
        Index('idx_password_reset_expires', 'expires_at'),
    )

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @classmethod
    def create_for_user(cls, user_id: int, expiry_seconds: int = 3600):
        token = secrets.token_urlsafe(32)
        return cls(
            user_id=user_id,
            token_hash=cls.hash_token(token),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expiry_seconds)
        ), token

    def is_valid(self) -> bool:
        """Check if token is still valid (not used and not expired)"""
        now = datetime.now(timezone.utc)

        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return self.used_at is None and expires_at > now

    def mark_used(self) -> None:
        """Mark token as used"""
        self.used_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"


class RevokedToken(Base):
    """Revoked JWT tokens for persistent blacklist across restarts and workers"""
    __tablename__ = 'revoked_tokens'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index('idx_revoked_tokens_jti', 'jti'),
        Index('idx_revoked_tokens_expires', 'expires_at'),
    )

    @classmethod
    def cleanup_expired(cls, db) -> int:
        """Remove expired revoked tokens from the database"""
        from sqlalchemy import delete
        now = datetime.now(timezone.utc)
        stmt = delete(cls).where(cls.expires_at < now)
        result = db.execute(stmt)
        db.commit()
        return result.rowcount

    def __repr__(self) -> str:
        return f"<RevokedToken(jti={self.jti}, expires_at={self.expires_at})>"


class HistoryMeta(Base):
    """Database identity that scopes the snapshot history object store"""
    __tablename__ = 'history_meta'

    id: Mapped[int] = mapped_column(primary_key=True)
    db_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    clear_counter: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class HistoryObject(Base):
    """Content-addressed object stored in the snapshot history object store"""
    __tablename__ = 'history_objects'

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class SnapshotVersion(Base):
    """One committed or automatic version of a snapshot's consumable file set"""
    __tablename__ = 'snapshot_versions'

    version_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    namespace: Mapped[str] = mapped_column(String(64), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    parent_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey('snapshot_versions.version_id', ondelete='SET NULL')
    )
    parent_seq: Mapped[Optional[int]] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(String(500), nullable=False)
    author_user_id: Mapped[Optional[int]] = mapped_column(Integer)
    author_username: Mapped[Optional[str]] = mapped_column(String(50))
    restored_from_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey('snapshot_versions.version_id', ondelete='SET NULL')
    )
    restored_from_seq: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    file_count: Mapped[int] = mapped_column(Integer, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (
        UniqueConstraint('namespace', 'snapshot_id', 'seq', name='uq_snapshot_versions_namespace_snapshot_seq'),
        Index('idx_snapshot_versions_snapshot', 'namespace', 'snapshot_id'),
    )


class SnapshotVersionFile(Base):
    """Manifest entry of a snapshot version"""
    __tablename__ = 'snapshot_version_files'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    version_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey('snapshot_versions.version_id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(
        String(64),
        ForeignKey('history_objects.sha256', ondelete='RESTRICT'),
        nullable=False,
        index=True
    )
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)


class SnapshotState(Base):
    """Working-tree state of one snapshot within one deployment namespace"""
    __tablename__ = 'snapshot_states'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    namespace: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    snapshot_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stat_fingerprint: Mapped[Optional[str]] = mapped_column(String(64))
    content_hash: Mapped[Optional[str]] = mapped_column(String(64))
    head_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey('snapshot_versions.version_id', ondelete='SET NULL')
    )
    next_seq: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    restored_from_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey('snapshot_versions.version_id', ondelete='SET NULL')
    )
    restored_from_seq: Mapped[Optional[int]] = mapped_column(Integer)
    pending_external: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    missing_since: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    clear_seq: Mapped[Optional[int]] = mapped_column(Integer)
    evaluated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        UniqueConstraint('namespace', 'snapshot_id', name='uq_snapshot_states_namespace_snapshot'),
    )


class HistoryNamespace(Base):
    """Deployment namespace that used this database for snapshot history"""
    __tablename__ = 'history_namespaces'

    namespace: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
