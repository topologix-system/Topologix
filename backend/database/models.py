"""
SQLAlchemy database models for authentication and authorization
- User model with password hashing and role management
- Role model with hierarchical permissions
- Many-to-many user-role association
- Password reset tokens and login attempt tracking
- SQLAlchemy 2.0 declarative base with type hints
"""
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, Table, Column, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash


# SQLAlchemy 2.0 declarative base
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

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Required authentication fields
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Optional user information
    full_name: Mapped[Optional[str]] = mapped_column(String(100))

    # Status flags
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    force_password_change: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Security tracking
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    account_locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length

    # Timestamps - always timezone-aware
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

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        secondary=user_roles,
        back_populates="users",
        lazy="selectin"  # Avoid N+1 queries
    )

    # Indexes
    __table_args__ = (
        Index('idx_users_email_active', 'email', 'is_active'),
        Index('idx_users_created', 'created_at'),
    )

    def set_password(self, password: str) -> None:
        """Hash and set password using bcrypt via werkzeug

        Args:
            password: Plain text password to hash
        """
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = datetime.now(timezone.utc)
        self.force_password_change = False

    def check_password(self, password: str) -> bool:
        """Verify password against stored hash

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches
        """
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through their roles

        Args:
            permission_name: Permission name (e.g., "network:read")

        Returns:
            True if user has the permission
        """
        if self.is_superuser:
            return True

        return any(
            perm.name == permission_name
            for role in self.roles
            for perm in role.permissions
        )

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role

        Args:
            role_name: Role name (e.g., "admin")

        Returns:
            True if user has the role
        """
        return any(role.name == role_name for role in self.roles)

    def to_dict(self, include_roles: bool = True) -> dict:
        """Convert to dictionary for JSON serialization

        Args:
            include_roles: Whether to include user's roles

        Returns:
            Dictionary representation of user
        """
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

    # Relationships
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
        """Convert to dictionary for JSON serialization

        Args:
            include_permissions: Whether to include role's permissions

        Returns:
            Dictionary representation of role
        """
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
    """Permission model for fine-grained access control

    Permissions follow the format: resource:action
    Examples: network:read, snapshot:write, user:delete
    """
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

    # Relationships
    roles: Mapped[List["Role"]] = relationship(
        secondary=role_permissions,
        back_populates="permissions",
        lazy="selectin"
    )

    __table_args__ = (
        Index('idx_permissions_resource_action', 'resource', 'action'),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization

        Returns:
            Dictionary representation of permission
        """
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
    """Login attempt tracking for IP-based rate limiting

    Tracks all login attempts (successful and failed) by IP address
    for rate limiting and security monitoring.
    """
    __tablename__ = 'login_attempts'

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # IP address (IPv4 or IPv6)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)

    # Username attempted (may be None for non-existent users)
    username: Mapped[Optional[str]] = mapped_column(String(50), index=True)

    # Timestamp of attempt
    attempt_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )

    # Whether login was successful
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # User agent string for forensics
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))

    # Indexes for efficient queries
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

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Foreign key to user
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    # Secure random token (should be hashed in production, but using plain for simplicity)
    token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Expiration timestamp
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Usage tracking
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # Security tracking
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 max length

    # Creation timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationship to user
    user: Mapped["User"] = relationship("User", lazy="joined")

    # Indexes for efficient queries
    __table_args__ = (
        Index('idx_password_reset_token', 'token'),
        Index('idx_password_reset_user_created', 'user_id', 'created_at'),
        Index('idx_password_reset_expires', 'expires_at'),
    )

    def is_valid(self) -> bool:
        """Check if token is still valid (not used and not expired)

        Returns:
            True if token can be used for password reset
        """
        now = datetime.now(timezone.utc)

        # Handle timezone-naive datetimes from database
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return self.used_at is None and expires_at > now

    def mark_used(self) -> None:
        """Mark token as used"""
        self.used_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})>"
