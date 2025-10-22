"""
Database seeding for initial permissions, roles, and admin user
- seed_permissions(): Creates 17 default permissions (network, snapshot, OSPF, etc.)
- seed_roles(): Creates 3 default roles (admin, engineer, viewer)
- seed_admin_user(): Creates initial admin user with random password
- initialize_database(): Main entry point for database initialization
- Idempotent: Safe to call multiple times (only creates missing data)
- Only runs when AUTH_ENABLED=true
- Role definitions:
  * admin: Full system access, all permissions
  * engineer: Read/write network operations, no user management
  * viewer: Read-only access to all network data
"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from database.models import User, Role, Permission
from database.session import get_db
import logging
import secrets

logger = logging.getLogger(__name__)


def seed_permissions(db) -> dict[str, Permission]:
    """Create default permissions if they don't exist

    Returns:
        Dictionary mapping permission names to Permission objects
    """
    # Define all default permissions in resource:action format
    default_permissions = [
        # Network operations
        ('network:read', 'Read network topology and configuration', 'network', 'read'),
        ('network:write', 'Modify network configuration', 'network', 'write'),
        ('network:delete', 'Delete network configuration', 'network', 'delete'),

        # Snapshot operations
        ('snapshot:read', 'View network snapshots', 'snapshot', 'read'),
        ('snapshot:write', 'Create and update snapshots', 'snapshot', 'write'),
        ('snapshot:delete', 'Delete snapshots', 'snapshot', 'delete'),

        # OSPF operations (read-only)
        ('ospf:read', 'View OSPF processes and configuration', 'ospf', 'read'),

        # Edge operations (read-only)
        ('edges:read', 'View network edges (physical, layer3, OSPF)', 'edges', 'read'),

        # Configuration operations (read-only)
        ('config:read', 'View configuration structures and AAA', 'config', 'read'),

        # Validation operations (read-only)
        ('validation:read', 'View validation results and parse status', 'validation', 'read'),

        # Analysis operations
        ('analysis:read', 'View analysis results', 'analysis', 'read'),
        ('analysis:write', 'Run network analysis (reachability, route policies)', 'analysis', 'write'),

        # User management
        ('user:read', 'View user accounts', 'user', 'read'),
        ('user:write', 'Create and update user accounts', 'user', 'write'),
        ('user:delete', 'Delete user accounts', 'user', 'delete'),

        # Role management
        ('role:read', 'View roles and permissions', 'role', 'read'),
        ('role:write', 'Create and update roles', 'role', 'write'),
        ('role:delete', 'Delete roles', 'role', 'delete'),

        # Permission viewing
        ('permission:read', 'View available permissions', 'permission', 'read'),
    ]

    permissions = {}
    created_count = 0

    for name, description, resource, action in default_permissions:
        # Check if permission already exists
        stmt = select(Permission).where(Permission.name == name)
        existing = db.scalar(stmt)

        if existing:
            permissions[name] = existing
            logger.debug(f"Permission already exists: {name}")
        else:
            # Create new permission
            perm = Permission(
                name=name,
                description=description,
                resource=resource,
                action=action
            )
            db.add(perm)
            permissions[name] = perm
            created_count += 1
            logger.info(f"Created permission: {name}")

    db.flush()  # Ensure IDs are assigned
    logger.info(f"Permissions seeded: {created_count} created, {len(default_permissions) - created_count} existing")
    return permissions


def seed_roles(db, permissions: dict[str, Permission]) -> dict[str, Role]:
    """Create default roles with appropriate permissions

    Args:
        permissions: Dictionary of permission name -> Permission object

    Returns:
        Dictionary mapping role names to Role objects
    """
    # Define default roles
    default_roles = {
        'admin': {
            'description': 'Full system access - all permissions',
            'is_system': True,
            'permissions': list(permissions.keys())  # All permissions
        },
        'engineer': {
            'description': 'Network engineer - read/write network operations, no user management',
            'is_system': True,
            'permissions': [
                'network:read', 'network:write', 'network:delete',
                'snapshot:read', 'snapshot:write', 'snapshot:delete',
                'ospf:read',
                'edges:read',
                'config:read',
                'validation:read',
                'analysis:read', 'analysis:write',
            ]
        },
        'viewer': {
            'description': 'Read-only access - view all network data',
            'is_system': True,
            'permissions': [
                'network:read',
                'snapshot:read',
                'ospf:read',
                'edges:read',
                'config:read',
                'validation:read',
                'analysis:read',
            ]
        }
    }

    roles = {}
    created_count = 0

    for role_name, role_config in default_roles.items():
        # Check if role already exists
        stmt = select(Role).where(Role.name == role_name)
        existing = db.scalar(stmt)

        if existing:
            roles[role_name] = existing
            logger.debug(f"Role already exists: {role_name}")

            # Update permissions if role exists (in case we added new permissions)
            existing_perm_names = {p.name for p in existing.permissions}
            for perm_name in role_config['permissions']:
                if perm_name not in existing_perm_names and perm_name in permissions:
                    existing.permissions.append(permissions[perm_name])
                    logger.info(f"Added permission {perm_name} to existing role {role_name}")
        else:
            # Create new role
            role = Role(
                name=role_name,
                description=role_config['description'],
                is_system=role_config['is_system']
            )

            # Add permissions
            for perm_name in role_config['permissions']:
                if perm_name in permissions:
                    role.permissions.append(permissions[perm_name])

            db.add(role)
            roles[role_name] = role
            created_count += 1
            logger.info(f"Created role: {role_name} with {len(role_config['permissions'])} permissions")

    db.flush()  # Ensure IDs are assigned
    logger.info(f"Roles seeded: {created_count} created, {len(default_roles) - created_count} existing")
    return roles


def seed_admin_user(
    db,
    roles: dict[str, Role],
    admin_username: Optional[str] = None,
    admin_password: Optional[str] = None,
    admin_email: Optional[str] = None
) -> Optional[User]:
    """Create default admin user if it doesn't exist

    Args:
        roles: Dictionary of role name -> Role object
        admin_username: Username for admin (from config)
        admin_password: Password for admin (from config)
        admin_email: Email for admin (from config)

    Returns:
        Admin User object if created, None if already exists
    """
    # Use defaults if not provided
    admin_username = admin_username or 'admin'
    admin_email = admin_email or 'admin@topologix.local'

    # Check if admin user already exists
    stmt = select(User).where(User.username == admin_username)
    existing = db.scalar(stmt)

    if existing:
        logger.info(f"Admin user '{admin_username}' already exists (ID: {existing.id})")
        return None

    # Generate random password if not provided
    if not admin_password:
        admin_password = secrets.token_urlsafe(16)
        logger.warning(
            f"No admin password provided - generated random password: {admin_password}\n"
            f"IMPORTANT: Save this password! It will not be shown again."
        )

    # Create admin user
    admin_user = User(
        username=admin_username,
        email=admin_email,
        full_name='System Administrator',
        is_active=True,
        is_superuser=True,  # Superuser bypasses all permission checks
        email_verified=True  # Auto-verify admin email
    )
    admin_user.set_password(admin_password)

    # Add admin role
    if 'admin' in roles:
        admin_user.roles.append(roles['admin'])

    db.add(admin_user)
    db.flush()

    logger.info(
        f"Created admin user: {admin_username} (ID: {admin_user.id})\n"
        f"Email: {admin_email}\n"
        f"Is Superuser: True"
    )

    return admin_user


def initialize_database(
    admin_username: Optional[str] = None,
    admin_password: Optional[str] = None,
    admin_email: Optional[str] = None
) -> dict:
    """Initialize database with default permissions, roles, and admin user

    This function is idempotent - safe to call multiple times.
    Only creates data that doesn't already exist.

    Args:
        admin_username: Username for default admin (from config)
        admin_password: Password for default admin (from config)
        admin_email: Email for default admin (from config)

    Returns:
        Dictionary with seeding statistics
    """
    from flask import current_app

    # Only run if AUTH_ENABLED=true
    if not current_app.config.get('AUTH_ENABLED', False):
        logger.warning("Database initialization skipped (AUTH_ENABLED=false)")
        return {
            'status': 'skipped',
            'reason': 'AUTH_ENABLED=false'
        }

    logger.info("Starting database initialization...")

    try:
        with next(get_db()) as db:
            # Seed permissions
            permissions = seed_permissions(db)

            # Seed roles
            roles = seed_roles(db, permissions)

            # Seed admin user
            admin_user = seed_admin_user(
                db,
                roles,
                admin_username=admin_username,
                admin_password=admin_password,
                admin_email=admin_email
            )

            # Commit all changes
            db.commit()

            result = {
                'status': 'success',
                'permissions_count': len(permissions),
                'roles_count': len(roles),
                'admin_created': admin_user is not None,
                'admin_username': admin_username if admin_user else None
            }

            logger.info(f"Database initialization completed: {result}")
            return result

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
