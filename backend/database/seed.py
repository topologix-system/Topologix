"""Database seeding for initial permissions, roles, and admin user"""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from database.models import User, Role, Permission
from database.session import get_db
import logging
import secrets

logger = logging.getLogger(__name__)


def seed_permissions(db) -> dict[str, Permission]:
    """Create default permissions if they don't exist"""
    default_permissions = [
        ('network:read', 'Read network topology and configuration', 'network', 'read'),
        ('network:write', 'Modify network configuration', 'network', 'write'),
        ('network:delete', 'Delete network configuration', 'network', 'delete'),

        ('snapshot:read', 'View network snapshots', 'snapshot', 'read'),
        ('snapshot:write', 'Create and update snapshots', 'snapshot', 'write'),
        ('snapshot:delete', 'Delete snapshots', 'snapshot', 'delete'),

        ('ospf:read', 'View OSPF processes and configuration', 'ospf', 'read'),

        ('edges:read', 'View network edges (physical, layer3, OSPF)', 'edges', 'read'),

        ('config:read', 'View configuration structures and AAA', 'config', 'read'),

        ('validation:read', 'View validation results and parse status', 'validation', 'read'),

        ('analysis:read', 'View analysis results', 'analysis', 'read'),
        ('analysis:write', 'Run network analysis (reachability, route policies)', 'analysis', 'write'),

        ('user:read', 'View user accounts', 'user', 'read'),
        ('user:write', 'Create and update user accounts', 'user', 'write'),
        ('user:delete', 'Delete user accounts', 'user', 'delete'),

        ('role:read', 'View roles and permissions', 'role', 'read'),
        ('role:write', 'Create and update roles', 'role', 'write'),
        ('role:delete', 'Delete roles', 'role', 'delete'),

        ('permission:read', 'View available permissions', 'permission', 'read'),
    ]

    permissions = {}
    created_count = 0

    for name, description, resource, action in default_permissions:
        stmt = select(Permission).where(Permission.name == name)
        existing = db.scalar(stmt)

        if existing:
            permissions[name] = existing
            logger.debug(f"Permission already exists: {name}")
        else:
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

    db.flush()
    logger.info(f"Permissions seeded: {created_count} created, {len(default_permissions) - created_count} existing")
    return permissions


def seed_roles(db, permissions: dict[str, Permission]) -> dict[str, Role]:
    """Create default roles with appropriate permissions"""
    default_roles = {
        'admin': {
            'description': 'Full system access - all permissions',
            'is_system': True,
            'permissions': list(permissions.keys())
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
        stmt = select(Role).where(Role.name == role_name)
        existing = db.scalar(stmt)

        if existing:
            roles[role_name] = existing
            logger.debug(f"Role already exists: {role_name}")

            existing_perm_names = {p.name for p in existing.permissions}
            for perm_name in role_config['permissions']:
                if perm_name not in existing_perm_names and perm_name in permissions:
                    existing.permissions.append(permissions[perm_name])
                    logger.info(f"Added permission {perm_name} to existing role {role_name}")
        else:
            role = Role(
                name=role_name,
                description=role_config['description'],
                is_system=role_config['is_system']
            )

            for perm_name in role_config['permissions']:
                if perm_name in permissions:
                    role.permissions.append(permissions[perm_name])

            db.add(role)
            roles[role_name] = role
            created_count += 1
            logger.info(f"Created role: {role_name} with {len(role_config['permissions'])} permissions")

    db.flush()
    logger.info(f"Roles seeded: {created_count} created, {len(default_roles) - created_count} existing")
    return roles


def seed_admin_user(
    db,
    roles: dict[str, Role],
    admin_username: Optional[str] = None,
    admin_password: Optional[str] = None,
    admin_email: Optional[str] = None
) -> Optional[User]:
    """Create default admin user if it doesn't exist"""
    admin_username = admin_username or 'admin'
    admin_email = admin_email or 'admin@topologix.local'

    stmt = select(User).where(User.username == admin_username)
    existing = db.scalar(stmt)

    if existing:
        logger.info(f"Admin user '{admin_username}' already exists (ID: {existing.id})")
        return None

    if not admin_password:
        admin_password = secrets.token_urlsafe(16)
        logger.warning("No admin password provided - generated random password (printed to stdout)")
        print(f"\n{'=' * 60}")
        print(f"  GENERATED ADMIN PASSWORD (save securely):")
        print(f"  {admin_password}")
        print(f"{'=' * 60}\n", flush=True)

    admin_user = User(
        username=admin_username,
        email=admin_email,
        full_name='System Administrator',
        is_active=True,
        is_superuser=True,  # Superuser bypasses all permission checks
        email_verified=True
    )
    admin_user.set_password(admin_password)

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
    """Initialize database with default permissions, roles, and admin user"""
    from flask import current_app

    if not current_app.config.get('AUTH_ENABLED', False):
        logger.warning("Database initialization skipped (AUTH_ENABLED=false)")
        return {
            'status': 'skipped',
            'reason': 'AUTH_ENABLED=false'
        }

    logger.info("Starting database initialization...")

    try:
        with next(get_db()) as db:
            permissions = seed_permissions(db)

            roles = seed_roles(db, permissions)

            admin_user = seed_admin_user(
                db,
                roles,
                admin_username=admin_username,
                admin_password=admin_password,
                admin_email=admin_email
            )

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
