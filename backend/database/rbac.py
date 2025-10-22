"""
Role-Based Access Control (RBAC) implementation
- Flask decorators for permission and role-based access control
- @require_permission() decorator for fine-grained endpoint protection
- @require_role() decorator for role-level endpoint protection
- Helper functions: check_user_permission(), get_user_permissions()
- Integrates with database User, Role, and Permission models
- Supports superuser bypass (is_superuser=True)
- Only enforced when AUTH_ENABLED=true
- Comprehensive logging for access control decisions
"""
from functools import wraps
from typing import Optional
from flask import request, jsonify, current_app
from sqlalchemy import select
from database.models import User
from database.session import get_db
import logging

logger = logging.getLogger(__name__)


def require_permission(permission_name: str):
    """Decorator to require specific permission for endpoint access

    Checks user's permissions through their roles in the database.
    Only enforced when AUTH_ENABLED=true.

    Args:
        permission_name: Permission name in format "resource:action"
                        (e.g., "network:read", "snapshot:write")

    Example:
        @app.route('/api/snapshots', methods=['POST'])
        @require_permission('snapshot:write')
        def create_snapshot():
            return jsonify({'status': 'created'})

    Returns:
        Decorated function that checks permissions before execution
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip permission check if auth is disabled
            if not current_app.config.get('AUTH_ENABLED', False):
                logger.debug(f"Permission check skipped (AUTH_ENABLED=false): {permission_name}")
                return f(*args, **kwargs)

            # Get user from JWT payload (set by JWTManager)
            if not hasattr(request, 'jwt_payload'):
                logger.warning(f"Permission denied: No JWT payload found for {permission_name}")
                return jsonify({'error': 'Authentication required', 'status': 'error'}), 401

            user_id = request.jwt_payload.get('user_id')
            if not user_id:
                logger.warning(f"Permission denied: No user_id in JWT payload for {permission_name}")
                return jsonify({'error': 'Invalid authentication token', 'status': 'error'}), 401

            # Check permission in database
            try:
                with next(get_db()) as db:
                    user = db.get(User, user_id)

                    if not user:
                        logger.warning(f"Permission denied: User {user_id} not found for {permission_name}")
                        return jsonify({'error': 'User not found', 'status': 'error'}), 401

                    if not user.is_active:
                        logger.warning(f"Permission denied: User {user.username} is inactive for {permission_name}")
                        return jsonify({'error': 'User account is inactive', 'status': 'error'}), 401

                    # Superusers have all permissions
                    if user.is_superuser:
                        logger.debug(f"Permission granted (superuser): {user.username} -> {permission_name}")
                        return f(*args, **kwargs)

                    # Check specific permission
                    if not user.has_permission(permission_name):
                        logger.warning(
                            f"Permission denied: {user.username} lacks '{permission_name}' "
                            f"(roles: {[r.name for r in user.roles]})"
                        )
                        return jsonify({
                            'error': f'Permission denied: {permission_name} required',
                            'status': 'error'
                        }), 403

                    logger.debug(f"Permission granted: {user.username} -> {permission_name}")
                    return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Error checking permission {permission_name}: {e}")
                return jsonify({
                    'error': 'Internal server error during permission check',
                    'status': 'error'
                }), 500

        return decorated_function
    return decorator


def check_user_permission(user_id: int, permission_name: str) -> bool:
    """Check if user has a specific permission

    Helper function for programmatic permission checking.

    Args:
        user_id: User ID to check
        permission_name: Permission name (e.g., "network:read")

    Returns:
        True if user has the permission, False otherwise

    Example:
        if check_user_permission(user_id, 'snapshot:delete'):
            # User can delete snapshots
            pass
    """
    try:
        with next(get_db()) as db:
            user = db.get(User, user_id)
            if not user or not user.is_active:
                return False

            return user.has_permission(permission_name)

    except Exception as e:
        logger.error(f"Error checking user {user_id} permission {permission_name}: {e}")
        return False


def get_user_permissions(user_id: int) -> list[str]:
    """Get all permissions for a user

    Args:
        user_id: User ID

    Returns:
        List of permission names (e.g., ["network:read", "snapshot:write"])

    Example:
        permissions = get_user_permissions(1)
        # ['network:read', 'network:write', 'snapshot:read']
    """
    try:
        with next(get_db()) as db:
            user = db.get(User, user_id)
            if not user or not user.is_active:
                return []

            # Superusers have all permissions
            if user.is_superuser:
                return ['*:*']  # Wildcard for all permissions

            # Collect unique permissions from all roles
            permissions = set()
            for role in user.roles:
                for perm in role.permissions:
                    permissions.add(perm.name)

            return sorted(list(permissions))

    except Exception as e:
        logger.error(f"Error getting user {user_id} permissions: {e}")
        return []


def require_role(role_name: str):
    """Decorator to require specific role for endpoint access

    Simpler than require_permission when role-level access is sufficient.

    Args:
        role_name: Role name (e.g., "admin", "engineer")

    Example:
        @app.route('/api/admin/users', methods=['GET'])
        @require_role('admin')
        def list_users():
            return jsonify({'users': []})

    Returns:
        Decorated function that checks role before execution
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip role check if auth is disabled
            if not current_app.config.get('AUTH_ENABLED', False):
                logger.debug(f"Role check skipped (AUTH_ENABLED=false): {role_name}")
                return f(*args, **kwargs)

            # Get user from JWT payload
            if not hasattr(request, 'jwt_payload'):
                logger.warning(f"Role denied: No JWT payload found for {role_name}")
                return jsonify({'error': 'Authentication required', 'status': 'error'}), 401

            user_id = request.jwt_payload.get('user_id')
            if not user_id:
                logger.warning(f"Role denied: No user_id in JWT payload for {role_name}")
                return jsonify({'error': 'Invalid authentication token', 'status': 'error'}), 401

            # Check role in database
            try:
                with next(get_db()) as db:
                    user = db.get(User, user_id)

                    if not user:
                        logger.warning(f"Role denied: User {user_id} not found for {role_name}")
                        return jsonify({'error': 'User not found', 'status': 'error'}), 401

                    if not user.is_active:
                        logger.warning(f"Role denied: User {user.username} is inactive for {role_name}")
                        return jsonify({'error': 'User account is inactive', 'status': 'error'}), 401

                    # Superusers have all roles
                    if user.is_superuser:
                        logger.debug(f"Role granted (superuser): {user.username} -> {role_name}")
                        return f(*args, **kwargs)

                    # Check specific role
                    if not user.has_role(role_name):
                        logger.warning(
                            f"Role denied: {user.username} lacks '{role_name}' "
                            f"(roles: {[r.name for r in user.roles]})"
                        )
                        return jsonify({
                            'error': f'Role denied: {role_name} required',
                            'status': 'error'
                        }), 403

                    logger.debug(f"Role granted: {user.username} -> {role_name}")
                    return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Error checking role {role_name}: {e}")
                return jsonify({
                    'error': 'Internal server error during role check',
                    'status': 'error'
                }), 500

        return decorated_function
    return decorator
