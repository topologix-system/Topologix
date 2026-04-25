"""Security package exports with lazy auth-related imports."""
from .validation import (
    sanitize_input,
    validate_path,
    validate_file_upload,
    validate_snapshot_name,
    validate_node_name,
    validate_json_input
)

_LAZY_EXPORTS = {
    'JWTManager': ('.auth', 'JWTManager'),
    'require_auth': ('.auth', 'require_auth'),
    'require_role': ('.auth', 'require_role'),
    'CSRFProtect': ('.csrf', 'CSRFProtect'),
    'SecurityHeaders': ('.headers', 'SecurityHeaders'),
    'RateLimiter': ('.rate_limit', 'RateLimiter'),
}


def __getattr__(name):
    """Load auth/security helpers only when callers request them."""
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module 'security' has no attribute '{name}'")

    module_name, attr_name = _LAZY_EXPORTS[name]
    from importlib import import_module

    value = getattr(import_module(module_name, __name__), attr_name)
    globals()[name] = value
    return value

__all__ = [
    'JWTManager',
    'require_auth',
    'require_role',
    'sanitize_input',
    'validate_path',
    'validate_file_upload',
    'validate_snapshot_name',
    'validate_node_name',
    'validate_json_input',
    'CSRFProtect',
    'SecurityHeaders',
    'RateLimiter'
]
