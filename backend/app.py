"""
Flask application entry point with authentication
- Configurable auth via AUTH_ENABLED env var (disabled by default for OSS distribution)
- Set AUTH_ENABLED=false for development or evaluation environments
- Comprehensive network analysis REST API powered by Batfish
- CORS, compression, rate limiting, and security headers for production
- Health check, snapshot management, and 40+ Batfish query endpoints
"""
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta
import hashlib
import json
from threading import RLock

from flask import Flask, jsonify, request, make_response, session
from flask_cors import CORS
from flask_compress import Compress
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config
from services import BatfishService, SnapshotService
from security.validation import validate_path

# Configure logging early so it's available during conditional imports
logging.basicConfig(
    level=logging.INFO if not config.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Conditional imports for authentication
if config.AUTH_ENABLED:
    from flask_session import Session
    from security import (
        JWTManager, require_auth, require_role,
        sanitize_input, validate_file_upload,
        validate_snapshot_name, validate_node_name, validate_json_input,
        SecurityHeaders, RateLimiter
    )
    from security.auth import TooManyAttemptsError
    # Import CSRF protection based on mode
    if config.CSRF_MODE == 'double-submit':
        from security.csrf_double_submit import DoubleSubmitCSRFProtect as CSRFProtect
        logger.info("CSRF Mode: Double-Submit Cookie Pattern (stateless)")
    else:
        from security.csrf import CSRFProtect
        logger.info("CSRF Mode: Session-Based Synchronized Token Pattern")
    # Import database modules (only when AUTH_ENABLED=true)
    from database import init_db
    from database.seed import initialize_database
else:
    # No-op decorators when authentication is disabled
    def require_auth(f):
        return f

    def require_role(*roles):
        def decorator(f):
            return f
        return decorator

# Initialize Flask app
app = Flask(__name__)

# Apply ProxyFix middleware if behind reverse proxy (Caddy/nginx)
# This ensures request.remote_addr contains real client IP, not proxy IP
if config.BEHIND_REVERSE_PROXY:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=config.TRUSTED_PROXY_COUNT,
        x_proto=config.TRUSTED_PROXY_COUNT,
        x_host=config.TRUSTED_PROXY_COUNT,
        x_port=0,  # Don't trust X-Forwarded-Port
        x_prefix=0  # Don't trust X-Forwarded-Prefix
    )
    logger.info(f"ProxyFix middleware applied: trusting {config.TRUSTED_PROXY_COUNT} proxies")

# Configure Flask app
if config.AUTH_ENABLED:
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
    app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
    app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.JWT_ACCESS_TOKEN_EXPIRES

# Initialize CORS
# When auth is disabled, use simpler CORS configuration
if config.AUTH_ENABLED:
    CORS(app,
         origins=config.CORS_ORIGINS,
         allow_headers=config.CORS_ALLOW_HEADERS,
         expose_headers=config.CORS_EXPOSE_HEADERS,
         supports_credentials=config.CORS_SUPPORTS_CREDENTIALS,
         max_age=config.CORS_MAX_AGE)
else:
    # Simple CORS for non-auth mode
    CORS(app,
         origins=config.CORS_ORIGINS,
         allow_headers=['Content-Type', 'Cache-Control', 'Pragma'],
         supports_credentials=False)

# Enable gzip compression for responses > 500 bytes
Compress(app)
app.config['COMPRESS_ALGORITHM'] = 'gzip'
app.config['COMPRESS_LEVEL'] = 6  # Balanced compression level
app.config['COMPRESS_MIN_SIZE'] = 500

# Initialize security components (only if auth is enabled)
if config.AUTH_ENABLED:
    Session(app)
    jwt_manager = JWTManager(app, config.JWT_SECRET_KEY)
    csrf_protect = CSRFProtect(app, config.CSRF_SECRET_KEY)
    security_headers = SecurityHeaders(app)
    rate_limiter = RateLimiter(app)
    logger.info("Authentication and security features: ENABLED")

    # Initialize database (only if auth is enabled)
    try:
        # Store config in app for database access
        app.config['AUTH_ENABLED'] = config.AUTH_ENABLED
        app.config['DEBUG'] = config.DEBUG

        # Initialize database manager
        db_manager = init_db(app)
        logger.info(f"Database initialized: {config.SQLALCHEMY_DATABASE_URI.split(':')[0]}")

        # Create tables if they don't exist
        db_manager.create_all()
        logger.info("Database tables created/verified")

        # Seed database with default data
        with app.app_context():
            seed_result = initialize_database(
                admin_username=config.AUTH_DEFAULT_ADMIN_USER,
                admin_password=config.AUTH_DEFAULT_ADMIN_PASS if config.AUTH_DEFAULT_ADMIN_PASS else None,
                admin_email=f"{config.AUTH_DEFAULT_ADMIN_USER}@topologix.local"
            )
            logger.info(f"Database seeding: {seed_result}")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise RuntimeError(f"Failed to initialize database: {e}")
else:
    logger.info("Authentication and security features: DISABLED (open access)")

# ========== Global Authentication Check (only if AUTH_ENABLED) ==========
if config.AUTH_ENABLED:
    # Define routes that don't require authentication
    AUTH_EXEMPT_ROUTES = {
        '/api/health',
        '/api/auth/login',
        '/api/auth/refresh',
        '/api/auth/password-reset-request',
        '/api/auth/password-reset',
        '/api/endpoints'
    }

    @app.before_request
    def check_authentication():
        # Skip authentication for exempt routes
        if request.path in AUTH_EXEMPT_ROUTES:
            return None

        # Skip authentication for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return None

        # Special handling for POST /api/users (self-registration)
        # Allow unauthenticated POST for self-registration, but require auth for other methods (GET, PUT, DELETE)
        if request.path == '/api/users' and request.method == 'POST':
            return None

        # Extract token from Authorization header or cookie
        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header:
            if not auth_header.startswith('Bearer '):
                logger.warning(f"Invalid Authorization header format: {request.path} from {request.remote_addr}")
                return error_response("Invalid authentication format", 401)
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('access_token')

        if not token:
            logger.warning(f"Missing authentication: {request.path} from {request.remote_addr}")
            return error_response("Authentication required", 401)

        # Validate JWT token
        try:
            payload = jwt_manager.decode_token(token)

            # Check if token is access token (not refresh token)
            if payload.get('type') != 'access':
                logger.warning(f"Invalid token type: {request.path} from {request.remote_addr}")
                return error_response("Invalid token type", 401)

        except Exception as e:
            logger.warning(f"Token validation failed: {request.path} from {request.remote_addr} - {e}")
            return error_response("Invalid or expired token", 401)

        # Store user info in request context for use in route handlers
        request.user_id = payload.get('user_id')
        request.username = payload.get('username')
        request.roles = payload.get('roles', [])

        logger.debug(f"Authenticated request: {request.username} -> {request.path}")

        return None

    # Periodic cleanup for expired revoked JWT tokens (runs at most once per hour)
    _last_token_cleanup = [0.0]  # mutable container for closure
    TOKEN_CLEANUP_INTERVAL = 3600  # seconds

    @app.after_request
    def periodic_revoked_token_cleanup(response):
        now = time.time()
        if now - _last_token_cleanup[0] > TOKEN_CLEANUP_INTERVAL:
            _last_token_cleanup[0] = now
            try:
                from database.models import RevokedToken
                from database.session import get_db
                with next(get_db()) as db:
                    count = RevokedToken.cleanup_expired(db)
                    if count:
                        logger.info(f"Cleaned up {count} expired revoked tokens")
            except Exception as e:
                logger.debug(f"Token cleanup skipped: {e}")
        return response

# Initialize services
batfish_service = BatfishService()
snapshot_service = SnapshotService()
batfish_request_lock = RLock()


def _parse_gunicorn_workers(command_text: str | None) -> int | None:
    """Extract gunicorn worker count from a command string when it is explicit."""
    if not command_text:
        return None

    match = re.search(r"(?:--workers(?:=|\s+)|-w(?:\s+)?)(\d+)", command_text)
    if not match:
        return None
    return int(match.group(1))


def _get_process_command_line(pid: int) -> str | None:
    """Read a process command line on Linux containers when available."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as command_file:
            command = command_file.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
            return command or None
    except OSError:
        return None


def warn_if_multi_worker_batfish_state() -> None:
    """Warn when process-local Batfish state may be split across workers."""
    worker_values = [
        os.environ.get("WEB_CONCURRENCY"),
        os.environ.get("GUNICORN_WORKERS"),
    ]
    command_lines = [
        " ".join(sys.argv),
        _get_process_command_line(os.getpid()),
        _get_process_command_line(os.getppid()),
    ]
    worker_values.extend([
        str(_parse_gunicorn_workers(os.environ.get("GUNICORN_CMD_ARGS")) or ""),
        str(_parse_gunicorn_workers(os.environ.get("BACKEND_COMMAND")) or ""),
        *(str(_parse_gunicorn_workers(command) or "") for command in command_lines),
    ])

    for value in worker_values:
        if not value:
            continue
        try:
            if int(value) > 1:
                logger.warning(
                    "Multiple backend workers are not supported for process-local Batfish session state. "
                    "Use one backend worker or externalize snapshot/session state before scaling workers."
                )
                return
        except ValueError:
            continue


warn_if_multi_worker_batfish_state()

SNAPSHOT_QUERY_PREFIXES = (
    '/api/network/',
    '/api/ospf/',
    '/api/edges/',
    '/api/config/',
    '/api/validation/',
    '/api/analysis/',
    '/api/security/',
    '/api/bgp/',
    '/api/acl/',
    '/api/path/',
    '/api/ha/',
    '/api/protocols/',
    '/api/topology/',
    '/api/advanced/',
)


def get_batfish_request_network_name() -> str:
    """Return the Batfish network namespace for the current request."""
    if not config.AUTH_ENABLED:
        return config.BATFISH_NETWORK

    requester_user_id = getattr(request, 'user_id', None)
    if requester_user_id is None:
        return config.BATFISH_NETWORK

    return f"{config.BATFISH_NETWORK}_user_{int(requester_user_id)}"


def request_uses_batfish() -> bool:
    """Check whether the current request needs exclusive Batfish access."""
    path = request.path

    if path.startswith(SNAPSHOT_QUERY_PREFIXES):
        return True

    if path == '/api/network/initialize':
        return True

    if path == '/api/snapshots/compare':
        return True

    if path.endswith('/activate') and path.startswith('/api/snapshots/'):
        return True

    if path.startswith('/api/snapshots/') and '/files' in path and request.method in {'POST', 'PATCH', 'DELETE'}:
        return True

    if path.endswith('/interfaces') and path.startswith('/api/snapshots/'):
        return True

    if path.endswith('/layer1-topology') and path.startswith('/api/snapshots/') and request.method in {'PUT', 'DELETE'}:
        return True

    return False


@app.before_request
def prepare_batfish_request_context():
    """Serialize Batfish operations and switch to the request-specific network namespace."""
    if request.method == 'OPTIONS' or not request_uses_batfish():
        return None

    batfish_request_lock.acquire()
    request._batfish_lock_acquired = True
    batfish_service.set_network_context(get_batfish_request_network_name())
    return None


@app.after_request
def release_batfish_request_lock(response):
    """Release Batfish lock after a response is produced."""
    if getattr(request, '_batfish_lock_acquired', False):
        batfish_request_lock.release()
        request._batfish_lock_acquired = False
    return response


@app.teardown_request
def cleanup_batfish_request_lock(error):
    """Ensure Batfish lock is released on error paths."""
    if getattr(request, '_batfish_lock_acquired', False):
        batfish_request_lock.release()
        request._batfish_lock_acquired = False
    return None

if config.AUTH_ENABLED:
    @app.before_request
    def ensure_authenticated_snapshot_context():
        """Restore the active snapshot for the authenticated browser session."""
        if request.method == 'OPTIONS':
            return None

        if request.path == '/api/network/initialize':
            return None

        if not request.path.startswith(SNAPSHOT_QUERY_PREFIXES):
            return None

        active_snapshot_name = session.get('current_snapshot_name')
        if not active_snapshot_name:
            return None

        try:
            snapshot_path = snapshot_service.get_snapshot_path(
                active_snapshot_name,
                **get_snapshot_request_context(),
            )

            if batfish_service.current_snapshot_name != active_snapshot_name:
                batfish_service.initialize_network(str(snapshot_path), snapshot_name=active_snapshot_name)
                logger.info(
                    "Synchronized Batfish snapshot for user=%s snapshot=%s",
                    getattr(request, 'username', 'unknown'),
                    active_snapshot_name,
                )
        except PermissionError:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared unauthorized active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                active_snapshot_name,
            )
            return error_response("Active snapshot access denied", 403)
        except FileNotFoundError:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared missing active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                active_snapshot_name,
            )
            return error_response("Active snapshot not found", 404)

        return None


# ========== Error Handlers ==========
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500


# ========== Utility Functions ==========
def generate_etag(data: Any) -> str:
    json_str = json.dumps(data, sort_keys=True)
    return hashlib.md5(json_str.encode()).hexdigest()


def add_cache_headers(response, cache_time: int = 300, private: bool = False):
    cache_control = []
    if private:
        cache_control.append('private')
    else:
        cache_control.append('public')

    cache_control.append(f'max-age={cache_time}')
    cache_control.append('must-revalidate')

    response.headers['Cache-Control'] = ', '.join(cache_control)
    response.headers['Vary'] = 'Accept-Encoding, Authorization, Cookie' if private else 'Accept-Encoding'

    # Add expires header for older proxies
    expires = datetime.utcnow() + timedelta(seconds=cache_time)
    response.headers['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')

    return response


def success_response(data: Any, message: str = "Success", cache_time: int = 0, use_etag: bool = False, status_code: int = 200) -> tuple:
    """Create success response with optional caching

    Args:
        data: Response data
        message: Success message
        cache_time: Cache time in seconds (0 = no cache)
        use_etag: Whether to generate and check ETags
        status_code: HTTP status code (default 200)
    """
    response_data = {"status": "success", "message": message, "data": data}

    # Generate ETag if requested
    if use_etag:
        etag = generate_etag(response_data)

        # Check if client has matching ETag
        if request.headers.get('If-None-Match') == etag:
            return '', 304  # Not Modified

        response = make_response(jsonify(response_data), status_code)
        response.headers['ETag'] = etag
    else:
        response = make_response(jsonify(response_data), status_code)

    # Add cache headers if cache_time > 0
    if cache_time > 0:
        add_cache_headers(response, cache_time, private=config.AUTH_ENABLED)

    return response


def error_response(message: str, status_code: int = 400) -> tuple:
    """Create error response"""
    return jsonify({"status": "error", "message": message}), status_code


def get_snapshot_request_context() -> dict[str, Any]:
    """Build per-request snapshot authorization context."""
    return {
        'requester_user_id': getattr(request, 'user_id', None),
        'auth_enabled': config.AUTH_ENABLED,
    }


def get_snapshot_creation_context() -> dict[str, Any]:
    """Build snapshot creation context including owner metadata."""
    return {
        'owner_user_id': getattr(request, 'user_id', None),
        'owner_username': getattr(request, 'username', None),
        'auth_enabled': config.AUTH_ENABLED,
    }


def require_snapshot_access(snapshot_name: str | None) -> None:
    """Validate that the current requester can access a named snapshot."""
    if not snapshot_name:
        return
    snapshot_service.get_snapshot_path(snapshot_name, **get_snapshot_request_context())


def normalize_batfish_specifier(value: Any) -> str | None:
    """Normalize UI list or comma text into a Batfish regex-style specifier."""
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return "|".join(parts) if parts else None
    return str(value).strip() or None


def get_query_specifier(name: str) -> str | None:
    """Read a query parameter that may be encoded as name or name[]."""
    values = request.args.getlist(name) or request.args.getlist(f"{name}[]")
    if len(values) > 1:
        return normalize_batfish_specifier(values)
    if values:
        return normalize_batfish_specifier(values[0])
    return normalize_batfish_specifier(request.args.get(name))


def parse_optional_bool(value: Any, default: bool | None = None) -> bool | None:
    """Parse optional bools from JSON or query parameters."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return default


def reload_active_snapshot_after_layer1_change(name: str) -> None:
    """Reload Batfish when Layer1 changes affect the active snapshot context."""
    if config.AUTH_ENABLED:
        if session.get('current_snapshot_name') != name:
            return
    elif batfish_service.current_snapshot_name != name:
        return

    snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    batfish_service.initialize_network(str(snapshot_path), snapshot_name=name)
    logger.info("Reloaded Batfish snapshot after Layer1 change: snapshot=%s", name)


# ========== User Management Validation Functions ==========
def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against security policy

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"

    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters"

    if config.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if config.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if config.REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if config.REQUIRE_SPECIAL_CHARS and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    import re

    if not email:
        return False, "Email is required"

    # RFC 5322 simplified email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_pattern, email):
        return False, "Invalid email format"

    if len(email) > 255:
        return False, "Email address too long"

    return True, ""


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format

    Args:
        username: Username to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    import re

    if not username:
        return False, "Username is required"

    if len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(username) > 50:
        return False, "Username must be at most 50 characters"

    # Only allow alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"

    return True, ""


# ========== Health Check ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    return success_response({
        "service": "topologix-backend",
        "status": "healthy",
        "auth_enabled": config.AUTH_ENABLED
    })


# ========== Authentication Endpoints (only if AUTH_ENABLED) ==========
if config.AUTH_ENABLED:
    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """Authenticate user and return JWT tokens"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['username', 'password']
            )

            username = sanitize_input(data['username'], max_length=50)
            password = data['password']  # Don't sanitize passwords

            try:
                user = jwt_manager.authenticate_user(username, password)
            except TooManyAttemptsError as e:
                return jsonify({"status": "error", "message": "Too many attempts",
                                "retry_after": e.retry_after}), 429
            if not user:
                logger.warning(f"Failed login attempt for {username} from {request.remote_addr}")
                return error_response("Invalid credentials", 401)

            tokens = jwt_manager.generate_tokens(
                user['id'], user['username'], user['roles']
            )

            # Generate CSRF token (mode-dependent)
            if config.CSRF_MODE == 'double-submit':
                # Generate token with user binding for double-submit pattern
                csrf_token = csrf_protect.generate_csrf_token(
                    user_id=user['id'],
                    session_id=request.headers.get('X-Session-ID')
                )
            else:
                # Session-based mode
                csrf_token = csrf_protect.generate_csrf_token()

            logger.info(f"Successful login for {username} from {request.remote_addr}")

            is_secure = config.ENV == 'production'

            response = jsonify({
                "status": "success",
                "message": "Login successful",
                "data": {
                    "token_type": "Bearer",
                    "expires_in": tokens['expires_in'],
                    "user": {
                        "username": user['username'],
                        "roles": user['roles'],
                        "email": user['email']
                    },
                    "csrf_token": csrf_token
                }
            })

            # Set CSRF cookie for double-submit pattern
            if config.CSRF_MODE == 'double-submit':
                csrf_protect.set_csrf_cookie(response, csrf_token)

            # Set tokens as HTTP-only cookies (not returned in JSON body)
            response.set_cookie(
                'access_token',
                tokens['access_token'],
                secure=is_secure,
                httponly=True,
                samesite='Lax',
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES
            )
            response.set_cookie(
                'refresh_token',
                tokens['refresh_token'],
                secure=is_secure,
                httponly=True,
                samesite='Lax',
                path='/api/auth/refresh',
                max_age=config.JWT_REFRESH_TOKEN_EXPIRES
            )

            return response, 200

        except ValueError as e:
            return error_response(str(e), 400)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return error_response("Login failed", 500)

    @app.route('/api/auth/logout', methods=['POST'])
    @require_auth
    def logout():
        """Logout user and invalidate token"""
        try:
            username = request.jwt_payload.get('username')
            logger.info(f"Logout for {username} from {request.remote_addr}")

            # Revoke the access token before clearing session
            token = jwt_manager._extract_token()
            if token:
                jwt_manager.revoke_token(token)
                logger.info(f"Token revoked for user {username}")

            session.clear()

            response = make_response(success_response({}, "Logout successful"))

            # Clear cookies
            response.set_cookie('access_token', '', expires=0)
            response.set_cookie('refresh_token', '', expires=0, path='/api/auth/refresh')

            # Clear CSRF cookie (mode-dependent)
            if config.CSRF_MODE == 'double-submit':
                csrf_protect.clear_csrf_cookie(response)
            else:
                # Session-based mode uses generic cookie clear
                response.set_cookie('csrf_token', '', expires=0)

            return response

        except Exception as e:
            logger.error(f"Logout error: {e}")
            return error_response("Logout failed", 500)

    @app.route('/api/auth/refresh', methods=['POST'])
    def refresh_token():
        """Refresh access token using refresh token from HTTP-only cookie"""
        try:
            refresh_token_str = request.cookies.get('refresh_token')
            if not refresh_token_str:
                return error_response("Refresh token required", 401)

            payload = jwt_manager.decode_token(refresh_token_str)

            if payload.get('type') != 'refresh':
                return error_response("Invalid token type", 401)

            user_id = payload.get('user_id')

            # Get user based on AUTH_ENABLED mode
            if config.AUTH_ENABLED:
                # Database mode
                from database.models import User
                from database.session import get_db

                with next(get_db()) as db:
                    user_obj = db.get(User, user_id)
                    if not user_obj or not user_obj.is_active:
                        return error_response("User not found or inactive", 401)

                    user = {
                        'id': user_obj.id,
                        'username': user_obj.username,
                        'roles': [role.name for role in user_obj.roles]
                    }
            else:
                # In-memory mode
                from security.auth import USERS_DB
                user = None
                for u in USERS_DB.values():
                    if u['id'] == user_id:
                        user = u
                        break

                if not user:
                    return error_response("User not found", 401)

            # Generate new access token
            tokens = jwt_manager.generate_tokens(
                user['id'], user['username'], user['roles']
            )

            is_secure = config.ENV == 'production'
            response = jsonify({
                "status": "success",
                "message": "Token refreshed",
                "data": {
                    "token_type": "Bearer",
                    "expires_in": tokens['expires_in']
                }
            })
            response.set_cookie(
                'access_token',
                tokens['access_token'],
                secure=is_secure,
                httponly=True,
                samesite='Lax',
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES
            )

            return response

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return error_response("Token refresh failed", 401)

    @app.route('/api/auth/csrf-token', methods=['GET'])
    @require_auth
    def get_csrf_token():
        """Get CSRF token for authenticated user"""
        if config.CSRF_MODE == 'double-submit':
            # Generate token with user binding for double-submit pattern
            csrf_token = csrf_protect.generate_csrf_token(
                user_id=request.user_id,
                session_id=request.headers.get('X-Session-ID')
            )
            # Create response and set cookie
            response = make_response(success_response({'csrf_token': csrf_token}))
            csrf_protect.set_csrf_cookie(response, csrf_token)
            return response
        else:
            # Session-based mode (no cookie needed)
            csrf_token = csrf_protect.generate_csrf_token()
            return success_response({'csrf_token': csrf_token})

    # ========== User Management Endpoints ==========

    @app.route('/api/users', methods=['POST'])
    def create_user():
        """Create new user (self-registration or admin creation)

        Self-registration: Allowed when ALLOW_REGISTRATION=true, no authentication required
        Admin creation: Requires user:write permission
        """
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['username', 'email', 'password'],
                optional_fields=['full_name', 'roles']
            )

            # Check if request is from an authenticated admin or unauthenticated self-registration
            # POST /api/users is skipped by before_request (line 170-171), so we manually parse JWT
            is_self_registration = True
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                try:
                    token = auth_header.split(' ')[1]
                    payload = jwt_manager.decode_token(token)
                    if payload.get('type') == 'access':
                        request.user_id = payload.get('user_id')
                        request.username = payload.get('username')
                        request.roles = payload.get('roles', [])
                        is_self_registration = False
                except Exception:
                    pass

            if is_self_registration:
                if not config.ALLOW_REGISTRATION:
                    return error_response("Self-registration is disabled", 403)
                # Self-registration always assigns 'viewer' role
                roles_to_assign = ['viewer']
            else:
                # Admin creation - check permission
                from database.rbac import require_permission
                # This will be checked by decorator if auth is enabled
                if not hasattr(request, 'user_id'):
                    return error_response("Authentication required", 401)

                from database.models import User
                from database.session import get_db
                with next(get_db()) as db:
                    admin_user = db.get(User, request.user_id)
                    if not admin_user or not admin_user.has_permission('user:write'):
                        return error_response("Permission denied: user:write required", 403)

                # Admin can specify roles
                roles_to_assign = data.get('roles', ['viewer'])

            # Validate input
            is_valid, error_msg = validate_username(data['username'])
            if not is_valid:
                return error_response(error_msg, 400)

            is_valid, error_msg = validate_email(data['email'])
            if not is_valid:
                return error_response(error_msg, 400)

            is_valid, error_msg = validate_password(data['password'])
            if not is_valid:
                return error_response(error_msg, 400)

            # Create user in database
            from database.models import User, Role
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                # Check if username already exists
                stmt = select(User).where(User.username == data['username'])
                if db.scalar(stmt):
                    return error_response("Username already exists", 409)

                # Check if email already exists
                stmt = select(User).where(User.email == data['email'])
                if db.scalar(stmt):
                    return error_response("Email already exists", 409)

                # Create new user
                new_user = User(
                    username=data['username'],
                    email=data['email'],
                    full_name=data.get('full_name', ''),
                    is_active=True,
                    email_verified=False
                )
                new_user.set_password(data['password'])

                # Assign roles
                for role_name in roles_to_assign:
                    stmt = select(Role).where(Role.name == role_name)
                    role = db.scalar(stmt)
                    if role:
                        new_user.roles.append(role)

                db.add(new_user)
                db.commit()
                db.refresh(new_user)

                logger.info(f"User created: {new_user.username} (ID: {new_user.id}) by {'self-registration' if is_self_registration else f'admin {request.username}'}")

                return success_response(new_user.to_dict(), "User created successfully", status_code=201)

        except Exception as e:
            logger.error(f"User creation error: {e}")
            return error_response(f"Failed to create user: {str(e)}", 500)

    @app.route('/api/users', methods=['GET'])
    @require_auth
    def list_users():
        """Get list of all users (admin only)

        Requires user:read permission
        """
        try:
            from database.models import User
            from database.session import get_db
            from sqlalchemy import select

            # Check permission
            with next(get_db()) as db:
                admin_user = db.get(User, request.user_id)
                if not admin_user or not admin_user.has_permission('user:read'):
                    return error_response("Permission denied: user:read required", 403)

                # Get all users
                stmt = select(User).order_by(User.created_at.desc())
                users = db.scalars(stmt).all()

                users_data = [user.to_dict() for user in users]
                return success_response(users_data)

        except Exception as e:
            logger.error(f"List users error: {e}")
            return error_response(f"Failed to list users: {str(e)}", 500)

    @app.route('/api/users/me', methods=['GET'])
    @require_auth
    def get_current_user_info():
        """Get current authenticated user information"""
        try:
            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                user = db.get(User, request.user_id)
                if not user:
                    return error_response("User not found", 404)

                return success_response(user.to_dict())

        except Exception as e:
            logger.error(f"Get current user error: {e}")
            return error_response(f"Failed to get user info: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['GET'])
    @require_auth
    def get_user(user_id: int):
        """Get user by ID

        Accessible by: user themselves or users with user:read permission
        """
        try:
            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                # Check if requesting own profile or has permission
                is_own_profile = request.user_id == user_id

                if not is_own_profile:
                    admin_user = db.get(User, request.user_id)
                    if not admin_user or not admin_user.has_permission('user:read'):
                        return error_response("Permission denied", 403)

                # Get user
                user = db.get(User, user_id)
                if not user:
                    return error_response("User not found", 404)

                return success_response(user.to_dict())

        except Exception as e:
            logger.error(f"Get user error: {e}")
            return error_response(f"Failed to get user: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['PUT'])
    @require_auth
    def update_user(user_id: int):
        """Update user information

        Own profile: Can update email, full_name
        Admin (user:write): Can update all fields including roles
        """
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=[],
                optional_fields=['email', 'full_name', 'roles', 'is_active']
            )

            from database.models import User, Role
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                # Get current user and target user
                current_user = db.get(User, request.user_id)
                target_user = db.get(User, user_id)

                if not target_user:
                    return error_response("User not found", 404)

                is_own_profile = request.user_id == user_id
                has_admin_permission = current_user and current_user.has_permission('user:write')

                # Own profile: can update basic info only
                if is_own_profile:
                    if 'email' in data:
                        is_valid, error_msg = validate_email(data['email'])
                        if not is_valid:
                            return error_response(error_msg, 400)

                        # Check email uniqueness
                        stmt = select(User).where(User.email == data['email'], User.id != user_id)
                        if db.scalar(stmt):
                            return error_response("Email already exists", 409)

                        target_user.email = data['email']
                        target_user.email_verified = False  # Require re-verification

                    if 'full_name' in data:
                        target_user.full_name = data['full_name']

                    # Deny role/status changes on own profile
                    if 'roles' in data or 'is_active' in data:
                        return error_response("Cannot change roles or status on own profile", 403)

                # Admin: can update all fields
                elif has_admin_permission:
                    if 'email' in data:
                        is_valid, error_msg = validate_email(data['email'])
                        if not is_valid:
                            return error_response(error_msg, 400)

                        stmt = select(User).where(User.email == data['email'], User.id != user_id)
                        if db.scalar(stmt):
                            return error_response("Email already exists", 409)

                        target_user.email = data['email']

                    if 'full_name' in data:
                        target_user.full_name = data['full_name']

                    if 'is_active' in data:
                        target_user.is_active = bool(data['is_active'])

                    if 'roles' in data:
                        # Update roles
                        target_user.roles.clear()
                        for role_name in data['roles']:
                            stmt = select(Role).where(Role.name == role_name)
                            role = db.scalar(stmt)
                            if role:
                                target_user.roles.append(role)

                else:
                    return error_response("Permission denied", 403)

                db.commit()
                db.refresh(target_user)

                logger.info(f"User updated: {target_user.username} (ID: {user_id}) by {request.username}")
                return success_response(target_user.to_dict(), "User updated successfully")

        except Exception as e:
            logger.error(f"Update user error: {e}")
            return error_response(f"Failed to update user: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>/password', methods=['PUT'])
    @require_auth
    def change_password(user_id: int):
        """Change user password

        Only the user themselves can change their password
        Requires current password for verification
        """
        try:
            # Only allow changing own password
            if request.user_id != user_id:
                return error_response("Can only change own password", 403)

            data = validate_json_input(
                request.get_json(),
                required_fields=['current_password', 'new_password'],
                optional_fields=[]
            )

            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                user = db.get(User, user_id)
                if not user:
                    return error_response("User not found", 404)

                # Verify current password
                if not user.check_password(data['current_password']):
                    return error_response("Current password is incorrect", 401)

                # Validate new password
                is_valid, error_msg = validate_password(data['new_password'])
                if not is_valid:
                    return error_response(error_msg, 400)

                # Set new password
                user.set_password(data['new_password'])
                db.commit()

                logger.info(f"Password changed for user: {user.username} (ID: {user_id})")
                return success_response(None, "Password changed successfully")

        except Exception as e:
            logger.error(f"Change password error: {e}")
            return error_response(f"Failed to change password: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['DELETE'])
    @require_auth
    def delete_user(user_id: int):
        """Delete user (admin only)

        Requires user:delete permission
        Cannot delete own account
        """
        try:
            # Prevent self-deletion
            if request.user_id == user_id:
                return error_response("Cannot delete own account", 403)

            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                # Check permission
                admin_user = db.get(User, request.user_id)
                if not admin_user or not admin_user.has_permission('user:delete'):
                    return error_response("Permission denied: user:delete required", 403)

                # Get target user
                target_user = db.get(User, user_id)
                if not target_user:
                    return error_response("User not found", 404)

                username = target_user.username
                db.delete(target_user)
                db.commit()

                logger.info(f"User deleted: {username} (ID: {user_id}) by {request.username}")
                return success_response(None, "User deleted successfully")

        except Exception as e:
            logger.error(f"Delete user error: {e}")
            return error_response(f"Failed to delete user: {str(e)}", 500)

    # ========== Admin Security Logs Endpoints ==========

    @app.route('/api/admin/security-logs', methods=['GET'])
    @require_role('admin')
    def get_security_logs():
        """Get security logs (login attempts) - Admin only

        Query parameters:
            page (int): Page number (default: 1)
            per_page (int): Items per page (default: 50, max: 200)
            ip_address (str): Filter by IP address
            username (str): Filter by username
            success (bool): Filter by success status (true/false)
            start_date (str): Filter by start date (ISO format)
            end_date (str): Filter by end date (ISO format)
            sort (str): Sort order - 'asc' or 'desc' (default: 'desc')

        Returns:
            JSON response with paginated login attempts
        """
        try:
            from database.models import LoginAttempt
            from database.session import get_db
            from sqlalchemy import select, func, and_
            from datetime import datetime, timezone

            # Parse query parameters with validation
            page = max(1, int(request.args.get('page', 1)))
            per_page = min(200, max(1, int(request.args.get('per_page', 50))))
            ip_address = request.args.get('ip_address')
            username = request.args.get('username')
            success_filter = request.args.get('success')
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            sort_order = request.args.get('sort', 'desc')

            with next(get_db()) as db:
                # Build base query
                query = select(LoginAttempt)
                filters = []

                # Apply filters
                if ip_address:
                    filters.append(LoginAttempt.ip_address == ip_address)

                if username:
                    filters.append(LoginAttempt.username == username)

                if success_filter is not None:
                    success_bool = success_filter.lower() == 'true'
                    filters.append(LoginAttempt.success == success_bool)

                if start_date:
                    try:
                        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                        filters.append(LoginAttempt.attempt_time >= start_dt)
                    except ValueError:
                        return error_response("Invalid start_date format. Use ISO format.", 400)

                if end_date:
                    try:
                        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        filters.append(LoginAttempt.attempt_time <= end_dt)
                    except ValueError:
                        return error_response("Invalid end_date format. Use ISO format.", 400)

                if filters:
                    query = query.where(and_(*filters))

                # Apply sorting
                if sort_order == 'asc':
                    query = query.order_by(LoginAttempt.attempt_time.asc())
                else:
                    query = query.order_by(LoginAttempt.attempt_time.desc())

                # Get total count
                count_query = select(func.count()).select_from(LoginAttempt)
                if filters:
                    count_query = count_query.where(and_(*filters))
                total = db.scalar(count_query)

                # Apply pagination
                offset = (page - 1) * per_page
                query = query.offset(offset).limit(per_page)

                # Execute query
                attempts = db.scalars(query).all()

                # Convert to dict
                logs = []
                for attempt in attempts:
                    logs.append({
                        'id': attempt.id,
                        'ip_address': attempt.ip_address,
                        'username': attempt.username,
                        'attempt_time': attempt.attempt_time.isoformat(),
                        'success': attempt.success,
                        'user_agent': attempt.user_agent
                    })

                # Calculate pagination info
                total_pages = (total + per_page - 1) // per_page

                logger.info(f"Security logs retrieved: page={page}, total={total}, user={request.username}")

                return success_response({
                    'logs': logs,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                })

        except ValueError as e:
            return error_response(f"Invalid parameter: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Get security logs error: {e}")
            return error_response(f"Failed to retrieve security logs: {str(e)}", 500)

    @app.route('/api/admin/security-logs/stats', methods=['GET'])
    @require_role('admin')
    def get_security_stats():
        """Get security statistics - Admin only

        Returns:
            JSON response with security statistics
        """
        try:
            from database.models import LoginAttempt
            from database.session import get_db
            from sqlalchemy import select, func, and_
            from datetime import datetime, timezone, timedelta

            with next(get_db()) as db:
                now = datetime.now(timezone.utc)

                # Total attempts
                total_attempts = db.scalar(select(func.count()).select_from(LoginAttempt))

                # Failed attempts
                failed_attempts = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.success == False
                    )
                )

                # Success rate
                success_rate = ((total_attempts - failed_attempts) / total_attempts * 100) if total_attempts > 0 else 0

                # Unique IPs
                unique_ips = db.scalar(
                    select(func.count(func.distinct(LoginAttempt.ip_address))).select_from(LoginAttempt)
                )

                # Blocked IPs (IPs with failed attempts in last 15 minutes)
                rate_limit_window = now - timedelta(minutes=15)
                blocked_ips_query = select(func.count(func.distinct(LoginAttempt.ip_address))).select_from(LoginAttempt).where(
                    and_(
                        LoginAttempt.attempt_time > rate_limit_window.replace(tzinfo=None),
                        LoginAttempt.success == False
                    )
                ).group_by(LoginAttempt.ip_address).having(
                    func.count() >= 10
                )
                blocked_ips = len(list(db.execute(blocked_ips_query)))

                # Most targeted accounts (top 5)
                most_targeted = db.execute(
                    select(
                        LoginAttempt.username,
                        func.count().label('count')
                    ).where(
                        and_(
                            LoginAttempt.username.isnot(None),
                            LoginAttempt.success == False
                        )
                    ).group_by(LoginAttempt.username).order_by(func.count().desc()).limit(5)
                ).all()

                most_targeted_accounts = [
                    {'username': row[0], 'count': row[1]} for row in most_targeted
                ]

                # Recent 24 hours stats
                recent_24h_start = now - timedelta(hours=24)
                recent_24h_total = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.attempt_time > recent_24h_start.replace(tzinfo=None)
                    )
                )
                recent_24h_failed = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        and_(
                            LoginAttempt.attempt_time > recent_24h_start.replace(tzinfo=None),
                            LoginAttempt.success == False
                        )
                    )
                )

                # Recent 7 days stats
                recent_7d_start = now - timedelta(days=7)
                recent_7d_total = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.attempt_time > recent_7d_start.replace(tzinfo=None)
                    )
                )
                recent_7d_failed = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        and_(
                            LoginAttempt.attempt_time > recent_7d_start.replace(tzinfo=None),
                            LoginAttempt.success == False
                        )
                    )
                )

                logger.info(f"Security stats retrieved by user={request.username}")

                return success_response({
                    'total_attempts': total_attempts or 0,
                    'failed_attempts': failed_attempts or 0,
                    'success_rate': round(success_rate, 2),
                    'unique_ips': unique_ips or 0,
                    'blocked_ips': blocked_ips,
                    'most_targeted_accounts': most_targeted_accounts,
                    'recent_24h': {
                        'total': recent_24h_total or 0,
                        'failed': recent_24h_failed or 0
                    },
                    'recent_7d': {
                        'total': recent_7d_total or 0,
                        'failed': recent_7d_failed or 0
                    }
                })

        except Exception as e:
            logger.error(f"Get security stats error: {e}")
            return error_response(f"Failed to retrieve security statistics: {str(e)}", 500)

    # ========== Password Reset Endpoints ==========

    @app.route('/api/auth/password-reset-request', methods=['POST'])
    def password_reset_request():
        """Request password reset link

        Public endpoint - no authentication required
        Always returns success to prevent email enumeration attacks

        Request body:
        {
            "email": "user@example.com"
        }
        """
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['email'],
                optional_fields=[]
            )

            email = data['email'].strip().lower()

            # Basic email validation
            is_valid, error_msg = validate_email(email)
            if not is_valid:
                # Still return success to prevent enumeration
                return success_response(
                    None,
                    "If the email exists, a password reset link has been sent"
                )

            from database.models import User, PasswordResetToken
            from database.session import get_db
            from sqlalchemy import select
            from datetime import datetime, timezone, timedelta
            import secrets

            with next(get_db()) as db:
                # Find user by email
                stmt = select(User).where(User.email == email)
                user = db.scalar(stmt)

                if user and user.is_active:
                    # Create reset token (plaintext token returned, hash stored in DB)
                    reset_token, token = PasswordResetToken.create_for_user(
                        user_id=user.id,
                        expiry_seconds=config.PASSWORD_RESET_TOKEN_EXPIRY
                    )
                    reset_token.ip_address = request.remote_addr
                    db.add(reset_token)
                    db.commit()

                    # Send email with plaintext token
                    from utils.email import send_password_reset_email
                    send_password_reset_email(user.email, user.username, token)

                    logger.info(f"Password reset requested for user: {user.username} from {request.remote_addr}")

            # Always return same message (security: prevent email enumeration)
            return success_response(
                None,
                "If the email exists, a password reset link has been sent"
            )

        except Exception as e:
            logger.error(f"Password reset request error: {e}")
            # Still return success to prevent information leakage
            return success_response(
                None,
                "If the email exists, a password reset link has been sent"
            )

    @app.route('/api/auth/password-reset', methods=['POST'])
    def password_reset():
        """Reset password using valid token

        Public endpoint - no authentication required

        Request body:
        {
            "token": "secure-token-string",
            "new_password": "NewPassword123!"
        }
        """
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['token', 'new_password'],
                optional_fields=[]
            )

            token = data['token'].strip()
            new_password = data['new_password']

            if not token:
                return error_response("Token is required", 400)

            from database.models import User, PasswordResetToken
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                # Find token by hash (plaintext never stored)
                token_hash = PasswordResetToken.hash_token(token)
                stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
                reset_token = db.scalar(stmt)

                if not reset_token or not reset_token.is_valid():
                    return error_response("Invalid or expired reset token", 400)

                # Validate new password
                is_valid, error_msg = validate_password(new_password)
                if not is_valid:
                    return error_response(error_msg, 400)

                # Get user
                user = reset_token.user

                # Update password
                user.set_password(new_password)

                # Mark token as used
                reset_token.mark_used()

                db.commit()

                logger.info(f"Password reset successful for user: {user.username} from {request.remote_addr}")

                return success_response(None, "Password has been reset successfully")

        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return error_response("Failed to reset password", 500)


# ========== Network Initialization ==========
@app.route('/api/network/initialize', methods=['POST'])
def initialize_network():
    """
    Initialize Batfish network with configuration snapshot

    Request body:
    {
        "snapshot_dir": "/path/to/snapshot",
        "snapshot_name": "optional-name"
    }
    """
    try:
        data = request.get_json()
        if not data or ('snapshot_dir' not in data and 'snapshot_name' not in data):
            return error_response("Missing 'snapshot_dir' or 'snapshot_name' in request body", 400)

        snapshot_dir = data.get('snapshot_dir', '')
        snapshot_name = data.get('snapshot_name')

        if config.AUTH_ENABLED:
            resolved_snapshot_name = snapshot_name or Path(str(snapshot_dir)).name
            safe_path = snapshot_service.get_snapshot_path(
                resolved_snapshot_name,
                **get_snapshot_request_context(),
            )
            snapshot_name = resolved_snapshot_name
        else:
            # Validate snapshot directory path against allowed base path
            try:
                safe_path = validate_path(config.ALLOWED_SNAPSHOT_PATH, snapshot_dir)
            except ValueError as e:
                return error_response(f"Invalid snapshot directory: {e}", 400)

        # Initialize network
        result = batfish_service.initialize_network(str(safe_path), snapshot_name)

        if config.AUTH_ENABLED:
            session['current_snapshot_name'] = result.get('snapshot')

        return success_response(result, "Network initialized successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to initialize network: {e}")
        return error_response(f"Initialization failed: {str(e)}", 500)


# ========== Query Endpoints (22 types) ==========

@app.route('/api/network/nodes', methods=['GET'])
def get_nodes():
    """Get all node properties"""
    try:
        nodes = batfish_service.get_node_properties()
        # Cache for 5 minutes with ETag support
        return success_response(nodes, cache_time=300, use_etag=True)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get nodes: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/interfaces', methods=['GET'])
def get_interfaces():
    """Get all interface properties"""
    try:
        interfaces = batfish_service.get_interface_properties()
        # Cache for 5 minutes with ETag support
        return success_response(interfaces, cache_time=300, use_etag=True)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/routes', methods=['GET'])
def get_routes():
    """Get all routing table entries"""
    try:
        routes = batfish_service.get_routes()
        # Cache for 5 minutes with ETag support
        return success_response(routes, cache_time=300, use_etag=True)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get routes: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/processes', methods=['GET'])
def get_ospf_processes():
    """Get OSPF process configurations"""
    try:
        processes = batfish_service.get_ospf_process_configuration()
        return success_response([p.to_dict() for p in processes])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF processes: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/areas', methods=['GET'])
def get_ospf_areas():
    """Get OSPF area configurations"""
    try:
        areas = batfish_service.get_ospf_area_configuration()
        return success_response([a.to_dict() for a in areas])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF areas: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/interfaces', methods=['GET'])
def get_ospf_interfaces():
    """Get OSPF interface configurations"""
    try:
        interfaces = batfish_service.get_ospf_interface_configuration()
        return success_response([i.to_dict() for i in interfaces])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF interfaces: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/sessions', methods=['GET'])
def get_ospf_sessions():
    """Get OSPF session compatibility status"""
    try:
        sessions = batfish_service.get_ospf_session_compatibility()
        return success_response([s.to_dict() for s in sessions])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF sessions: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/ospf', methods=['GET'])
def get_ospf_edges():
    """Get OSPF topology edges"""
    try:
        edges = batfish_service.get_ospf_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/physical', methods=['GET'])
def get_physical_edges():
    """Get layer 1 physical edges"""
    try:
        edges = batfish_service.get_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get physical edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/layer3', methods=['GET'])
def get_layer3_edges():
    """Get layer 3 edges"""
    try:
        edges = batfish_service.get_layer3_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer 3 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/vlans', methods=['GET'])
def get_vlans():
    """Get switched VLAN properties"""
    try:
        vlans = batfish_service.get_switched_vlan_properties()
        return success_response(vlans)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VLANs: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/ip-owners', methods=['GET'])
def get_ip_owners():
    """Get IP address ownership mapping"""
    try:
        owners = batfish_service.get_ip_owners()
        return success_response(owners)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IP owners: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/defined-structures', methods=['GET'])
def get_defined_structures():
    """Get defined configuration structures"""
    try:
        structures = batfish_service.get_defined_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get defined structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/referenced-structures', methods=['GET'])
def get_referenced_structures():
    """Get referenced configuration structures"""
    try:
        structures = batfish_service.get_referenced_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get referenced structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/named-structures', methods=['GET'])
def get_named_structures():
    """Get named structures with full definitions"""
    try:
        structures = batfish_service.get_named_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get named structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/file-parse-status', methods=['GET'])
def get_file_parse_status():
    """Get file parse status"""
    try:
        statuses = batfish_service.get_file_parse_status()
        return success_response([s.to_dict() for s in statuses])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get file parse status: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/init-issues', methods=['GET'])
def get_init_issues():
    """Get initialization issues"""
    try:
        issues = batfish_service.get_init_issues()
        return success_response([i.to_dict() for i in issues])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get init issues: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/parse-warnings', methods=['GET'])
def get_parse_warnings():
    """Get parse warnings"""
    try:
        warnings = batfish_service.get_parse_warnings()
        return success_response([w.to_dict() for w in warnings])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get parse warnings: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/vi-conversion-status', methods=['GET'])
def get_vi_conversion_status():
    """Get vendor-independent conversion status"""
    try:
        statuses = batfish_service.get_vi_conversion_status()
        return success_response([s.to_dict() for s in statuses])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VI conversion status: {e}")
        return error_response(str(e), 500)


@app.route('/api/analysis/reachability', methods=['POST'])
def get_reachability():
    """
    Get reachability analysis results

    Optional request body:
    {
        "headers": {
            "srcIps": "192.0.2.1",
            "dstIps": "192.0.2.2"
        }
    }
    """
    try:
        data = request.get_json() if request.is_json else {}
        headers = data.get('headers') if data else None

        flow_traces = batfish_service.get_reachability(headers)
        return success_response([f.to_dict() for f in flow_traces])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/analysis/route-policies', methods=['GET'])
def get_route_policies():
    """
    Search route policies

    Query parameters:
    - nodes: Node regex pattern (default: ".*")
    - action: Action to search for (default: "permit")
    """
    try:
        nodes = request.args.get('nodes', '.*')
        action = request.args.get('action', 'permit')

        policies = batfish_service.get_search_route_policies(nodes, action)
        return success_response(policies)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/aaa-authentication', methods=['GET'])
def get_aaa_authentication():
    """Get AAA authentication login configuration"""
    try:
        aaa_configs = batfish_service.get_aaa_authentication_login()
        return success_response(aaa_configs)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get AAA authentication: {e}")
        return error_response(str(e), 500)


@app.route('/api/security/snmp-communities', methods=['GET'])
def get_snmp_communities():
    """Get SNMP community configurations for security validation."""
    try:
        snmp_configs = batfish_service.get_snmp_community_clients()
        return success_response(snmp_configs)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get SNMP community clients: {e}")
        return error_response(str(e), 500)


# ========== BGP Analysis Endpoints ==========
@app.route('/api/bgp/edges', methods=['GET'])
def get_bgp_edges():
    """Get BGP adjacencies/neighbors topology"""
    try:
        edges = batfish_service.get_bgp_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/peer-configuration', methods=['GET'])
def get_bgp_peer_configuration():
    """Get BGP peer settings and configurations"""
    try:
        peers = batfish_service.get_bgp_peer_configuration()
        return success_response(peers)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP peer configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/process-configuration', methods=['GET'])
def get_bgp_process_configuration():
    """Get BGP process-wide settings"""
    try:
        processes = batfish_service.get_bgp_process_configuration()
        return success_response(processes)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP process configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/session-status', methods=['GET'])
def get_bgp_session_status():
    """Get BGP session operational status"""
    try:
        sessions = batfish_service.get_bgp_session_status()
        return success_response(sessions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP session status: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/session-compatibility', methods=['GET'])
def get_bgp_session_compatibility():
    """Get BGP session configuration validation"""
    try:
        compatibility = batfish_service.get_bgp_session_compatibility()
        return success_response(compatibility)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP session compatibility: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/rib', methods=['GET'])
def get_bgp_rib():
    """Get BGP Routing Information Base entries"""
    try:
        rib = batfish_service.get_bgp_rib()
        return success_response(rib)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP RIB: {e}")
        return error_response(str(e), 500)


# ========== ACL/Firewall Analysis Endpoints ==========
@app.route('/api/acl/test-filters', methods=['POST'])
def test_filters():
    """
    Test flows against ACLs/firewall rules

    Request body:
    {
        "headers": {"srcIps": "192.0.2.1", "dstIps": "198.51.100.1", "dstPorts": "22"},
        "nodes": "router1",
        "filters": "ACL_NAME",
        "startLocation": "router1[GigabitEthernet0/1]"
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        if not isinstance(headers, dict) or not headers:
            return error_response("Missing required 'headers' object for testFilters", 400)

        nodes = normalize_batfish_specifier(data.get('nodes'))
        filters = normalize_batfish_specifier(data.get('filters'))
        startLocation = data.get('startLocation')

        results = batfish_service.test_filters(headers, nodes, filters, startLocation)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to test filters: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/filter-line-reachability', methods=['GET'])
def get_filter_line_reachability():
    """Identify unreachable/shadowed ACL lines"""
    try:
        filters = get_query_specifier('filters')
        nodes = get_query_specifier('nodes')
        ignore_composites = parse_optional_bool(request.args.get('ignoreComposites'))

        results = batfish_service.get_filter_line_reachability(
            filters=filters,
            nodes=nodes,
            ignoreComposites=ignore_composites,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get filter line reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/search-filters', methods=['POST'])
def search_filters():
    """
    Search for flows matching conditions (permit/deny)

    Request body:
    {
        "headers": {"srcIps": "192.0.2.1", "dstIps": "198.51.100.1"},
        "action": "PERMIT",
        "filters": "ACL_NAME",
        "nodes": "router1"
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        action = data.get('action')
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))

        results = batfish_service.search_filters(headers, action, filters, nodes)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to search filters: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/find-matching-lines', methods=['POST'])
def find_matching_filter_lines():
    """
    Find ACL lines matching specific flows

    Request body:
    {
        "headers": {"srcIps": "192.0.2.1", "dstIps": "198.51.100.1"},
        "filters": "ACL_NAME",
        "nodes": "router1"
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))

        results = batfish_service.find_matching_filter_lines(headers, filters, nodes)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to find matching filter lines: {e}")
        return error_response(str(e), 500)


# ========== Path Analysis Endpoints ==========
@app.route('/api/path/traceroute', methods=['POST'])
def traceroute():
    """
    Virtual traceroute through network

    Request body:
    {
        "headers": {
            "srcIps": "192.0.2.1",
            "dstIps": "198.51.100.1",
            "ipProtocols": ["TCP", "UDP"],
            "srcPorts": "1000-2000",
            "dstPorts": "80,443",
            "applications": ["DNS", "SSH"],
            "icmpTypes": [0, 8],
            "icmpCodes": [0],
            "dscps": [0],
            "ecns": [0]
        },
        "startLocation": "router1[GigabitEthernet0/1]",
        "maxTraces": 10,
        "ignoreFilters": false
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        startLocation = data.get('startLocation')
        ignoreFilters = data.get('ignoreFilters', False)
        maxTraces = data.get('maxTraces')

        results = batfish_service.traceroute(
            headers=headers,
            startLocation=startLocation,
            ignoreFilters=ignoreFilters,
            maxTraces=maxTraces,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run traceroute: {e}")
        return error_response(str(e), 500)


@app.route('/api/path/bidirectional-traceroute', methods=['POST'])
def bidirectional_traceroute():
    """
    Bidirectional traceroute validation

    Tests reachability in both directions with detailed configuration options.

    Request body supports:
    - headers: detailed packet specifications (srcIps, dstIps, ipProtocols, ports, ICMP, DSCP, ECN)
    - startLocation: starting device/interface
    - maxTraces: limit result count
    - ignoreFilters: bypass ACLs

    Example:
    {
        "headers": {
            "srcIps": "192.0.2.1",
            "dstIps": "198.51.100.1",
            "ipProtocols": ["TCP"],
            "dstPorts": "80"
        },
        "startLocation": "router1",
        "maxTraces": 5,
        "ignoreFilters": false
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        startLocation = data.get('startLocation')
        ignoreFilters = data.get('ignoreFilters', False)
        maxTraces = data.get('maxTraces')

        results = batfish_service.bidirectional_traceroute(
            headers=headers,
            startLocation=startLocation,
            ignoreFilters=ignoreFilters,
            maxTraces=maxTraces,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run bidirectional traceroute: {e}")
        return error_response(str(e), 500)


# ========== Aggregate Data Endpoint ==========
@app.route('/api/network/all-data', methods=['GET'])
def get_all_data():
    """
    Fetch all 22 types of Batfish data in one request

    This is useful for initial data loading or full refresh
    """
    try:
        all_data = batfish_service.fetch_all_data()
        # Cache for 5 minutes with ETag support - this is the main data endpoint
        return success_response(all_data, "All network data fetched successfully",
                              cache_time=300, use_etag=True)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to fetch all data: {e}")
        return error_response(str(e), 500)


# ========== Phase 1: Network Validation Endpoints ==========
@app.route('/api/validation/unused-structures', methods=['GET'])
def get_unused_structures():
    """Get unused configuration structures (defined but not referenced)"""
    try:
        unused = batfish_service.get_unused_structures()
        return success_response(unused)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get unused structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/undefined-references', methods=['GET'])
def get_undefined_references():
    """Get undefined references (referenced but not defined)"""
    try:
        undefined = batfish_service.get_undefined_references()
        return success_response(undefined)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get undefined references: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-filter-specifier', methods=['POST'])
def resolve_filter_specifier():
    """
    Resolve filter specifier to actual filters

    Request body:
    {
        "filters": "ACL.*",
        "nodes": "router1"
    }
    """
    try:
        data = request.get_json() or {}
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        if not filters:
            return error_response("Missing required 'filters' for resolveFilterSpecifier", 400)

        results = batfish_service.resolve_filter_specifier(filters, nodes, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve filter specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-node-specifier', methods=['POST'])
def resolve_node_specifier():
    """
    Resolve node specifier to actual nodes

    Request body:
    {
        "nodes": "/router.*/"
    }
    """
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_node_specifier(nodes, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve node specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-interface-specifier', methods=['POST'])
def resolve_interface_specifier():
    """
    Resolve interface specifier to actual interfaces

    Request body:
    {
        "interfaces": "GigabitEthernet.*",
        "nodes": "router1"
    }
    """
    try:
        data = request.get_json() or {}
        interfaces = normalize_batfish_specifier(data.get('interfaces'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        if not interfaces:
            return error_response("Missing required 'interfaces' for resolveInterfaceSpecifier", 400)

        results = batfish_service.resolve_interface_specifier(interfaces, nodes, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve interface specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/detect-loops', methods=['GET'])
def get_detect_loops():
    """Detect forwarding loops in the network"""
    try:
        loops = batfish_service.get_detect_loops()
        return success_response(loops)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to detect loops: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/multipath-consistency', methods=['GET'])
def get_multipath_consistency():
    """Check multipath routing consistency"""
    try:
        consistency = batfish_service.get_multipath_consistency()
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/loopback-multipath-consistency', methods=['GET'])
def get_loopback_multipath_consistency():
    """Check loopback multipath routing consistency"""
    try:
        consistency = batfish_service.get_loopback_multipath_consistency()
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check loopback multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/subnet-multipath-consistency', methods=['POST'])
def get_subnet_multipath_consistency():
    """Subnet multipath consistency check"""
    try:
        data = request.get_json() or {}
        max_traces = data.get('maxTraces')
        consistency = batfish_service.get_subnet_multipath_consistency(maxTraces=max_traces)
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check subnet multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/compare-filters', methods=['POST'])
def compare_filters():
    """
    Compare filters/ACLs for equivalence

    Request body:
    {
        "filters": "ACL1,ACL2",
        "nodes": "router1,router2"
    }
    """
    try:
        data = request.get_json() or {}
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        ignore_composites = parse_optional_bool(data.get('ignoreComposites'))
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot'))
        snapshot = data.get('snapshot')

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for compare filters", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_filters(
            filters=filters,
            nodes=nodes,
            ignoreComposites=ignore_composites,
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare filters: {e}")
        return error_response(str(e), 500)


# ========== High Availability Endpoints ==========
@app.route('/api/ha/vrrp-properties', methods=['GET'])
def get_vrrp_properties():
    """Get VRRP (Virtual Router Redundancy Protocol) properties"""
    try:
        vrrp = batfish_service.get_vrrp_properties()
        return success_response(vrrp)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VRRP properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/hsrp-properties', methods=['GET'])
def get_hsrp_properties():
    """Get HSRP (Hot Standby Router Protocol) properties"""
    try:
        hsrp = batfish_service.get_hsrp_properties()
        return success_response(hsrp)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get HSRP properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/mlag-properties', methods=['GET'])
def get_mlag_properties():
    """Get MLAG (Multi-chassis LAG) properties"""
    try:
        mlag = batfish_service.get_mlag_properties()
        return success_response(mlag)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get MLAG properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/duplicate-router-ids', methods=['GET'])
def get_duplicate_router_ids():
    """Get duplicate router IDs detected in OSPF or BGP"""
    try:
        duplicates = batfish_service.get_duplicate_router_ids()
        return success_response([d.to_dict() for d in duplicates])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get duplicate router IDs: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/switching-properties', methods=['GET'])
def get_switching_properties():
    """Get switching properties"""
    try:
        switching = batfish_service.get_switched_vlan_properties()
        return success_response(switching)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get switching properties: {e}")
        return error_response(str(e), 500)


# ========== Phase 2: EVPN/VXLAN Endpoints ==========
@app.route('/api/protocols/evpn/rib', methods=['GET'])
def get_evpn_rib():
    """Get EVPN Routing Information Base"""
    try:
        evpn_rib = batfish_service.get_evpn_rib()
        return success_response(evpn_rib)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EVPN RIB: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/evpn/vxlan-edges', methods=['GET'])
def get_vxlan_edges():
    """Get VXLAN tunnel edges/topology"""
    try:
        edges = batfish_service.get_vxlan_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VXLAN edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/evpn/vxlan-vni-properties', methods=['GET'])
def get_vxlan_vni_properties():
    """Get VXLAN VNI (Virtual Network Identifier) properties"""
    try:
        vni_props = batfish_service.get_vxlan_vni_properties()
        return success_response(vni_props)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VXLAN VNI properties: {e}")
        return error_response(str(e), 500)


# ========== EIGRP Protocol Endpoints ==========
@app.route('/api/protocols/eigrp/edges', methods=['GET'])
def get_eigrp_edges():
    """Get EIGRP neighbor relationships/topology"""
    try:
        edges = batfish_service.get_eigrp_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EIGRP edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/eigrp/interface-configuration', methods=['GET'])
def get_eigrp_interface_configuration():
    """Get EIGRP interface configuration"""
    try:
        interfaces = batfish_service.get_eigrp_interface_configuration()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EIGRP interface configuration: {e}")
        return error_response(str(e), 500)


# ========== IS-IS Protocol Endpoints ==========
@app.route('/api/protocols/isis/edges', methods=['GET'])
def get_isis_edges():
    """Get IS-IS neighbor relationships/topology"""
    try:
        edges = batfish_service.get_isis_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IS-IS edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/isis/interface-configuration', methods=['GET'])
def get_isis_interface_configuration():
    """Get IS-IS interface configuration"""
    try:
        interfaces = batfish_service.get_isis_interface_configuration()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IS-IS interface configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/isis-loopback-interfaces', methods=['GET'])
def get_isis_loopback_interfaces():
    """Get IS-IS loopback interfaces"""
    try:
        return success_response([])
    except Exception as e:
        logger.error(f"Failed to get IS-IS loopback interfaces: {e}")
        return error_response(str(e), 500)


# ========== BFD Protocol Endpoints ==========
@app.route('/api/protocols/bfd-session-status', methods=['GET'])
def get_bfd_session_status():
    """Get BFD session status"""
    try:
        sessions = batfish_service.get_bfd_session_status()
        return success_response(sessions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BFD session status: {e}")
        return error_response(str(e), 500)


# ========== Topology Endpoints ==========
@app.route('/api/topology/layer1-edges', methods=['GET'])
def get_layer1_edges():
    """Get Layer 1 physical topology edges"""
    try:
        edges = batfish_service.get_layer1_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer 1 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/layer1-topology', methods=['GET'])
def get_layer1_topology():
    """Get Layer 1 topology"""
    try:
        layer1 = batfish_service.get_layer1_edges()
        return success_response(layer1)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/user-provided-layer1-edges', methods=['POST'])
def get_user_provided_layer1_edges():
    """Get Batfish-normalized user-provided Layer1 edges."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        remote_nodes = normalize_batfish_specifier(data.get('remoteNodes'))

        edges = batfish_service.get_user_provided_layer1_edges(nodes, remote_nodes)
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get user-provided Layer1 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-session-status', methods=['GET'])
def get_ipsec_session_status():
    """Get IPsec session status"""
    try:
        sessions = batfish_service.get_ipsec_session_status()
        return success_response(sessions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec session status: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-edges', methods=['GET'])
def get_ipsec_edges():
    """Get IPsec VPN edges"""
    try:
        edges = batfish_service.get_ipsec_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-peer-configuration', methods=['GET'])
def get_ipsec_peer_configuration():
    """Get IPsec peer configuration"""
    try:
        config = batfish_service.get_ipsec_peer_configuration()
        return success_response(config)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec peer configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/layer2-topology', methods=['GET'])
def get_layer2_topology():
    """Get Layer 2 topology"""
    try:
        layer2 = batfish_service.get_layer2_topology()
        return success_response(layer2)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer2 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/switched-vlan-edges', methods=['GET'])
def get_switched_vlan_edges():
    """Get switched VLAN topology edges"""
    try:
        edges = batfish_service.get_switched_vlan_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get switched VLAN edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/interface-mtu', methods=['GET'])
def get_interface_mtu():
    """Get interface MTU configurations"""
    try:
        mtu = batfish_service.get_interface_mtu()
        return success_response(mtu)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interface MTU: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ip-space-assignment', methods=['GET'])
def get_ip_space_assignment():
    """Get IP space assignments across the network"""
    try:
        assignments = batfish_service.get_ip_space_assignment()
        return success_response(assignments)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IP space assignment: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/lpm-routes', methods=['POST'])
def get_lpm_routes():
    """
    Get Longest Prefix Match routes for an IP

    Request body:
    {
        "ip": "192.0.2.1"
    }
    """
    try:
        data = request.get_json() or {}
        ip = data.get('ip')
        nodes = normalize_batfish_specifier(data.get('nodes'))
        vrfs = normalize_batfish_specifier(data.get('vrfs'))

        if not ip:
            return error_response("Missing 'ip' parameter", 400)

        routes = batfish_service.get_lpm_routes(ip, nodes, vrfs)
        return success_response(routes)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get LPM routes: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/prefix-tracer', methods=['POST'])
def get_prefix_tracer():
    """
    Trace prefix propagation through network

    Request body:
    {
        "prefix": "192.0.2.0/24",
        "nodes": "router1"
    }
    """
    try:
        data = request.get_json() or {}
        prefix = data.get('prefix')
        nodes = normalize_batfish_specifier(data.get('nodes'))

        if not prefix:
            return error_response("Missing 'prefix' parameter", 400)

        traces = batfish_service.get_prefix_tracer(prefix, nodes)
        return success_response(traces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to trace prefix: {e}")
        return error_response(str(e), 500)


# ========== Phase 3: Advanced Features Endpoints ==========
@app.route('/api/advanced/differential-reachability', methods=['POST'])
def get_differential_reachability():
    """
    Get differential reachability analysis

    Request body:
    {
        "reference_snapshot": "baseline-snapshot",
        "snapshot": "candidate-snapshot",
        "headers": {
            "srcIps": "192.0.2.1",
            "dstIps": "198.51.100.1"
        },
        "pathConstraints": {
            "transitLocations": "router1"
        }
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        reference_snapshot = data.get('reference_snapshot')
        snapshot = data.get('snapshot')
        path_constraints = data.get('pathConstraints')
        actions = data.get('actions')
        max_traces = data.get('maxTraces')
        invert_search = parse_optional_bool(data.get('invertSearch'))
        ignore_filters = parse_optional_bool(data.get('ignoreFilters'))

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for differential reachability", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.get_differential_reachability(
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
            headers=headers,
            pathConstraints=path_constraints,
            actions=actions,
            maxTraces=max_traces,
            invertSearch=invert_search,
            ignoreFilters=ignore_filters,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to get differential reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/bidirectional-reachability', methods=['POST'])
def get_bidirectional_reachability():
    """
    Get bidirectional reachability analysis

    Request body:
    {
        "headers": {
            "srcIps": "192.0.2.1",
            "dstIps": "198.51.100.1"
        }
    }
    """
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        path_constraints = data.get('pathConstraints')
        return_flow_type = data.get('returnFlowType')

        if not headers:
            return error_response("Missing required 'headers' for bidirectional reachability", 400)

        results = batfish_service.get_bidirectional_reachability(
            headers=headers,
            pathConstraints=path_constraints,
            returnFlowType=return_flow_type,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get bidirectional reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-location-specifier', methods=['POST'])
def resolve_location_specifier():
    """
    Resolve location specifier to actual locations

    Request body:
    {
        "locations": "router1[GigabitEthernet0/1]"
    }
    """
    try:
        data = request.get_json() or {}
        locations = data.get('locations')
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_location_specifier(locations, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve location specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-ip-specifier', methods=['POST'])
def resolve_ip_specifier():
    """
    Resolve IP specifier to actual IPs

    Request body:
    {
        "ips": "192.0.2.0/24"
    }
    """
    try:
        data = request.get_json() or {}
        ips = data.get('ips')
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_ip_specifier(ips, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve IP specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-ips-of-location-specifier', methods=['POST'])
def resolve_ips_of_location_specifier():
    """
    Resolve location specifier to source IP spaces.

    Request body:
    {
        "locations": "@enter(router1[GigabitEthernet0/1])"
    }
    """
    try:
        data = request.get_json() or {}
        locations = data.get('locations')
        grammar_version = data.get('grammarVersion')

        if not locations:
            return error_response("Missing required 'locations' for resolveIpsOfLocationSpecifier", 400)

        results = batfish_service.resolve_ips_of_location_specifier(locations, grammar_version)
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve IPs of location specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/f5-bigip-vip-configuration', methods=['GET'])
def get_f5_bigip_vip_configuration():
    """Get F5 BIG-IP VIP configuration"""
    try:
        vip_config = batfish_service.get_f5_bigip_vip_configuration()
        return success_response(vip_config)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get F5 VIP configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/a10-virtual-server-configuration', methods=['POST'])
def get_a10_virtual_server_configuration():
    """Get A10 virtual server configuration."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        virtual_server_ips = data.get('virtualServerIps')

        virtual_servers = batfish_service.get_a10_virtual_server_configuration(
            nodes=nodes,
            virtualServerIps=virtual_server_ips,
        )
        return success_response(virtual_servers)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get A10 virtual server configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/route-policies', methods=['GET'])
def get_route_policies_advanced():
    """
    Get route policies/maps configuration

    Query parameters:
    - nodes: Node regex pattern (optional)
    """
    try:
        nodes = request.args.get('nodes')

        policies = batfish_service.get_route_policies(nodes)
        return success_response(policies)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/test-route-policies', methods=['POST'])
def test_route_policies():
    """
    Test route policies against input routes

    Request body:
    {
        "direction": "IN",
        "inputRoutes": [{
            "network": "192.0.2.0/24",
            "nextHopIp": "198.51.100.1",
            "protocol": "bgp"
        }],
        "nodes": "router1",
        "policies": "POLICY_NAME"
    }
    """
    try:
        data = request.get_json() or {}
        direction = data.get('direction')
        inputRoutes = data.get('inputRoutes', data.get('inputRoute'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        policies = normalize_batfish_specifier(data.get('policies'))
        bgpSessionProperties = data.get('bgpSessionProperties')

        if not direction:
            return error_response("Missing required 'direction' for testRoutePolicies", 400)
        if inputRoutes is None:
            return error_response("Missing required 'inputRoutes' for testRoutePolicies", 400)

        results = batfish_service.test_route_policies(
            direction=direction,
            inputRoutes=inputRoutes,
            nodes=nodes,
            policies=policies,
            bgpSessionProperties=bgpSessionProperties,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to test route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/transfer-bdd-validation', methods=['POST'])
def transfer_bdd_validation():
    """Run symbolic route policy transfer BDD validation."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        policies = normalize_batfish_specifier(data.get('policies'))
        retain_all_paths = parse_optional_bool(data.get('retainAllPaths'))
        seed = data.get('seed')

        if seed is not None:
            if isinstance(seed, bool):
                return error_response("'seed' must be an integer", 400)
            if isinstance(seed, int):
                pass
            elif isinstance(seed, str) and re.fullmatch(r'-?\d+', seed.strip()):
                seed = int(seed.strip())
            else:
                return error_response("'seed' must be an integer", 400)

        results = batfish_service.get_transfer_bdd_validation(
            nodes=nodes,
            policies=policies,
            retainAllPaths=retain_all_paths,
            seed=seed,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run transfer BDD validation: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/compare-peer-group-policies', methods=['GET', 'POST'])
def compare_peer_group_policies():
    """Compare peer group policies."""
    try:
        data = request.get_json(silent=True) or {}
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot', request.args.get('reference_snapshot')))
        snapshot = data.get('snapshot', request.args.get('snapshot'))

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for comparePeerGroupPolicies", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_peer_group_policies(
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare peer group policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/compare-route-policies', methods=['POST'])
def compare_route_policies():
    """Compare symbolic behavior of two route policies."""
    try:
        data = request.get_json() or {}
        policy = data.get('policy')
        reference_policy = data.get('referencePolicy')
        nodes = normalize_batfish_specifier(data.get('nodes'))
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot'))
        snapshot = data.get('snapshot')

        if not policy:
            return error_response("Missing required 'policy' for compareRoutePolicies", 400)
        if not reference_policy:
            return error_response("Missing required 'referencePolicy' for compareRoutePolicies", 400)
        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for compareRoutePolicies", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_route_policies(
            policy,
            reference_policy,
            nodes,
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/questions', methods=['GET'])
def get_questions():
    """Get list of available Batfish questions"""
    try:
        questions = batfish_service.get_questions()
        return success_response(questions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get questions: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/node-roles', methods=['GET'])
def get_node_roles():
    """Get node role definitions"""
    try:
        roles = batfish_service.get_node_roles()
        return success_response(roles)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get node roles: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/interface-blacklist', methods=['GET'])
def get_interface_blacklist():
    """Get interface blacklist configuration"""
    try:
        blacklist = batfish_service.get_interface_blacklist()
        return success_response(blacklist)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interface blacklist: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/vi-model', methods=['GET'])
def get_vi_model():
    """Get Vendor Independent model"""
    try:
        vi_model = batfish_service.get_vi_model()
        return success_response(vi_model)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VI model: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/search-route-policies', methods=['POST'])
def advanced_search_route_policies():
    """Search route policies"""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes', '.*'))
        action = data.get('action', 'permit')
        policies = normalize_batfish_specifier(data.get('policies'))
        input_constraints = data.get('inputConstraints')
        output_constraints = data.get('outputConstraints')
        per_path = parse_optional_bool(data.get('perPath'))
        path_option = data.get('pathOption')

        results = batfish_service.get_search_route_policies(
            nodes=nodes,
            action=action,
            policies=policies,
            inputConstraints=input_constraints,
            outputConstraints=output_constraints,
            perPath=per_path,
            pathOption=path_option,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to search route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/reduce-reachability', methods=['POST'])
def reduce_reachability():
    """Reduced reachability analysis"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        path_constraints = data.get('pathConstraints')
        actions = data.get('actions')
        max_traces = data.get('maxTraces')
        invert_search = parse_optional_bool(data.get('invertSearch'))
        ignore_filters = parse_optional_bool(data.get('ignoreFilters'))

        flow_traces = batfish_service.get_reachability(
            headers=headers,
            pathConstraints=path_constraints,
            actions=actions,
            maxTraces=max_traces,
            invertSearch=invert_search,
            ignoreFilters=ignore_filters,
        )
        return success_response([f.to_dict() for f in flow_traces])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get reduced reachability: {e}")
        return error_response(str(e), 500)


# ========== Snapshot Management Endpoints ==========
@app.route('/api/snapshots', methods=['GET'])
def list_snapshots():
    """List all available snapshots"""
    try:
        snapshots = snapshot_service.list_snapshots(**get_snapshot_request_context())
        return success_response(snapshots)
    except PermissionError as e:
        return error_response(str(e), 403)
    except Exception as e:
        logger.error(f"Failed to list snapshots: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots', methods=['POST'])
def create_snapshot():
    """
    Create a new empty snapshot

    Request body:
    {
        "name": "snapshot-name"
    }
    """
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return error_response("Missing 'name' in request body", 400)

        name = data['name']
        folder_name = data.get('folder_name')
        snapshot = snapshot_service.create_snapshot(
            name,
            folder_name=folder_name,
            **get_snapshot_creation_context(),
        )

        return success_response(snapshot, "Snapshot created successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to create snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>', methods=['PATCH'])
def update_snapshot(name: str):
    """Update snapshot metadata such as folder classification."""
    try:
        data = request.get_json()
        if data is None or 'folder_name' not in data:
            return error_response("Missing 'folder_name' in request body", 400)

        snapshot = snapshot_service.update_snapshot_metadata(
            name,
            folder_name=data.get('folder_name'),
            **get_snapshot_request_context(),
        )

        return success_response(snapshot, "Snapshot updated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>', methods=['DELETE'])
def delete_snapshot(name: str):
    """Delete a snapshot"""
    try:
        snapshot_service.delete_snapshot(name, **get_snapshot_request_context())

        if config.AUTH_ENABLED and session.get('current_snapshot_name') == name:
            session.pop('current_snapshot_name', None)

        return success_response({"name": name}, "Snapshot deleted successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to delete snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files', methods=['GET'])
def get_snapshot_files(name: str):
    """Get list of files in a snapshot"""
    try:
        files = snapshot_service.get_snapshot_files(name, **get_snapshot_request_context())
        return success_response(files)

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot files: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files', methods=['POST'])
def upload_snapshot_file(name: str):
    """
    Upload a configuration file to a snapshot

    Multipart form data with 'file' field
    """
    try:
        if 'file' not in request.files:
            return error_response("No file provided", 400)

        file = request.files['file']
        if file.filename == '':
            return error_response("No file selected", 400)

        file_info = snapshot_service.upload_file(
            name,
            file,
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "File uploaded successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>/format', methods=['PATCH'])
def update_snapshot_file_format(name: str, filename: str):
    """Update a snapshot file's Batfish configuration format override."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        if 'configuration_format_override' not in data:
            return error_response("Missing 'configuration_format_override' in request body", 400)

        file_info = snapshot_service.update_snapshot_file_format(
            name,
            filename,
            data.get('configuration_format_override'),
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "Snapshot file format updated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot file format: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>', methods=['DELETE'])
def delete_snapshot_file(name: str, filename: str):
    """Delete one uploaded file from a snapshot."""
    try:
        file_info = snapshot_service.delete_snapshot_file(
            name,
            filename,
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "Snapshot file deleted successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to delete snapshot file: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/activate', methods=['POST'])
def activate_snapshot(name: str):
    """
    Activate a snapshot (initialize Batfish with this snapshot)
    """
    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
        result = batfish_service.initialize_network(str(snapshot_path), name)

        if config.AUTH_ENABLED:
            session['current_snapshot_name'] = name

        return success_response(result, f"Snapshot '{name}' activated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        import traceback
        logger.error(f"Failed to activate snapshot: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


# ========== Snapshot Comparison Endpoint ==========
@app.route('/api/snapshots/compare', methods=['POST'])
def compare_snapshots():
    """
    Compare two network snapshots

    Request body:
        {
            "base_snapshot": "snapshot1",
            "comparison_snapshot": "snapshot2"
        }

    Returns:
        Comparison results with nodes, edges, routes, and reachability changes
    """
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required", 400)

        base_snapshot = data.get('base_snapshot')
        comparison_snapshot = data.get('comparison_snapshot')

        if not base_snapshot or not comparison_snapshot:
            return error_response("Both 'base_snapshot' and 'comparison_snapshot' are required", 400)

        snapshot_context = get_snapshot_request_context()
        base_snapshot_path = snapshot_service.get_snapshot_path(base_snapshot, **snapshot_context)
        comparison_snapshot_path = snapshot_service.get_snapshot_path(comparison_snapshot, **snapshot_context)

        # Use existing compare_snapshots method from batfish_service
        result = batfish_service.compare_snapshots(
            base_snapshot,
            comparison_snapshot,
            base_snapshot_path=base_snapshot_path,
            comparison_snapshot_path=comparison_snapshot_path,
        )

        return success_response(result, "Snapshots compared successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to compare snapshots: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


# ========== Layer1 Topology Management Endpoints ==========
@app.route('/api/snapshots/<name>/layer1-topology', methods=['GET'])
def get_snapshot_layer1_topology(name: str):
    """
    Get Layer1 topology configuration for a snapshot

    Returns:
        Layer1 topology data with edges array
    """
    try:
        topology = snapshot_service.get_layer1_topology(name, **get_snapshot_request_context())
        return success_response(topology, "Layer1 topology retrieved successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get Layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/layer1-topology', methods=['PUT'])
def save_snapshot_layer1_topology(name: str):
    """
    Save Layer1 topology configuration for a snapshot

    Request body:
        {
            "edges": [
                {
                    "node1": {"hostname": "router1", "interfaceName": "GigabitEthernet0/0"},
                    "node2": {"hostname": "router2", "interfaceName": "GigabitEthernet0/1"}
                }
            ]
        }

    Returns:
        Save result with metadata
    """
    try:
        topology_data = request.get_json()

        if not topology_data:
            return error_response("Request body is required", 400)

        if 'edges' not in topology_data:
            return error_response("'edges' field is required in request body", 400)

        result = snapshot_service.save_layer1_topology(
            name,
            topology_data,
            **get_snapshot_request_context(),
        )

        reload_active_snapshot_after_layer1_change(name)

        return success_response(result, "Layer1 topology saved successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to save Layer1 topology: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/layer1-topology', methods=['DELETE'])
def delete_snapshot_layer1_topology(name: str):
    """
    Delete Layer1 topology configuration for a snapshot

    Returns:
        Success message
    """
    try:
        snapshot_service.delete_layer1_topology(name, **get_snapshot_request_context())
        reload_active_snapshot_after_layer1_change(name)
        return success_response({"snapshot": name}, "Layer1 topology deleted successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to delete Layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/interfaces', methods=['GET'])
def get_snapshot_interfaces(name: str):
    """
    Get all interfaces for devices in a snapshot

    Returns:
        Dictionary mapping hostnames to interface lists
    """
    try:
        interfaces = snapshot_service.get_snapshot_interfaces(
            name,
            batfish_service,
            **get_snapshot_request_context(),
        )
        return success_response(interfaces, "Snapshot interfaces retrieved successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot interfaces: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


# ========== API Documentation Endpoint ==========
@app.route('/api/endpoints', methods=['GET'])
def list_endpoints():
    """List all available API endpoints"""
    endpoints = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            endpoints.append({
                "path": str(rule),
                "methods": list(rule.methods - {'HEAD', 'OPTIONS'}),
                "endpoint": rule.endpoint
            })

    return success_response(sorted(endpoints, key=lambda x: x['path']))


# ========== Security Headers ==========
if config.AUTH_ENABLED and config.CSRF_MODE == 'double-submit':
    @app.after_request
    def set_enhanced_security_headers(response):
        """
        Enhanced security headers for Double-Submit Cookie Pattern
        Critical for mitigating XSS risks when HttpOnly=False for CSRF tokens
        """
        # Strict Content Security Policy to mitigate XSS
        # Note: Adjust 'unsafe-inline' and 'unsafe-eval' based on your frontend requirements
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Enable browser XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Enforce HTTPS (only in production)
        if config.ENV == 'production':
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )

        # Control referrer information
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy (formerly Feature-Policy)
        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=(), '
            'gyroscope=(), '
            'accelerometer=()'
        )

        return response

# ========== Main ==========
if __name__ == '__main__':
    logger.info(f"Starting Topologix Backend on {config.HOST}:{config.PORT}")
    logger.info(f"Debug mode: {config.DEBUG}")
    logger.info(f"Batfish connection: {config.BATFISH_HOST}:{config.BATFISH_PORT}")
    logger.info(f"Authentication: {'ENABLED' if config.AUTH_ENABLED else 'DISABLED (open access)'}")
    if config.AUTH_ENABLED:
        logger.info("JWT Authentication: ENABLED")
        logger.info("CSRF Protection: ENABLED")
        logger.info("Rate Limiting: ENABLED")
        logger.info("Security Headers: ENABLED")
        logger.warning("Default credentials in use - CHANGE IMMEDIATELY in production!")
    else:
        logger.info("All endpoints are publicly accessible without authentication")

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )
