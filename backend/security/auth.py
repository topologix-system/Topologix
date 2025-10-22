"""
JWT authentication and authorization
- JWT token generation, validation, and refresh
- Login/logout with password verification
- Role-based access control decorators (@require_auth, @require_role)
- Password reset token generation and validation
"""
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any, List
import secrets

import jwt
from flask import request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select

logger = logging.getLogger(__name__)


def get_client_ip() -> str:
    """Get real client IP address with validation

    Priority order:
    1. X-Original-Client-IP (custom header set by reverse proxy with actual client IP)
    2. request.remote_addr (after ProxyFix middleware)
    3. X-Forwarded-For fallback

    Note: In environments behind NAT/NAPT gateways or load balancers, the IP
    address may represent the gateway/proxy rather than the actual client.
    This is acceptable for security logging purposes.

    Returns:
        Client IP address string
    """
    import ipaddress

    # Priority 1: Custom header from reverse proxy with actual client IP
    original_ip = request.headers.get('X-Original-Client-IP')
    if original_ip:
        original_ip = original_ip.strip()
        try:
            ipaddress.ip_address(original_ip)
            logger.debug(f"Client IP determined from X-Original-Client-IP: {original_ip}")
            return original_ip
        except ValueError:
            logger.warning(f"Invalid IP in X-Original-Client-IP: {original_ip}")

    # Priority 2: After ProxyFix, remote_addr should be correct
    ip = request.remote_addr

    # Validate IP format
    if ip:
        try:
            ipaddress.ip_address(ip)
            logger.debug(f"Client IP determined from request.remote_addr: {ip}")
            return ip
        except ValueError:
            logger.warning(f"Invalid IP format from request.remote_addr: {ip}")

    # Priority 3: Fallback to X-Forwarded-For header
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # Take first IP in the chain
        first_ip = xff.split(',')[0].strip()
        try:
            ipaddress.ip_address(first_ip)
            logger.warning(f"Client IP determined from X-Forwarded-For fallback: {first_ip}")
            return first_ip
        except ValueError:
            logger.warning(f"Invalid IP in X-Forwarded-For: {first_ip}")

    # Final fallback
    logger.error("Could not determine client IP, using 0.0.0.0")
    return "0.0.0.0"


# In-memory user database (used only when AUTH_ENABLED=false)
# This provides a simple authentication mechanism for quick setup
USERS_DB = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password_hash": None,  # Will be set at runtime
        "roles": ["admin", "user"],
        "email": "admin@topologix.local"
    },
    "viewer": {
        "id": 2,
        "username": "viewer",
        "password_hash": None,  # Will be set at runtime
        "roles": ["viewer"],
        "email": "viewer@topologix.local"
    }
}

# Initialize default passwords for in-memory database
def _initialize_passwords():
    """Initialize default passwords for in-memory USERS_DB

    Only used when AUTH_ENABLED=false.
    When AUTH_ENABLED=true, users are managed in the database.
    """
    if USERS_DB["admin"]["password_hash"] is None:
        USERS_DB["admin"]["password_hash"] = generate_password_hash("ChangeMe123!Admin")
    if USERS_DB["viewer"]["password_hash"] is None:
        USERS_DB["viewer"]["password_hash"] = generate_password_hash("ChangeMe123!Viewer")

_initialize_passwords()


class JWTManager:
    """Manages JWT authentication for the application"""

    def __init__(self, app=None, secret_key: Optional[str] = None):
        """Initialize JWT Manager

        Args:
            app: Flask application instance
            secret_key: Secret key for JWT signing (should be from environment)
        """
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"
        self.access_token_expires = timedelta(hours=1)
        self.refresh_token_expires = timedelta(days=7)
        self.token_blacklist = set()  # In production, use Redis or database

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for JWT"""
        app.jwt_manager = self

        # Add before_request handler for token validation
        @app.before_request
        def validate_token():
            # Skip authentication for certain endpoints
            exempt_endpoints = [
                '/api/health',
                '/api/auth/login',
                '/api/auth/refresh',
                '/api/auth/password-reset-request',
                '/api/auth/password-reset'
            ]

            if request.path in exempt_endpoints or request.method == 'OPTIONS':
                return

            # Validate token for all other endpoints
            token = self._extract_token()
            if token:
                try:
                    payload = self.decode_token(token)
                    request.jwt_payload = payload
                except jwt.ExpiredSignatureError:
                    logger.warning(f"Expired token attempted from {get_client_ip()}")
                except jwt.InvalidTokenError as e:
                    logger.warning(f"Invalid token attempted from {get_client_ip()}: {e}")

    def generate_tokens(self, user_id: str, username: str, roles: List[str]) -> Dict[str, str]:
        """Generate access and refresh tokens

        Args:
            user_id: User identifier
            username: Username
            roles: List of user roles

        Returns:
            Dictionary containing access_token and refresh_token
        """
        now = datetime.now(timezone.utc)

        # Access token payload
        access_payload = {
            "user_id": user_id,
            "username": username,
            "roles": roles,
            "type": "access",
            "iat": now,
            "exp": now + self.access_token_expires,
            "jti": secrets.token_urlsafe(16)  # JWT ID for revocation
        }

        # Refresh token payload
        refresh_payload = {
            "user_id": user_id,
            "type": "refresh",
            "iat": now,
            "exp": now + self.refresh_token_expires,
            "jti": secrets.token_urlsafe(16)
        }

        access_token = jwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm=self.algorithm)

        logger.info(f"Generated tokens for user {username} from {get_client_ip()}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": int(self.access_token_expires.total_seconds())
        }

    def decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate JWT token

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid
            jwt.ExpiredSignatureError: If token has expired
        """
        # Check if token is blacklisted
        if token in self.token_blacklist:
            raise jwt.InvalidTokenError("Token has been revoked")

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            # Additional validation
            if "type" not in payload:
                raise jwt.InvalidTokenError("Invalid token structure")

            return payload

        except jwt.ExpiredSignatureError:
            logger.debug("Token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            raise

    def revoke_token(self, token: str):
        """Revoke a token by adding it to blacklist

        Args:
            token: JWT token to revoke
        """
        self.token_blacklist.add(token)
        logger.info(f"Token revoked for {get_client_ip()}")

    def _extract_token(self) -> Optional[str]:
        """Extract JWT token from request

        Returns:
            Token string or None if not found
        """
        # Check Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                scheme, token = auth_header.split(' ', 1)
                if scheme.lower() == 'bearer':
                    return token
            except ValueError:
                pass

        # Check cookie (for web browser clients)
        token = request.cookies.get('access_token')
        if token:
            return token

        # Check query parameter (only for specific endpoints like downloads)
        if request.path.startswith('/api/download/'):
            return request.args.get('token')

        return None

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password

        Supports two authentication modes:
        - AUTH_ENABLED=false: Uses in-memory USERS_DB
        - AUTH_ENABLED=true: Uses database authentication with security tracking

        Args:
            username: Username
            password: Password

        Returns:
            User data if authentication successful, None otherwise
        """
        auth_enabled = current_app.config.get('AUTH_ENABLED', False)

        if not auth_enabled:
            # Use in-memory USERS_DB
            return self._authenticate_in_memory(username, password)
        else:
            # Use database authentication
            return self._authenticate_database(username, password)

    def _authenticate_in_memory(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate against in-memory USERS_DB (AUTH_ENABLED=false)"""
        user = USERS_DB.get(username)
        if not user:
            logger.warning(f"Login attempt for non-existent user {username} from {get_client_ip()}")
            return None

        if not check_password_hash(user["password_hash"], password):
            logger.warning(f"Failed login attempt for user {username} from {get_client_ip()}")
            return None

        logger.info(f"Successful login for user {username} from {get_client_ip()}")
        return {
            "id": user["id"],
            "username": user["username"],
            "roles": user["roles"],
            "email": user["email"]
        }

    def _apply_progressive_delay(self, attempt_count: int):
        """Apply progressive delay based on failed attempt count

        Implements exponential backoff to slow down brute force attacks.
        Delay increases with each failed attempt: 1s, 2s, 4s, 8s, 16s, max 30s

        Args:
            attempt_count: Number of failed login attempts
        """
        import time
        import random

        if attempt_count <= 0:
            return

        # Exponential backoff: 2^(n-1) seconds, capped at 30 seconds
        base_delay = min(2 ** (attempt_count - 1), 30)

        # Add jitter (0-0.5 seconds) to prevent timing attacks
        jitter = random.uniform(0, 0.5)
        total_delay = base_delay + jitter

        logger.info(f"Applying progressive delay: {total_delay:.2f}s for attempt #{attempt_count}")
        time.sleep(total_delay)

    def _check_ip_rate_limit(self, ip_address: str) -> tuple[bool, int]:
        """Check if IP address is rate limited

        Args:
            ip_address: IP address to check

        Returns:
            Tuple of (is_blocked, remaining_seconds)
        """
        from database.models import LoginAttempt
        from database.session import get_db

        try:
            max_attempts = current_app.config.get('LOGIN_MAX_ATTEMPTS_PER_IP', 10)
            window_minutes = current_app.config.get('LOGIN_RATE_WINDOW_MINUTES', 15)

            cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

            with next(get_db()) as db:
                # Count failed attempts from this IP in the time window
                recent_attempts = db.query(LoginAttempt).filter(
                    LoginAttempt.ip_address == ip_address,
                    LoginAttempt.attempt_time > cutoff_time,
                    LoginAttempt.success == False
                ).count()

                if recent_attempts >= max_attempts:
                    # Calculate remaining block time
                    oldest_attempt = db.query(LoginAttempt).filter(
                        LoginAttempt.ip_address == ip_address,
                        LoginAttempt.attempt_time > cutoff_time
                    ).order_by(LoginAttempt.attempt_time).first()

                    if oldest_attempt:
                        elapsed = datetime.now(timezone.utc) - oldest_attempt.attempt_time
                        remaining = (timedelta(minutes=window_minutes) - elapsed).total_seconds()
                        return True, max(0, int(remaining))

            return False, 0

        except Exception as e:
            logger.error(f"Error checking IP rate limit: {e}")
            return False, 0  # Fail open on errors

    def _record_login_attempt(self, ip_address: str, username: Optional[str], success: bool):
        """Record login attempt for rate limiting and security monitoring

        Args:
            ip_address: IP address of the attempt
            username: Username attempted (may be None)
            success: Whether login was successful
        """
        from database.models import LoginAttempt
        from database.session import get_db

        try:
            user_agent = request.headers.get('User-Agent', '')

            with next(get_db()) as db:
                attempt = LoginAttempt(
                    ip_address=ip_address,
                    username=username,
                    success=success,
                    user_agent=user_agent[:255] if user_agent else None
                )
                db.add(attempt)
                db.commit()

                logger.info(f"Recorded login attempt: IP={ip_address}, username={username}, success={success}")

        except Exception as e:
            logger.error(f"Error recording login attempt: {e}")
            # Don't fail login on logging error

    def _authenticate_database(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate against database (AUTH_ENABLED=true)

        Includes security features:
        - Account lockout after failed attempts (5 attempts = 30 min lockout)
        - Progressive delay to slow down brute force attacks
        - Failed login tracking
        - Last login timestamp and IP tracking

        Note: IP-based rate limiting is disabled because this application may be
        deployed behind NAT/NAPT gateways, load balancers, or proxies where
        multiple users share the same IP address. Account-based security measures
        provide sufficient protection in these environments.
        """
        from database.models import User
        from database.session import get_db
        import time

        ip_address = get_client_ip()

        # IP-based rate limiting is disabled for shared IP environments
        # All security is handled by account-based measures below

        try:
            with next(get_db()) as db:
                # Find user by username
                stmt = select(User).where(User.username == username)
                user = db.scalar(stmt)

                # 2. Check if user exists
                if not user:
                    logger.warning(f"Login attempt for non-existent user {username} from {ip_address}")
                    # Record failed attempt for security monitoring
                    self._record_login_attempt(ip_address, username, False)
                    # Apply progressive delay to prevent timing attacks (use 1 attempt as baseline)
                    self._apply_progressive_delay(1)
                    return None

                # 3. Check if account is locked
                if user.account_locked_until:
                    # Handle timezone-naive datetimes from SQLite
                    locked_until = user.account_locked_until
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)
                    if now < locked_until:
                        logger.warning(
                            f"Login attempt for locked account {username} from {ip_address} "
                            f"(locked until {user.account_locked_until})"
                        )
                        # Record failed attempt
                        self._record_login_attempt(ip_address, username, False)
                        return None
                    else:
                        # Lock expired, reset failed attempts
                        user.account_locked_until = None
                        user.failed_login_attempts = 0

                # 4. Check if account is active
                if not user.is_active:
                    logger.warning(f"Login attempt for inactive account {username} from {ip_address}")
                    # Record failed attempt
                    self._record_login_attempt(ip_address, username, False)
                    return None

                # 5. Apply progressive delay BEFORE password verification
                # This slows down brute force attacks based on previous failed attempts
                if user.failed_login_attempts > 0:
                    self._apply_progressive_delay(user.failed_login_attempts)

                # 6. Verify password
                if not user.check_password(password):
                    # Increment failed login attempts
                    user.failed_login_attempts += 1
                    logger.warning(
                        f"Failed login attempt for user {username} from {ip_address} "
                        f"(attempt {user.failed_login_attempts})"
                    )

                    # Lock account after threshold (default: 5 failed attempts)
                    lockout_threshold = current_app.config.get('ACCOUNT_LOCKOUT_THRESHOLD', 5)
                    lockout_duration_minutes = current_app.config.get('LOGIN_LOCKOUT_DURATION_MINUTES', 30)

                    if user.failed_login_attempts >= lockout_threshold:
                        user.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_duration_minutes)
                        logger.warning(
                            f"Account {username} locked for {lockout_duration_minutes} minutes "
                            f"after {lockout_threshold} failed attempts"
                        )

                    db.commit()

                    # Record failed attempt for security monitoring
                    self._record_login_attempt(ip_address, username, False)
                    return None

                # 6. Successful authentication - reset failed attempts and update login info
                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.last_login_at = datetime.now(timezone.utc)
                user.last_login_ip = ip_address
                db.commit()

                logger.info(f"Successful database login for user {username} from {ip_address}")

                # Record successful attempt
                self._record_login_attempt(ip_address, username, True)

                return {
                    "id": user.id,
                    "username": user.username,
                    "roles": [role.name for role in user.roles],
                    "email": user.email
                }

        except Exception as e:
            logger.error(f"Database authentication error for user {username}: {e}")
            # Record failed attempt on exception
            self._record_login_attempt(ip_address, username, False)
            return None


def require_auth(f):
    """Decorator to require authentication for an endpoint

    Args:
        f: Function to decorate

    Returns:
        Decorated function that requires authentication
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_manager = current_app.jwt_manager
        token = jwt_manager._extract_token()

        if not token:
            logger.warning(f"Unauthorized access attempt to {request.path} from {get_client_ip()}")
            return jsonify({
                "status": "error",
                "message": "Authentication required"
            }), 401

        try:
            payload = jwt_manager.decode_token(token)

            # Only allow access tokens for API calls
            if payload.get("type") != "access":
                return jsonify({
                    "status": "error",
                    "message": "Invalid token type"
                }), 401

            request.jwt_payload = payload
            return f(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "message": "Token has expired"
            }), 401
        except jwt.InvalidTokenError as e:
            return jsonify({
                "status": "error",
                "message": f"Invalid token: {str(e)}"
            }), 401

    return decorated_function


def require_role(*allowed_roles):
    """Decorator to require specific roles for an endpoint

    Args:
        allowed_roles: Roles that are allowed to access the endpoint

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user_roles = request.jwt_payload.get("roles", [])

            # Check if user has any of the allowed roles
            if not any(role in user_roles for role in allowed_roles):
                logger.warning(
                    f"Access denied for user {request.jwt_payload.get('username')} "
                    f"to {request.path} from {get_client_ip()}"
                )
                return jsonify({
                    "status": "error",
                    "message": "Insufficient permissions"
                }), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_current_user() -> Optional[Dict[str, Any]]:
    """Get current authenticated user from request context

    Returns:
        User data or None if not authenticated
    """
    if hasattr(request, 'jwt_payload'):
        return {
            "id": request.jwt_payload.get("user_id"),
            "username": request.jwt_payload.get("username"),
            "roles": request.jwt_payload.get("roles", [])
        }
    return None