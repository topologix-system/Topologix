"""JWT authentication and authorization"""
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any, List

import jwt
from flask import request, jsonify, current_app, g
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select

logger = logging.getLogger(__name__)


class TooManyAttemptsError(Exception):
    """Rate limiting exception for login attempts"""
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"Too many attempts, retry after {retry_after}s")


def get_client_ip() -> str:
    """Get real client IP address with validation"""
    import ipaddress

    original_ip = request.headers.get('X-Original-Client-IP')
    if original_ip:
        original_ip = original_ip.strip()
        try:
            ipaddress.ip_address(original_ip)
            logger.debug(f"Client IP determined from X-Original-Client-IP: {original_ip}")
            return original_ip
        except ValueError:
            logger.warning(f"Invalid IP in X-Original-Client-IP: {original_ip}")

    ip = request.remote_addr

    if ip:
        try:
            ipaddress.ip_address(ip)
            logger.debug(f"Client IP determined from request.remote_addr: {ip}")
            return ip
        except ValueError:
            logger.warning(f"Invalid IP format from request.remote_addr: {ip}")

    xff = request.headers.get('X-Forwarded-For')
    if xff:
        first_ip = xff.split(',')[0].strip()
        try:
            ipaddress.ip_address(first_ip)
            logger.warning(f"Client IP determined from X-Forwarded-For fallback: {first_ip}")
            return first_ip
        except ValueError:
            logger.warning(f"Invalid IP in X-Forwarded-For: {first_ip}")

    logger.error("Could not determine client IP, using 0.0.0.0")
    return "0.0.0.0"


# In-memory user database (used only when AUTH_ENABLED=false)
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

def _initialize_passwords():
    """Initialize default passwords for in-memory USERS_DB"""
    import os
    admin_pass = os.getenv('DEV_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
    viewer_pass = os.getenv('DEV_VIEWER_PASSWORD') or secrets.token_urlsafe(16)

    if USERS_DB["admin"]["password_hash"] is None:
        USERS_DB["admin"]["password_hash"] = generate_password_hash(admin_pass)
        if not os.getenv('DEV_ADMIN_PASSWORD'):
            logger.warning("Generated random dev admin password (set DEV_ADMIN_PASSWORD to fix)")
    if USERS_DB["viewer"]["password_hash"] is None:
        USERS_DB["viewer"]["password_hash"] = generate_password_hash(viewer_pass)
        if not os.getenv('DEV_VIEWER_PASSWORD'):
            logger.warning("Generated random dev viewer password (set DEV_VIEWER_PASSWORD to fix)")

_initialize_passwords()


class JWTManager:
    """Manages JWT authentication for the application"""

    def __init__(self, app=None, secret_key: Optional[str] = None):
        """Initialize JWT Manager"""
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = "HS256"

        expires_seconds = 3600  # Default: 1 hour
        if app and hasattr(app, 'config'):
            expires_seconds = app.config.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
        self.access_token_expires = timedelta(seconds=expires_seconds)

        self.refresh_token_expires = timedelta(days=7)
        self.token_blacklist = set()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for JWT"""
        app.jwt_manager = self

        @app.before_request
        def validate_token():
            exempt_endpoints = [
                '/api/health',
                '/api/auth/login',
                '/api/auth/refresh',
                '/api/auth/password-reset-request',
                '/api/auth/password-reset'
            ]

            if request.path in exempt_endpoints or request.method == 'OPTIONS':
                return

            token = self._extract_token()
            if token:
                try:
                    payload = self.decode_token(token)
                    request.jwt_payload = payload
                except jwt.ExpiredSignatureError:
                    logger.warning(f"Expired token attempted from {get_client_ip()}")
                except jwt.InvalidTokenError as e:
                    logger.warning(f"Invalid token attempted from {get_client_ip()}: {e}")

    def generate_tokens(self, user_id: str, username: str, roles: List[str],
                        session_id: Optional[str] = None) -> Dict[str, str]:
        """Generate access and refresh tokens carrying the login session id ("sid")

        "iat" has sub-second precision so it can be compared with the user's password_changed_at.
        """
        now = datetime.now(timezone.utc)
        refresh_jti = secrets.token_urlsafe(16)
        session_id = session_id or refresh_jti

        access_payload = {
            "user_id": user_id,
            "username": username,
            "roles": roles,
            "type": "access",
            "iat": now.timestamp(),
            "exp": now + self.access_token_expires,
            "jti": secrets.token_urlsafe(16),  # JWT ID for revocation
            "sid": session_id
        }

        refresh_payload = {
            "user_id": user_id,
            "type": "refresh",
            "iat": now.timestamp(),
            "exp": now + self.refresh_token_expires,
            "jti": refresh_jti,
            "sid": session_id
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
        """Decode and validate JWT token"""
        if token in self.token_blacklist:
            raise jwt.InvalidTokenError("Token has been revoked")

        try:
            pre_payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_exp": False})
            revocation_ids = [value for value in (pre_payload.get('jti'), pre_payload.get('sid')) if value]
            if revocation_ids:
                from database.session import get_db
                from database.models import RevokedToken
                from sqlalchemy import select
                with next(get_db()) as db:
                    if db.scalars(select(RevokedToken).where(RevokedToken.jti.in_(revocation_ids))).first() is not None:
                        self.token_blacklist.add(token)
                        raise jwt.InvalidTokenError("Token has been revoked")
        except jwt.InvalidTokenError:
            raise
        except Exception:
            pass

        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )

            if "type" not in payload:
                raise jwt.InvalidTokenError("Invalid token structure")

            if current_app.config.get('AUTH_ENABLED', False):
                self._check_token_user(payload)

            return payload

        except jwt.ExpiredSignatureError:
            logger.debug("Token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            raise

    def _check_token_user(self, payload: Dict[str, Any]) -> None:
        """Validate the token's user against the database"""
        user_state = self._load_token_user(payload.get("user_id"))
        if user_state is None:
            raise jwt.InvalidTokenError("Token user no longer exists")
        if not user_state["is_active"]:
            raise jwt.InvalidTokenError("Token user is inactive")

        password_changed_at = user_state["password_changed_at"]
        if password_changed_at is not None and float(payload.get("iat", 0)) < password_changed_at:
            raise jwt.InvalidTokenError("Token was issued before the last password change")

        tokens_invalid_before = user_state["tokens_invalid_before"]
        if tokens_invalid_before is not None and float(payload.get("iat", 0)) < tokens_invalid_before:
            raise jwt.InvalidTokenError("Token was issued before the user's tokens were revoked")

        if payload.get("type") == "access":
            payload["roles"] = user_state["roles"]

    def _load_token_user(self, user_id: Any) -> Optional[Dict[str, Any]]:
        """Load a token user's active flag, token cutoff times and roles"""
        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            return None

        cache = g.setdefault('token_user_cache', {})
        if user_id in cache:
            return cache[user_id]

        from database.session import get_db
        from database.models import User, Role, user_roles

        stmt = (
            select(User.is_active, User.password_changed_at, User.tokens_invalid_before, Role.name)
            .select_from(User)
            .outerjoin(user_roles, user_roles.c.user_id == User.id)
            .outerjoin(Role, Role.id == user_roles.c.role_id)
            .where(User.id == user_id)
        )
        try:
            with next(get_db()) as db:
                rows = db.execute(stmt).all()
        except Exception as e:
            logger.error(f"Failed to load token user {user_id}: {e}")
            raise jwt.InvalidTokenError("Token user could not be verified")

        def to_timestamp(value: Optional[datetime]) -> Optional[float]:
            if value is None:
                return None
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.timestamp()

        user_state = None
        if rows:
            user_state = {
                "is_active": rows[0].is_active,
                "password_changed_at": to_timestamp(rows[0].password_changed_at),
                "tokens_invalid_before": to_timestamp(rows[0].tokens_invalid_before),
                "roles": [row.name for row in rows if row.name is not None],
            }

        cache[user_id] = user_state
        return user_state

    def revoke_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Revoke a token and its login session (in-memory + persistent DB)"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_exp": False})
        except jwt.InvalidTokenError as e:
            logger.warning(f"Ignored revocation of an unverifiable token from {get_client_ip()}: {e}")
            return None

        self.token_blacklist.add(token)
        try:
            jti = payload.get('jti')
            exp = payload.get('exp')
            sid = payload.get('sid')
            revocations = {}
            if jti and exp:
                revocations[jti] = datetime.fromtimestamp(exp, tz=timezone.utc)
            if sid and sid not in revocations:
                revocations[sid] = datetime.now(timezone.utc) + max(
                    self.refresh_token_expires, self.access_token_expires
                )
            if revocations:
                from database.session import get_db
                from database.models import RevokedToken
                with next(get_db()) as db:
                    already_revoked = set(db.scalars(
                        select(RevokedToken.jti).where(RevokedToken.jti.in_(list(revocations)))
                    ))
                    for revoked_id, expires_at in revocations.items():
                        if revoked_id not in already_revoked:
                            db.add(RevokedToken(jti=revoked_id, expires_at=expires_at))
                    db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist token revocation to DB: {e}")
        logger.info(f"Token revoked for {get_client_ip()}")
        return payload

    def _extract_token(self) -> Optional[str]:
        """Extract JWT token from request"""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                scheme, token = auth_header.split(' ', 1)
                if scheme.lower() == 'bearer':
                    return token
            except ValueError:
                pass

        token = request.cookies.get('access_token')
        if token:
            return token

        if request.path.startswith('/api/download/'):
            return request.args.get('token')

        return None

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password"""
        auth_enabled = current_app.config.get('AUTH_ENABLED', False)

        if not auth_enabled:
            return self._authenticate_in_memory(username, password)
        else:
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
        """Apply progressive delay after repeated failed login attempts"""
        threshold = 3
        if attempt_count < threshold:
            return

        effective_count = attempt_count - threshold + 1
        base_delay = min(2 ** (effective_count - 1), 30)
        logger.info(f"Progressive delay: sleeping {base_delay}s for attempt #{attempt_count}")
        time.sleep(base_delay)

    def _check_ip_rate_limit(self, ip_address: str) -> tuple[bool, int]:
        """Check if IP address is rate limited"""
        from database.models import LoginAttempt
        from database.session import get_db

        try:
            max_attempts = current_app.config.get('LOGIN_MAX_ATTEMPTS_PER_IP', 10)
            window_minutes = current_app.config.get('LOGIN_RATE_WINDOW_MINUTES', 15)

            cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

            with next(get_db()) as db:
                recent_attempts = db.query(LoginAttempt).filter(
                    LoginAttempt.ip_address == ip_address,
                    LoginAttempt.attempt_time > cutoff_time,
                    LoginAttempt.success == False
                ).count()

                if recent_attempts >= max_attempts:
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
        """Record a login attempt"""
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

    def _authenticate_database(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate against database (AUTH_ENABLED=true)"""
        from database.models import User
        from database.session import get_db

        ip_address = get_client_ip()

        try:
            with next(get_db()) as db:
                stmt = select(User).where(User.username == username)
                user = db.scalar(stmt)

                if not user:
                    logger.warning(f"Login attempt for non-existent user {username} from {ip_address}")
                    self._record_login_attempt(ip_address, username, False)
                    return None

                if user.account_locked_until:
                    locked_until = user.account_locked_until
                    if locked_until.tzinfo is None:
                        locked_until = locked_until.replace(tzinfo=timezone.utc)

                    now = datetime.now(timezone.utc)
                    if now < locked_until:
                        logger.warning(
                            f"Login attempt for locked account {username} from {ip_address} "
                            f"(locked until {user.account_locked_until})"
                        )
                        self._record_login_attempt(ip_address, username, False)
                        return None
                    else:
                        user.account_locked_until = None
                        user.failed_login_attempts = 0

                if not user.is_active:
                    logger.warning(f"Login attempt for inactive account {username} from {ip_address}")
                    self._record_login_attempt(ip_address, username, False)
                    return None

                # Apply progressive delay BEFORE password verification
                if user.failed_login_attempts > 0:
                    self._apply_progressive_delay(user.failed_login_attempts)

                if not user.check_password(password):
                    user.failed_login_attempts += 1
                    logger.warning(
                        f"Failed login attempt for user {username} from {ip_address} "
                        f"(attempt {user.failed_login_attempts})"
                    )

                    lockout_threshold = current_app.config.get('ACCOUNT_LOCKOUT_THRESHOLD', 5)
                    lockout_duration_minutes = current_app.config.get('LOGIN_LOCKOUT_DURATION_MINUTES', 30)

                    if user.failed_login_attempts >= lockout_threshold:
                        user.account_locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_duration_minutes)
                        logger.warning(
                            f"Account {username} locked for {lockout_duration_minutes} minutes "
                            f"after {lockout_threshold} failed attempts"
                        )

                    db.commit()

                    self._record_login_attempt(ip_address, username, False)
                    return None

                user.failed_login_attempts = 0
                user.account_locked_until = None
                user.last_login_at = datetime.now(timezone.utc)
                user.last_login_ip = ip_address
                db.commit()

                logger.info(f"Successful database login for user {username} from {ip_address}")

                self._record_login_attempt(ip_address, username, True)

                return {
                    "id": user.id,
                    "username": user.username,
                    "roles": [role.name for role in user.roles],
                    "email": user.email
                }

        except Exception as e:
            logger.error(f"Database authentication error for user {username}: {e}")
            self._record_login_attempt(ip_address, username, False)
            return None


def require_auth(f):
    """Decorator to require authentication for an endpoint"""
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
    """Decorator to require specific roles for an endpoint"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user_roles = request.jwt_payload.get("roles", [])

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
    """Get current authenticated user from request context"""
    if hasattr(request, 'jwt_payload'):
        return {
            "id": request.jwt_payload.get("user_id"),
            "username": request.jwt_payload.get("username"),
            "roles": request.jwt_payload.get("roles", [])
        }
    return None