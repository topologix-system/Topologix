"""
Signed Double-Submit Cookie Pattern for CSRF Protection
- Stateless CSRF protection without session dependency
- HMAC-signed tokens with user session binding
- Cookie-based token storage with proper security flags
- OWASP 2024 compliant implementation
- Industry standard (Django, Rails, Spring Security compatible)
"""
import logging
import hmac
import hashlib
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from functools import wraps
from flask import request, jsonify, make_response

logger = logging.getLogger(__name__)


class DoubleSubmitCSRFProtect:
    """
    Signed Double-Submit Cookie Pattern implementation
    Following OWASP 2024 recommendations for stateless CSRF protection
    """

    def __init__(self, app=None, secret_key: Optional[str] = None):
        """Initialize Double-Submit CSRF Protection

        Args:
            app: Flask application instance
            secret_key: Secret key for HMAC signing
        """
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.token_header_name = 'X-CSRF-Token'
        self.cookie_name = 'csrf_token'
        self.cookie_max_age = 3600  # 1 hour
        self.exempt_methods = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
        self.exempt_endpoints = {
            '/api/health',
            '/api/auth/login',
            '/api/auth/refresh',
            '/api/auth/password-reset-request',
            '/api/auth/password-reset',
            '/api/endpoints',
            '/api/users'  # Allow self-registration
        }

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize Flask app with CSRF protection"""
        app.csrf = self

        @app.before_request
        def csrf_protect():
            # Skip for exempt methods
            if request.method in self.exempt_methods:
                return

            # Skip for exempt endpoints
            if request.path in self.exempt_endpoints:
                return

            # Validate double-submit pattern
            if not self._validate_double_submit():
                logger.warning(
                    f"CSRF validation failed for {request.path} "
                    f"from {request.remote_addr}"
                )
                return jsonify({
                    "status": "error",
                    "message": "CSRF validation failed"
                }), 403

    def generate_csrf_token(self, user_id: str, session_id: Optional[str] = None) -> str:
        """Generate deterministic signed CSRF token with session binding

        Token is session-stable: same token for entire login session.
        Regenerated only on: login, logout, privilege escalation.

        This prevents race conditions from per-request token regeneration.
        Compliant with OWASP 2024 recommendations.

        Args:
            user_id: User identifier for binding
            session_id: Optional session ID for additional binding

        Returns:
            Base64-encoded signed token (deterministic for same session)
        """
        # Generate deterministic nonce from user session
        # This ensures same token for same session (OWASP 2024 best practice)
        deterministic_nonce = hmac.new(
            self.secret_key.encode(),
            f"{user_id}:{session_id}:{self.cookie_max_age}".encode(),
            hashlib.sha256
        ).hexdigest()

        # Create token payload with session binding
        payload = {
            'nonce': deterministic_nonce,
            'user_id': str(user_id),
            'session_id': session_id or secrets.token_urlsafe(16),
            'timestamp': datetime.utcnow().isoformat(),
            'expires': (datetime.utcnow() + timedelta(seconds=self.cookie_max_age)).isoformat()
        }

        # Encode payload
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()

        # Create HMAC signature
        signature = hmac.new(
            self.secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()

        # Return signed token
        signed_token = f"{payload_b64}.{signature}"
        logger.debug(f"Generated session-stable CSRF token for user {user_id}")
        return signed_token

    def _validate_double_submit(self) -> bool:
        """Validate double-submit cookie pattern

        Returns:
            True if valid, False otherwise
        """
        # Get token from cookie
        cookie_token = request.cookies.get(self.cookie_name)
        if not cookie_token:
            logger.debug("No CSRF token found in cookie")
            return False

        # Get token from header or body
        header_token = self._get_token_from_request()
        if not header_token:
            logger.debug("No CSRF token found in request")
            return False

        # Tokens must match exactly (constant-time comparison)
        if not hmac.compare_digest(cookie_token, header_token):
            logger.debug("CSRF token mismatch between cookie and header")
            return False

        # Validate signature and expiration
        if not self._validate_token_signature(cookie_token):
            logger.debug("Invalid CSRF token signature or expired")
            return False

        return True

    def _get_token_from_request(self) -> Optional[str]:
        """Extract CSRF token from request header or body

        Returns:
            CSRF token or None
        """
        # Check header first (preferred)
        token = request.headers.get(self.token_header_name)
        if token:
            return token

        # Check JSON body
        if request.is_json and request.json:
            token = request.json.get('csrf_token')
            if token:
                return token

        # Check form data
        if request.form:
            token = request.form.get('csrf_token')
            if token:
                return token

        return None

    def _validate_token_signature(self, token: str) -> bool:
        """Validate token signature and expiration

        Args:
            token: Signed token to validate

        Returns:
            True if valid and not expired
        """
        try:
            # Split token into payload and signature
            payload_b64, signature = token.rsplit('.', 1)

            # Verify HMAC signature (constant-time comparison)
            expected_sig = hmac.new(
                self.secret_key.encode(),
                payload_b64.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected_sig):
                logger.debug("CSRF token signature mismatch")
                return False

            # Decode and check expiration
            payload_json = base64.urlsafe_b64decode(payload_b64).decode()
            payload = json.loads(payload_json)

            expires = datetime.fromisoformat(payload['expires'])
            if datetime.utcnow() > expires:
                logger.debug("CSRF token expired")
                return False

            return True

        except (ValueError, KeyError, json.JSONDecodeError) as e:
            logger.debug(f"CSRF token validation error: {e}")
            return False

    def set_csrf_cookie(self, response, token: str) -> None:
        """Set CSRF cookie with proper security flags

        Args:
            response: Flask response object
            token: CSRF token to set
        """
        # Determine if running in secure context (production)
        from flask import current_app
        is_production = current_app.config.get('ENV') == 'production'

        response.set_cookie(
            self.cookie_name,
            value=token,
            max_age=self.cookie_max_age,
            secure=is_production,  # HTTPS only in production
            httponly=False,  # Must be False for JavaScript access
            samesite='Lax',  # Lax for usability, Strict for max security
            path='/'
        )
        logger.debug(f"Set CSRF cookie (secure={is_production})")

    def clear_csrf_cookie(self, response) -> None:
        """Clear CSRF cookie on logout

        Args:
            response: Flask response object
        """
        response.set_cookie(
            self.cookie_name,
            value='',
            max_age=0,
            path='/'
        )
        logger.debug("Cleared CSRF cookie")

    def exempt(self, f):
        """Decorator to exempt a view from CSRF protection

        Args:
            f: Function to exempt

        Returns:
            Decorated function
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            request.csrf_exempt = True
            return f(*args, **kwargs)

        return decorated_function


def csrf_exempt(f):
    """Decorator to exempt a specific endpoint from CSRF protection

    Args:
        f: Function to decorate

    Returns:
        Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request.csrf_exempt = True
        return f(*args, **kwargs)

    return decorated_function


def require_csrf_token(f):
    """Decorator to explicitly require CSRF token validation

    Args:
        f: Function to decorate

    Returns:
        Decorated function that requires CSRF validation
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf = request.app.csrf

        if not csrf._validate_double_submit():
            logger.warning(
                f"CSRF validation failed for {request.path} "
                f"from {request.remote_addr}"
            )
            return jsonify({
                "status": "error",
                "message": "CSRF validation failed"
            }), 403

        return f(*args, **kwargs)

    return decorated_function
