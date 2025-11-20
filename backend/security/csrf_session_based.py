"""
Cross-Site Request Forgery (CSRF) protection implementation
- CSRFProtect class for Flask application integration
- Token generation with HMAC-SHA256 signing
- Token validation from headers, forms, JSON, or cookies
- Session-based token storage
- Exempt methods: GET, HEAD, OPTIONS, TRACE
- Exempt endpoints: health, login, refresh, password reset, public registration
- @csrf_exempt decorator for manual exemption
- @require_csrf_token decorator for explicit protection
- Automatic before_request validation hook
"""
import logging
import secrets
import hmac
import hashlib
from functools import wraps
from typing import Optional
from flask import request, jsonify, session

logger = logging.getLogger(__name__)


class CSRFProtect:
    """CSRF Protection implementation for Flask"""

    def __init__(self, app=None, secret_key: Optional[str] = None):
        """Initialize CSRF Protection

        Args:
            app: Flask application instance
            secret_key: Secret key for CSRF token generation
        """
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.token_header_name = 'X-CSRF-Token'
        self.token_form_field = 'csrf_token'
        self.cookie_name = 'csrf_token'
        self.exempt_methods = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
        self.exempt_endpoints = {
            '/api/health',
            '/api/auth/login',  # Login needs special handling
            '/api/auth/refresh',  # Token refresh doesn't need CSRF
            '/api/auth/password-reset-request',  # Public endpoint for requesting password reset
            '/api/auth/password-reset',  # Public endpoint for resetting password
            '/api/endpoints',
            '/api/users'  # Allow self-registration without CSRF (authenticated requests from frontend will have CSRF)
        }

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for CSRF protection"""
        app.csrf = self

        # Session cookie configuration is managed by app.py from config.py

        # Add before_request handler
        @app.before_request
        def csrf_protect():
            # Skip CSRF check for exempt methods
            if request.method in self.exempt_methods:
                return

            # Skip CSRF check for exempt endpoints
            if request.path in self.exempt_endpoints:
                return

            # Skip for OPTIONS requests (CORS preflight)
            if request.method == 'OPTIONS':
                return

            # Validate CSRF token
            if not self._validate_csrf_token():
                logger.warning(
                    f"CSRF validation failed for {request.path} "
                    f"from {request.remote_addr}"
                )
                return jsonify({
                    "status": "error",
                    "message": "CSRF validation failed"
                }), 403

    def generate_csrf_token(self) -> str:
        """Generate a new CSRF token

        Returns:
            CSRF token string
        """
        # Generate random token
        token = secrets.token_urlsafe(32)

        # Store in session
        session['csrf_token'] = token

        # Sign the token with secret key
        signed_token = self._sign_token(token)

        logger.debug(f"Generated CSRF token for {request.remote_addr}")
        return signed_token

    def _sign_token(self, token: str) -> str:
        """Sign a CSRF token with the secret key

        Args:
            token: Token to sign

        Returns:
            Signed token string
        """
        signature = hmac.new(
            self.secret_key.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{token}.{signature}"

    def _verify_signature(self, signed_token: str) -> Optional[str]:
        """Verify the signature of a signed token

        Args:
            signed_token: Signed token string

        Returns:
            Original token if signature is valid, None otherwise
        """
        try:
            token, signature = signed_token.rsplit('.', 1)
            expected_signature = hmac.new(
                self.secret_key.encode(),
                token.encode(),
                hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(signature, expected_signature):
                return token
            return None
        except ValueError:
            return None

    def _validate_csrf_token(self) -> bool:
        """Validate CSRF token from request

        Returns:
            True if token is valid, False otherwise
        """
        # Get token from request
        request_token = self._get_csrf_token_from_request()
        if not request_token:
            logger.debug("No CSRF token found in request")
            return False

        # Verify signature
        token = self._verify_signature(request_token)
        if not token:
            logger.debug("Invalid CSRF token signature")
            return False

        # Get session token
        session_token = session.get('csrf_token')
        if not session_token:
            logger.debug("No CSRF token in session")
            return False

        # Compare tokens
        if not hmac.compare_digest(token, session_token):
            logger.debug("CSRF token mismatch")
            return False

        return True

    def _get_csrf_token_from_request(self) -> Optional[str]:
        """Extract CSRF token from request

        Returns:
            CSRF token or None if not found
        """
        # Check header first (preferred for AJAX requests)
        token = request.headers.get(self.token_header_name)
        if token:
            return token

        # Check form data
        if request.form:
            token = request.form.get(self.token_form_field)
            if token:
                return token

        # Check JSON data
        if request.is_json and request.json:
            token = request.json.get(self.token_form_field)
            if token:
                return token

        # Check cookie (for same-origin requests)
        token = request.cookies.get(self.cookie_name)
        if token:
            return token

        return None

    def exempt(self, f):
        """Decorator to exempt a view from CSRF protection

        Args:
            f: Function to exempt

        Returns:
            Decorated function
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Add marker to indicate CSRF exemption
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

        if not csrf._validate_csrf_token():
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
