"""Cross-Site Request Forgery (CSRF) protection implementation"""
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
        """Initialize CSRF Protection"""
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.token_header_name = 'X-CSRF-Token'
        self.token_form_field = 'csrf_token'
        self.cookie_name = 'csrf_token'
        self.exempt_methods = {'GET', 'HEAD', 'OPTIONS', 'TRACE'}
        self.exempt_endpoints = {
            '/api/health',
            '/api/auth/login',
            '/api/auth/refresh',
            '/api/auth/password-reset-request',  # Public endpoint for requesting password reset
            '/api/auth/password-reset',  # Public endpoint for resetting password
            '/api/endpoints',
            '/api/users'
        }

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for CSRF protection"""
        app.csrf = self

        @app.before_request
        def csrf_protect():
            if request.method in self.exempt_methods:
                return

            if request.path in self.exempt_endpoints:
                return

            if request.method == 'OPTIONS':
                return

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
        """Generate a new CSRF token"""
        token = secrets.token_urlsafe(32)

        session['csrf_token'] = token

        signed_token = self._sign_token(token)

        logger.debug(f"Generated CSRF token for {request.remote_addr}")
        return signed_token

    def _sign_token(self, token: str) -> str:
        """Sign a CSRF token with the secret key"""
        signature = hmac.new(
            self.secret_key.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{token}.{signature}"

    def _verify_signature(self, signed_token: str) -> Optional[str]:
        """Verify the signature of a signed token"""
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
        """Validate CSRF token from request"""
        request_token = self._get_csrf_token_from_request()
        if not request_token:
            logger.debug("No CSRF token found in request")
            return False

        token = self._verify_signature(request_token)
        if not token:
            logger.debug("Invalid CSRF token signature")
            return False

        session_token = session.get('csrf_token')
        if not session_token:
            logger.debug("No CSRF token in session")
            return False

        if not hmac.compare_digest(token, session_token):
            logger.debug("CSRF token mismatch")
            return False

        return True

    def _get_csrf_token_from_request(self) -> Optional[str]:
        """Extract CSRF token from request"""
        token = request.headers.get(self.token_header_name)
        if token:
            return token

        if request.form:
            token = request.form.get(self.token_form_field)
            if token:
                return token

        if request.is_json and isinstance(request.get_json(silent=True), dict):
            token = request.get_json(silent=True).get(self.token_form_field)
            if token:
                return token

        token = request.cookies.get(self.cookie_name)
        if token:
            return token

        return None

    def exempt(self, f):
        """Decorator that sets request.csrf_exempt before calling the view"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            request.csrf_exempt = True
            return f(*args, **kwargs)

        return decorated_function


def csrf_exempt(f):
    """Decorator that sets request.csrf_exempt before calling the view"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request.csrf_exempt = True
        return f(*args, **kwargs)

    return decorated_function


def require_csrf_token(f):
    """Decorator to explicitly require CSRF token validation"""
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