"""HTTP security headers management for Flask responses"""
import logging
import os
from flask import Response

logger = logging.getLogger(__name__)


class SecurityHeaders:
    """Manages security headers for HTTP responses"""

    def __init__(self, app=None):
        """Initialize Security Headers"""
        flask_env = os.getenv('FLASK_ENV', 'production')

        if flask_env == 'development':
            connect_src = "'self' http://localhost:* ws://localhost:*"
            logger.info("CSP configured for development environment (localhost connections allowed)")
        else:
            connect_src = "'self'"
            logger.info("CSP configured for production environment (localhost connections restricted)")

        self.headers = {
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "img-src 'self' data: https:; "
                f"connect-src {connect_src}; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "base-uri 'self'; "
                "object-src 'none'"
            ),
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': (
                'geolocation=(), microphone=(), camera=(), '
                'payment=(), usb=(), magnetometer=(), '
                'accelerometer=(), gyroscope=()'
            ),
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0'
        }

        self.hsts_header = (
            'max-age=31536000; includeSubDomains; preload'
        )

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application for security headers"""
        @app.after_request
        def add_security_headers(response: Response) -> Response:
            """Add security headers to every response"""
            for header, value in self.headers.items():
                if header in ['Cache-Control', 'Pragma', 'Expires']:
                    if response.mimetype and (
                        'image' in response.mimetype or
                        'css' in response.mimetype or
                        'javascript' in response.mimetype
                    ):
                        continue
                response.headers[header] = value

            response.headers['Strict-Transport-Security'] = self.hsts_header

            # CORS headers are managed by Flask-CORS middleware
            # Do not set CORS headers here to avoid conflicts

            response.headers.pop('Server', None)
            response.headers.pop('X-Powered-By', None)

            return response

    def update_header(self, header_name: str, value: str):
        """Update a specific security header"""
        self.headers[header_name] = value
        logger.info(f"Updated security header: {header_name}")

    def remove_header(self, header_name: str):
        """Remove a specific security header"""
        if header_name in self.headers:
            del self.headers[header_name]
            logger.info(f"Removed security header: {header_name}")

    def get_csp_nonce(self) -> str:
        """Generate a nonce for Content Security Policy"""
        import secrets
        return secrets.token_urlsafe(16)

    def set_csp_with_nonce(self, response: Response, nonce: str):
        """Set CSP header with a specific nonce"""
        flask_env = os.getenv('FLASK_ENV', 'production')
        connect_src = "'self' http://localhost:* ws://localhost:*" if flask_env == 'development' else "'self'"

        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
            f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            f"font-src 'self' https://fonts.gstatic.com; "
            f"img-src 'self' data: https:; "
            f"connect-src {connect_src}; "
            f"frame-ancestors 'none'; "
            f"form-action 'self'; "
            f"base-uri 'self'; "
            f"object-src 'none'"
        )
        response.headers['Content-Security-Policy'] = csp