"""
Nginx reverse proxy configuration helper for Flask applications
- ProxyFix middleware for X-Forwarded-* headers
- Real client IP extraction from proxy headers
- HTTPS detection through X-Forwarded-Proto
- Security headers configuration
- Request ID tracking for distributed tracing
- CORS configuration for proxied applications
- Logging configuration compatible with nginx logs
- Gunicorn production server configuration
"""
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix


class NginxProxyConfig:
    """Configuration helper for Flask apps behind Nginx reverse proxy"""

    @staticmethod
    def configure_app(app: Flask, trusted_proxies: int = 1):
        """
        Configure Flask app to work correctly behind Nginx reverse proxy

        Args:
            app: Flask application instance
            trusted_proxies: Number of trusted proxy servers (default 1 for single nginx)
        """

        # ProxyFix middleware to handle X-Forwarded headers correctly
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,      # X-Forwarded-For
            x_proto=trusted_proxies,     # X-Forwarded-Proto
            x_host=trusted_proxies,      # X-Forwarded-Host
            x_port=trusted_proxies,      # X-Forwarded-Port
            x_prefix=trusted_proxies     # X-Forwarded-Prefix
        )

        # Flask configuration for proxy
        app.config.update(
            # Trust proxy headers
            TRUSTED_PROXIES=['127.0.0.1', 'localhost', '::1'],

            # Session cookie security (when using HTTPS via proxy)
            SESSION_COOKIE_SECURE=True,  # Only send cookie over HTTPS
            SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS access
            SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection

            # Other security settings
            PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
            SEND_FILE_MAX_AGE_DEFAULT=0,  # Disable caching in dev

            # Request limits (should match nginx settings)
            MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB max request
        )

        return app

    @staticmethod
    def get_real_ip(request):
        """
        Get the real client IP address from proxy headers

        Args:
            request: Flask request object

        Returns:
            str: Real client IP address
        """
        # Check X-Forwarded-For first (added by nginx)
        if request.headers.get('X-Forwarded-For'):
            # X-Forwarded-For can contain multiple IPs
            # Format: client, proxy1, proxy2
            ips = request.headers.get('X-Forwarded-For').split(',')
            return ips[0].strip()

        # Fallback to X-Real-IP (also added by nginx)
        if request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')

        # Final fallback to remote_addr
        return request.remote_addr

    @staticmethod
    def is_secure_request(request):
        """
        Check if request came through HTTPS (even if proxied)

        Args:
            request: Flask request object

        Returns:
            bool: True if request is secure
        """
        # Check X-Forwarded-Proto header from nginx
        proto = request.headers.get('X-Forwarded-Proto', '')
        if proto == 'https':
            return True

        # Fallback to direct check
        return request.is_secure

    @staticmethod
    def configure_cors(app: Flask, allowed_origins=None):
        """
        Configure CORS for API when served through same origin via proxy

        Args:
            app: Flask application instance
            allowed_origins: List of allowed origins (None = same origin only)
        """
        from flask_cors import CORS

        if allowed_origins is None:
            # Same origin through proxy - no CORS headers needed
            # Nginx serves both frontend and proxies to backend
            pass
        else:
            # Cross-origin requests allowed
            CORS(app,
                 origins=allowed_origins,
                 supports_credentials=True,
                 methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                 allow_headers=['Content-Type', 'Authorization'],
                 expose_headers=['Content-Range', 'X-Content-Range'])

    @staticmethod
    def configure_logging(app: Flask):
        """
        Configure logging to work well with nginx logs

        Args:
            app: Flask application instance
        """
        import logging
        from logging.handlers import RotatingFileHandler
        import os

        if not app.debug:
            # Log to file
            if not os.path.exists('logs'):
                os.mkdir('logs')

            file_handler = RotatingFileHandler(
                'logs/flask.log',
                maxBytes=10240000,
                backupCount=10
            )

            # Format to complement nginx logs
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s '
                '[in %(pathname)s:%(lineno)d] '
                '[request_id: %(request_id)s]'
            ))

            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Flask startup')

    @staticmethod
    def add_security_headers(response):
        """
        Add security headers to response (if not handled by nginx)

        Args:
            response: Flask response object

        Returns:
            response: Modified response with security headers
        """
        # Only add if not already set by nginx
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'",
        }

        for header, value in headers.items():
            if header not in response.headers:
                response.headers[header] = value

        return response

    @staticmethod
    def handle_request_id(app: Flask):
        """
        Handle X-Request-ID header for request tracing

        Args:
            app: Flask application instance
        """
        import uuid
        from flask import g, request

        @app.before_request
        def before_request():
            # Get request ID from nginx or generate new one
            request_id = request.headers.get('X-Request-ID')
            if not request_id:
                request_id = str(uuid.uuid4())
            g.request_id = request_id

        @app.after_request
        def after_request(response):
            # Add request ID to response
            response.headers['X-Request-ID'] = g.get('request_id', '')
            return response


# Example usage
def create_app():
    """Example Flask app creation with nginx proxy configuration"""
    app = Flask(__name__)

    # Apply nginx proxy configuration
    NginxProxyConfig.configure_app(app, trusted_proxies=1)
    NginxProxyConfig.configure_logging(app)
    NginxProxyConfig.handle_request_id(app)

    # Add security headers middleware
    @app.after_request
    def add_security_headers(response):
        return NginxProxyConfig.add_security_headers(response)

    # Example route using real IP
    @app.route('/api/client-info')
    def client_info():
        from flask import request, jsonify

        real_ip = NginxProxyConfig.get_real_ip(request)
        is_secure = NginxProxyConfig.is_secure_request(request)

        return jsonify({
            'real_ip': real_ip,
            'is_secure': is_secure,
            'request_id': g.get('request_id', ''),
            'headers': dict(request.headers)
        })

    return app


# Gunicorn configuration for production
GUNICORN_CONFIG = {
    'bind': '0.0.0.0:5000',
    'workers': 4,  # 2-4 x CPU cores
    'worker_class': 'sync',  # or 'gevent' for async
    'worker_connections': 1000,
    'timeout': 300,  # Match nginx proxy_read_timeout
    'keepalive': 5,
    'max_requests': 1000,
    'max_requests_jitter': 50,
    'graceful_timeout': 30,
    'forwarded_allow_ips': '*',  # Trust all proxies (be careful in production)
    'secure_scheme_headers': {
        'X-FORWARDED-PROTO': 'https',
    },
    'accesslog': '-',
    'errorlog': '-',
    'loglevel': 'info',
}