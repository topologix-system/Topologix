"""Nginx reverse proxy configuration helper for Flask applications"""
import os

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix


class NginxProxyConfig:
    """Configuration helper for Flask apps behind Nginx reverse proxy"""

    @staticmethod
    def configure_app(app: Flask, trusted_proxies: int = 1):
        """Configure Flask app to work correctly behind Nginx reverse proxy"""

        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,      # X-Forwarded-For
            x_proto=trusted_proxies,     # X-Forwarded-Proto
            x_host=trusted_proxies,      # X-Forwarded-Host
            x_port=trusted_proxies,      # X-Forwarded-Port
            x_prefix=trusted_proxies     # X-Forwarded-Prefix
        )

        app.config.update(
            TRUSTED_PROXIES=['127.0.0.1', 'localhost', '::1'],

            SESSION_COOKIE_SECURE=True,  # Only send cookie over HTTPS
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',

            PERMANENT_SESSION_LIFETIME=3600,  # 1 hour
            SEND_FILE_MAX_AGE_DEFAULT=0,

            # Request limits (should match nginx settings)
            MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB max request
        )

        return app

    @staticmethod
    def get_real_ip(request):
        """Get the real client IP address from proxy headers"""
        if request.headers.get('X-Forwarded-For'):
            # X-Forwarded-For can contain multiple IPs
            # Format: client, proxy1, proxy2
            ips = request.headers.get('X-Forwarded-For').split(',')
            return ips[0].strip()

        if request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')

        return request.remote_addr

    @staticmethod
    def is_secure_request(request):
        """Check if request came through HTTPS (even if proxied)"""
        proto = request.headers.get('X-Forwarded-Proto', '')
        if proto == 'https':
            return True

        return request.is_secure

    @staticmethod
    def configure_cors(app: Flask, allowed_origins=None):
        """Configure CORS for API when served through same origin via proxy"""
        from flask_cors import CORS

        if allowed_origins is None:
            pass
        else:
            CORS(app,
                 origins=allowed_origins,
                 supports_credentials=True,
                 methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
                 allow_headers=['Content-Type', 'Authorization'],
                 expose_headers=['Content-Range', 'X-Content-Range'])

    @staticmethod
    def configure_logging(app: Flask):
        """Configure logging to work well with nginx logs"""
        import logging
        from logging.handlers import RotatingFileHandler
        import os

        if not app.debug:
            if not os.path.exists('logs'):
                os.mkdir('logs')

            file_handler = RotatingFileHandler(
                'logs/flask.log',
                maxBytes=10240000,
                backupCount=10
            )

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
        """Add security headers that the response does not already carry"""
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
        """Handle X-Request-ID header for request tracing"""
        import uuid
        from flask import g, request

        @app.before_request
        def before_request():
            request_id = request.headers.get('X-Request-ID')
            if not request_id:
                request_id = str(uuid.uuid4())
            g.request_id = request_id

        @app.after_request
        def after_request(response):
            response.headers['X-Request-ID'] = g.get('request_id', '')
            return response


def create_app():
    """Example Flask app creation with nginx proxy configuration"""
    app = Flask(__name__)

    NginxProxyConfig.configure_app(app, trusted_proxies=1)
    NginxProxyConfig.configure_logging(app)
    NginxProxyConfig.handle_request_id(app)

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
    'workers': 4,
    'worker_class': 'sync',
    'worker_connections': 1000,
    'timeout': 300,  # Match nginx proxy_read_timeout
    'keepalive': 5,
    'max_requests': 1000,
    'max_requests_jitter': 50,
    'graceful_timeout': 30,
    'forwarded_allow_ips': os.getenv('TRUSTED_PROXY_IPS', '127.0.0.1'),
    'secure_scheme_headers': {
        'X-FORWARDED-PROTO': 'https',
    },
    'accesslog': '-',
    'errorlog': '-',
    'loglevel': 'info',
}