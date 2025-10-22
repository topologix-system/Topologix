"""
Application configuration with security enhancements
- Environment-based configuration (development, production, testing)
- Authentication settings (optional, disabled by default for OSS)
- Security settings: JWT, CSRF, sessions, rate limiting, CORS
- Password policy and account lockout configuration
- File upload validation and size limits
- Batfish service connection settings
- Database and Redis configuration for production
- Audit logging and error handling configuration
"""
import os
import secrets
from pathlib import Path


class Config:
    """Application configuration with security enhancements"""

    # Environment
    ENV: str = os.getenv('FLASK_ENV', 'development')
    DEBUG: bool = os.getenv('FLASK_DEBUG', 'False') == 'True' and ENV != 'production'
    TESTING: bool = os.getenv('FLASK_TESTING', 'False') == 'True'

    # Flask
    HOST: str = '127.0.0.1' if ENV == 'production' else '0.0.0.0'
    PORT: int = int(os.getenv('PORT', '5000'))

    # Authentication - Optional (disabled by default for OSS distribution)
    AUTH_ENABLED: bool = os.getenv('AUTH_ENABLED', 'false').lower() == 'true'
    AUTH_DEFAULT_ADMIN_USER: str = os.getenv('AUTH_DEFAULT_ADMIN_USER', 'admin')
    AUTH_DEFAULT_ADMIN_PASS: str = os.getenv('AUTH_DEFAULT_ADMIN_PASS', '')  # Empty requires initial setup
    AUTH_FORCE_PASSWORD_CHANGE: bool = True  # Force password change on first login
    ALLOW_REGISTRATION: bool = os.getenv('ALLOW_REGISTRATION', 'true').lower() == 'true'  # Allow self-registration

    # Security - Secret Keys
    SECRET_KEY: str = os.getenv('SECRET_KEY', secrets.token_urlsafe(32))
    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))
    CSRF_SECRET_KEY: str = os.getenv('CSRF_SECRET_KEY', secrets.token_urlsafe(32))

    # Security - Session Configuration
    SESSION_COOKIE_SECURE: bool = ENV == 'production'
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour

    # Security - JWT Configuration
    JWT_ACCESS_TOKEN_EXPIRES: int = 3600  # 1 hour in seconds
    JWT_REFRESH_TOKEN_EXPIRES: int = 604800  # 7 days in seconds
    JWT_ALGORITHM: str = 'HS256'

    # Security - Password Policy
    MIN_PASSWORD_LENGTH: int = 12
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True
    PASSWORD_HISTORY_COUNT: int = 5
    PASSWORD_MAX_AGE_DAYS: int = 90

    # Security - Login Rate Limiting (OSS defaults - secure but not too restrictive)
    LOGIN_MAX_ATTEMPTS_PER_USER: int = int(os.getenv('LOGIN_MAX_ATTEMPTS_PER_USER', '5'))
    LOGIN_MAX_ATTEMPTS_PER_IP: int = int(os.getenv('LOGIN_MAX_ATTEMPTS_PER_IP', '10'))
    LOGIN_RATE_WINDOW_MINUTES: int = int(os.getenv('LOGIN_RATE_WINDOW_MINUTES', '15'))
    LOGIN_LOCKOUT_DURATION_MINUTES: int = int(os.getenv('LOGIN_LOCKOUT_DURATION_MINUTES', '30'))
    LOGIN_IP_BLOCK_DURATION_MINUTES: int = int(os.getenv('LOGIN_IP_BLOCK_DURATION_MINUTES', '30'))

    # Security - Account Lockout
    ACCOUNT_LOCKOUT_THRESHOLD: int = int(os.getenv('ACCOUNT_LOCKOUT_THRESHOLD', '5'))
    ACCOUNT_LOCKOUT_DURATION: int = int(os.getenv('ACCOUNT_LOCKOUT_DURATION', '1800'))  # 30 minutes in seconds

    # Security - Reverse Proxy Configuration
    # Set to True when behind reverse proxy (Caddy/nginx) for proper IP address extraction
    BEHIND_REVERSE_PROXY: bool = os.getenv('BEHIND_REVERSE_PROXY', 'true').lower() == 'true'
    # Number of trusted proxies in chain
    # - 1 for single nginx (typical Docker setup)
    # - 2 for Caddy/nginx -> nginx -> Flask
    # - N for N-layer proxy chain
    TRUSTED_PROXY_COUNT: int = int(os.getenv('TRUSTED_PROXY_COUNT', '1'))

    # Email Configuration
    # EMAIL_PROVIDER options: 'console' (print to console), 'smtp' (send via SMTP), 'disabled' (no email)
    EMAIL_PROVIDER: str = os.getenv('EMAIL_PROVIDER', 'console')
    EMAIL_FROM: str = os.getenv('EMAIL_FROM', 'noreply@topologix.local')
    EMAIL_FROM_NAME: str = os.getenv('EMAIL_FROM_NAME', 'Topologix')

    # SMTP Configuration (only used when EMAIL_PROVIDER='smtp')
    SMTP_HOST: str = os.getenv('SMTP_HOST', 'localhost')
    SMTP_PORT: int = int(os.getenv('SMTP_PORT', '587'))
    SMTP_USERNAME: str = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD: str = os.getenv('SMTP_PASSWORD', '')
    SMTP_USE_TLS: bool = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'

    # Password Reset Configuration
    PASSWORD_RESET_TOKEN_EXPIRY: int = int(os.getenv('PASSWORD_RESET_TOKEN_EXPIRY', '3600'))  # 1 hour in seconds
    PASSWORD_RESET_URL_BASE: str = os.getenv('PASSWORD_RESET_URL_BASE', 'http://localhost:3000')  # Frontend base URL

    # Security - File Upload
    MAX_CONTENT_LENGTH: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: set = {'.cfg', '.conf', '.txt'}
    UPLOAD_FOLDER: str = os.getenv('UPLOAD_FOLDER', '/tmp/topologix_uploads')

    # Security - Rate Limiting
    RATELIMIT_ENABLED: bool = True
    RATELIMIT_DEFAULT_PER_MINUTE: int = 60
    RATELIMIT_DEFAULT_PER_HOUR: int = 600
    RATELIMIT_STORAGE_URL: str = os.getenv('REDIS_URL', 'memory://')

    # Security - CORS
    CORS_ENABLED: bool = True
    CORS_ORIGINS: list[str] = os.getenv(
        'CORS_ORIGINS',
        'http://localhost:3000'
    ).split(',')
    CORS_ALLOW_HEADERS: list[str] = [
        'Content-Type',
        'Authorization',
        'X-CSRF-Token',
        'Cache-Control',
        'Pragma'
    ]
    CORS_EXPOSE_HEADERS: list[str] = [
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
    ]
    CORS_SUPPORTS_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600

    # Batfish
    BATFISH_HOST: str = os.getenv('BATFISH_HOST', 'localhost')
    BATFISH_PORT: int = int(os.getenv('BATFISH_PORT', '9996'))
    BATFISH_NETWORK: str = 'topologix_network'
    BATFISH_SNAPSHOT: str = 'current'
    BATFISH_TIMEOUT: int = 30  # seconds

    # Paths - with security validation
    BASE_DIR: Path = Path(__file__).parent.resolve()
    SNAPSHOTS_DIR: str = os.getenv(
        'SNAPSHOTS_DIR',
        str(BASE_DIR / 'snapshots')
    )
    ALLOWED_SNAPSHOT_PATH: Path = Path(SNAPSHOTS_DIR).resolve()

    # Logging
    LOG_DIR: Path = Path('/app/logs')  # Centralized log directory
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO' if ENV == 'production' else 'DEBUG')
    LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE: str = os.getenv('LOG_FILE', str(LOG_DIR / 'topologix.log'))
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5

    # Security - Audit Logging
    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = os.getenv('AUDIT_LOG_FILE', str(LOG_DIR / 'topologix_audit.log'))
    AUDIT_LOG_EVENTS: list[str] = [
        'login', 'logout', 'failed_login',
        'file_upload', 'file_delete',
        'snapshot_create', 'snapshot_delete',
        'network_init', 'config_change',
        'permission_denied', 'rate_limit_exceeded'
    ]

    # Security - Input Validation
    MAX_INPUT_LENGTH: int = 1000
    MAX_JSON_SIZE: int = 1024 * 1024  # 1MB
    ALLOWED_NODE_NAME_PATTERN: str = r'^[a-zA-Z0-9_\-\.]{1,64}$'
    ALLOWED_SNAPSHOT_NAME_PATTERN: str = r'^[a-zA-Z0-9_\-]{1,50}$'

    # Security - Error Handling
    PROPAGATE_EXCEPTIONS: bool = ENV != 'production'
    PRESERVE_CONTEXT_ON_EXCEPTION: bool = False
    TRAP_HTTP_EXCEPTIONS: bool = True
    ERROR_404_HELP: bool = False

    # Database (if using in future)
    SQLALCHEMY_DATABASE_URI: str = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{BASE_DIR}/topologix.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Redis (for caching and session storage in production)
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE: str = 'redis' if ENV == 'production' else 'simple'
    CACHE_DEFAULT_TIMEOUT: int = 300  # 5 minutes

    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration settings

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Ensure critical security keys are set in production
        if cls.ENV == 'production':
            if cls.SECRET_KEY == secrets.token_urlsafe(32):
                raise ValueError("SECRET_KEY must be set in production")
            if cls.JWT_SECRET_KEY == secrets.token_urlsafe(32):
                raise ValueError("JWT_SECRET_KEY must be set in production")
            if not cls.SESSION_COOKIE_SECURE:
                raise ValueError("SESSION_COOKIE_SECURE must be True in production")
            if cls.DEBUG:
                raise ValueError("DEBUG must be False in production")

        # Validate paths
        snapshots_path = Path(cls.SNAPSHOTS_DIR)
        if not snapshots_path.exists():
            snapshots_path.mkdir(parents=True, exist_ok=True)

        # Ensure snapshot directory is within allowed path
        if not str(snapshots_path.resolve()).startswith(str(cls.ALLOWED_SNAPSHOT_PATH)):
            raise ValueError("SNAPSHOTS_DIR is outside allowed path")

        return True

    @classmethod
    def get_safe_config(cls) -> dict:
        """Get configuration safe for client exposure

        Returns:
            Dictionary of safe configuration values
        """
        return {
            'env': cls.ENV,
            'cors_enabled': cls.CORS_ENABLED,
            'max_file_size': cls.MAX_CONTENT_LENGTH,
            'allowed_extensions': list(cls.ALLOWED_EXTENSIONS),
            'rate_limit_enabled': cls.RATELIMIT_ENABLED
        }


# Create configuration instance
config = Config()

# Validate configuration on import
try:
    config.validate_config()
except ValueError as e:
    import logging
    logging.error(f"Configuration validation failed: {e}")
    if config.ENV == 'production':
        raise