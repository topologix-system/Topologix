"""Application configuration with security enhancements"""
import hashlib
import logging
import math
import os
import secrets
import tempfile
from pathlib import Path
from typing import Mapping, Tuple

DEFAULT_DATA_DIR = '/app/data'
# Bump when a fix changes the body a cached endpoint returns, so results stored under an unchanged APP_BUILD_ID
# are recomputed.
RESULT_CACHE_SCHEMA_VERSION = 1
BUILD_ID_SOURCE_FILES = ('app.py', 'config.py', 'requirements.txt')
BUILD_ID_SOURCE_DIRS = ('services', 'security', 'database', 'utils', 'models')
RESULT_IDENTITY_HEADERS = ('X-Topologix-Snapshot-Id', 'X-Topologix-Content-Hash', 'X-Topologix-Cache')


def _load_secret(name: str) -> Tuple[str, bool]:
    """Return secret value and flag indicating whether it was auto-generated."""
    value = os.getenv(name)
    if value and value.strip():
        return value, False
    return secrets.token_urlsafe(32), True


def _env_text(name: str) -> str:
    """Return an environment value with empty and whitespace-only values treated as unset."""
    return (os.getenv(name) or '').strip()


def _env_finite_float(name: str, default: str) -> float:
    """Return an environment value as a finite float; unparsable and non-finite text raise ValueError."""
    value = float(_env_text(name) or default)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    return value


def resolve_data_dir(env: Mapping[str, str], default_candidate: str) -> Tuple[str, bool]:
    """Return the persistent data directory and whether it fell back to the system temp directory."""
    explicit = (env.get('DATA_DIR') or '').strip()
    if explicit:
        return explicit, False
    if os.path.isdir(default_candidate):
        return default_candidate, False
    return os.path.join(tempfile.gettempdir(), 'topologix-data'), True


def resolve_database_url(
    env: Mapping[str, str],
    base_dir: str | Path,
    data_dir: str | Path,
    data_dir_explicit: bool,
) -> str:
    """Return DATABASE_URL, or the default SQLite URL that moves into an explicit DATA_DIR without a legacy file."""
    explicit = (env.get('DATABASE_URL') or '').strip()
    if explicit:
        return explicit

    legacy_database = Path(base_dir) / 'topologix.db'
    if data_dir_explicit:
        if legacy_database.exists():
            logging.getLogger(__name__).warning(
                "DATA_DIR is set but the legacy database %s exists; it stays the default database. "
                "Set DATABASE_URL to choose another database.",
                legacy_database,
            )
            return f'sqlite:///{legacy_database}'
        return f'sqlite:///{Path(data_dir) / "topologix.db"}'
    return f'sqlite:///{base_dir}/topologix.db'


def derive_backend_build_id(base_dir: str | Path) -> str:
    """Return sha256 over the backend source set and requirements.txt; mounted data directories are never read."""
    base = Path(base_dir)
    sources = [base / name for name in BUILD_ID_SOURCE_FILES]
    for directory in BUILD_ID_SOURCE_DIRS:
        root = base / directory
        if root.is_dir():
            sources.extend(path for path in root.rglob('*.py') if '__pycache__' not in path.parts)
    digest = hashlib.sha256()
    for path in sorted(sources, key=lambda item: item.relative_to(base).as_posix()):
        try:
            content = path.read_bytes()
        except OSError:
            continue
        digest.update(path.relative_to(base).as_posix().encode('utf-8') + b'\0')
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


class Config:
    """Application configuration with security enhancements"""

    ENV: str = os.getenv('FLASK_ENV', 'development')
    DEBUG: bool = os.getenv('FLASK_DEBUG', 'False') == 'True' and ENV != 'production'
    TESTING: bool = os.getenv('FLASK_TESTING', 'False') == 'True'

    HOST: str = os.getenv('HOST', '0.0.0.0')
    PORT: int = int(os.getenv('PORT', '5000'))

    AUTH_ENABLED: bool = os.getenv('AUTH_ENABLED', 'false').lower() == 'true'
    AUTH_DEFAULT_ADMIN_USER: str = os.getenv('AUTH_DEFAULT_ADMIN_USER', 'admin')
    AUTH_DEFAULT_ADMIN_PASS: str = os.getenv('AUTH_DEFAULT_ADMIN_PASS', '')
    AUTH_FORCE_PASSWORD_CHANGE: bool = True
    ALLOW_REGISTRATION: bool = os.getenv('ALLOW_REGISTRATION', 'true').lower() == 'true'

    _SECRET_KEY_VALUE, _SECRET_KEY_AUTO = _load_secret('SECRET_KEY')
    SECRET_KEY: str = _SECRET_KEY_VALUE
    SECRET_KEY_AUTO_GENERATED: bool = _SECRET_KEY_AUTO

    _JWT_SECRET_VALUE, _JWT_SECRET_AUTO = _load_secret('JWT_SECRET_KEY')
    JWT_SECRET_KEY: str = _JWT_SECRET_VALUE
    JWT_SECRET_KEY_AUTO_GENERATED: bool = _JWT_SECRET_AUTO

    _CSRF_SECRET_VALUE, _CSRF_SECRET_AUTO = _load_secret('CSRF_SECRET_KEY')
    CSRF_SECRET_KEY: str = _CSRF_SECRET_VALUE
    CSRF_SECRET_KEY_AUTO_GENERATED: bool = _CSRF_SECRET_AUTO

    # 'session': session-based synchronized token pattern; 'double-submit': stateless double-submit cookie pattern
    CSRF_MODE: str = os.getenv('CSRF_MODE', 'session')

    SESSION_COOKIE_SECURE: bool = ENV == 'production'
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = 'Lax'
    PERMANENT_SESSION_LIFETIME: int = 3600  # 1 hour

    JWT_ACCESS_TOKEN_EXPIRES: int = int(os.getenv(
        'JWT_ACCESS_TOKEN_EXPIRES',
        '3600'  # 1 hour in seconds
    ))
    JWT_REFRESH_TOKEN_EXPIRES: int = 604800  # 7 days in seconds
    JWT_ALGORITHM: str = 'HS256'

    MIN_PASSWORD_LENGTH: int = 12
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_NUMBERS: bool = True
    REQUIRE_SPECIAL_CHARS: bool = True
    PASSWORD_HISTORY_COUNT: int = 5
    PASSWORD_MAX_AGE_DAYS: int = 90

    LOGIN_MAX_ATTEMPTS_PER_IP: int = int(os.getenv('LOGIN_MAX_ATTEMPTS_PER_IP', '10'))
    LOGIN_RATE_WINDOW_MINUTES: int = int(os.getenv('LOGIN_RATE_WINDOW_MINUTES', '15'))
    LOGIN_LOCKOUT_DURATION_MINUTES: int = int(os.getenv('LOGIN_LOCKOUT_DURATION_MINUTES', '30'))
    LOGIN_IP_BLOCK_DURATION_MINUTES: int = int(os.getenv('LOGIN_IP_BLOCK_DURATION_MINUTES', '30'))

    ACCOUNT_LOCKOUT_THRESHOLD: int = int(os.getenv('ACCOUNT_LOCKOUT_THRESHOLD', '5'))

    BEHIND_REVERSE_PROXY: bool = os.getenv('BEHIND_REVERSE_PROXY', 'false').lower() == 'true'
    # Number of trusted proxies in chain
    TRUSTED_PROXY_COUNT: int = int(os.getenv('TRUSTED_PROXY_COUNT', '1'))

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

    PASSWORD_RESET_TOKEN_EXPIRY: int = int(os.getenv('PASSWORD_RESET_TOKEN_EXPIRY', '3600'))  # 1 hour in seconds
    PASSWORD_RESET_URL_BASE: str = os.getenv('PASSWORD_RESET_URL_BASE', 'http://localhost:3000')  # Frontend base URL

    MAX_CONTENT_LENGTH: int = int(os.getenv('MAX_CONTENT_LENGTH', str(12 * 1024 * 1024)))
    ALLOWED_EXTENSIONS: set = {'.cfg', '.conf', '.txt', '.log'}
    UPLOAD_FOLDER: str = os.getenv('UPLOAD_FOLDER', './uploads')

    RATELIMIT_ENABLED: bool = True
    RATELIMIT_DEFAULT_PER_MINUTE: int = 60
    RATELIMIT_DEFAULT_PER_HOUR: int = 600
    RATELIMIT_STORAGE_URL: str = os.getenv('REDIS_URL', 'memory://')

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
        'X-RateLimit-Reset',
        *RESULT_IDENTITY_HEADERS,
    ]
    CORS_SUPPORTS_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600

    BATFISH_HOST: str = os.getenv('BATFISH_HOST', 'localhost')
    BATFISH_PORT: int = int(os.getenv('BATFISH_PORT', '9996'))
    BATFISH_NETWORK: str = 'topologix_network'
    BATFISH_SNAPSHOT: str = 'current'
    BATFISH_TIMEOUT: int = 30  # seconds
    # Upper bound for one Batfish query, applied only under gevent workers.
    BATFISH_QUERY_TIMEOUT_SECONDS: int = max(
        10, int(os.getenv('BATFISH_QUERY_TIMEOUT_SECONDS', '120'))
    )

    BASE_DIR: Path = Path(__file__).parent.resolve()
    SNAPSHOTS_DIR: str = os.getenv(
        'SNAPSHOTS_DIR',
        str(BASE_DIR / 'snapshots')
    )
    ALLOWED_SNAPSHOT_PATH: Path = Path(SNAPSHOTS_DIR).resolve()
    DATA_DIR, DATA_DIR_FELL_BACK = resolve_data_dir(os.environ, DEFAULT_DATA_DIR)
    DATA_DIR_EXPLICIT: bool = bool(_env_text('DATA_DIR'))
    RESULT_CACHE_DIR: str = _env_text('RESULT_CACHE_DIR') or os.path.join(DATA_DIR, 'result_cache')
    SNAPSHOT_HISTORY_DIR: str = _env_text('SNAPSHOT_HISTORY_DIR') or os.path.join(DATA_DIR, 'snapshot_history')

    DEPLOYMENT_ID: str = _env_text('DEPLOYMENT_ID')
    RESULT_CACHE_ENABLED: bool = (
        (_env_text('RESULT_CACHE_ENABLED') or 'true').lower() == 'true' and not DATA_DIR_FELL_BACK
    )
    HISTORY_GC_GRACE_SECONDS: int = max(0, int(_env_text('HISTORY_GC_GRACE_SECONDS') or '600'))
    HISTORY_ACCEPT_STORE_LOSS: str = _env_text('HISTORY_ACCEPT_STORE_LOSS')
    EXTERNAL_CHANGE_SETTLE_SECONDS: float = max(0.0, _env_finite_float('EXTERNAL_CHANGE_SETTLE_SECONDS', '10'))
    RESULT_CACHE_MAX_BYTES: int = max(0, int(_env_text('RESULT_CACHE_MAX_BYTES') or str(512 * 1024 * 1024)))
    RESULT_CACHE_MAX_ENTRIES: int = max(0, int(_env_text('RESULT_CACHE_MAX_ENTRIES') or '4000'))
    RESULT_CACHE_PROTECT_SECONDS: int = max(0, int(_env_text('RESULT_CACHE_PROTECT_SECONDS') or '900'))
    RESULT_CACHE_SCHEMA_VERSION: int = RESULT_CACHE_SCHEMA_VERSION
    BATFISH_VERSION_PROBE_TTL_SECONDS: int = max(0, int(_env_text('BATFISH_VERSION_PROBE_TTL_SECONDS') or '300'))
    BATFISH_VERSION_GRACE_SECONDS: int = max(0, int(_env_text('BATFISH_VERSION_GRACE_SECONDS') or '3600'))
    SNAPSHOT_DIFF_MAX_BYTES: int = max(0, int(_env_text('SNAPSHOT_DIFF_MAX_BYTES') or str(512 * 1024)))
    SNAPSHOT_DIFF_MAX_LINES: int = max(0, int(_env_text('SNAPSHOT_DIFF_MAX_LINES') or '2000'))
    BACKEND_BUILD_ID: str = _env_text('APP_BUILD_ID') or derive_backend_build_id(BASE_DIR)

    LOG_DIR: Path = Path(os.getenv('LOG_DIR', './logs'))
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO' if ENV == 'production' else 'DEBUG')
    LOG_FORMAT: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE: str = os.getenv('LOG_FILE', str(LOG_DIR / 'topologix.log'))
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5

    AUDIT_LOG_ENABLED: bool = True
    AUDIT_LOG_FILE: str = os.getenv('AUDIT_LOG_FILE', str(LOG_DIR / 'topologix_audit.log'))
    AUDIT_LOG_EVENTS: list[str] = [
        'login', 'logout', 'failed_login',
        'file_upload', 'file_delete',
        'snapshot_create', 'snapshot_delete',
        'network_init', 'config_change',
        'permission_denied', 'rate_limit_exceeded'
    ]

    MAX_INPUT_LENGTH: int = 1000
    MAX_JSON_SIZE: int = 1024 * 1024  # 1MB
    ALLOWED_NODE_NAME_PATTERN: str = r'^[a-zA-Z0-9_\-\.]{1,64}$'
    ALLOWED_SNAPSHOT_NAME_PATTERN: str = r'^[a-zA-Z0-9_\-]{1,50}$'

    PROPAGATE_EXCEPTIONS: bool = ENV != 'production'
    PRESERVE_CONTEXT_ON_EXCEPTION: bool = False
    TRAP_HTTP_EXCEPTIONS: bool = True
    ERROR_404_HELP: bool = False

    # Database (snapshot version history in both auth modes, authentication data under AUTH_ENABLED=true)
    SQLALCHEMY_DATABASE_URI: str = resolve_database_url(os.environ, BASE_DIR, DATA_DIR, DATA_DIR_EXPLICIT)
    SQLALCHEMY_ECHO: bool = os.getenv('SQLALCHEMY_ECHO', 'false').lower() == 'true'
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE: str = 'redis' if ENV == 'production' else 'simple'
    CACHE_DEFAULT_TIMEOUT: int = 300  # 5 minutes

    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration settings"""
        if cls.ENV == 'production':
            if cls.SECRET_KEY_AUTO_GENERATED:
                raise ValueError("SECRET_KEY must be provided when ENV=production")
            if cls.JWT_SECRET_KEY_AUTO_GENERATED:
                raise ValueError("JWT_SECRET_KEY must be provided when ENV=production")
            if cls.CSRF_SECRET_KEY_AUTO_GENERATED:
                raise ValueError("CSRF_SECRET_KEY must be provided when ENV=production")
            if not cls.SESSION_COOKIE_SECURE:
                raise ValueError("SESSION_COOKIE_SECURE must be True in production")
            if cls.DEBUG:
                raise ValueError("DEBUG must be False in production")

        snapshots_path = Path(cls.SNAPSHOTS_DIR)
        if not snapshots_path.exists():
            snapshots_path.mkdir(parents=True, exist_ok=True)

        if not str(snapshots_path.resolve()).startswith(str(cls.ALLOWED_SNAPSHOT_PATH)):
            raise ValueError("SNAPSHOTS_DIR is outside allowed path")

        return True

    @classmethod
    def get_safe_config(cls) -> dict:
        """Get configuration safe for client exposure"""
        return {
            'env': cls.ENV,
            'cors_enabled': cls.CORS_ENABLED,
            'max_file_size': cls.MAX_CONTENT_LENGTH,
            'allowed_extensions': list(cls.ALLOWED_EXTENSIONS),
            'rate_limit_enabled': cls.RATELIMIT_ENABLED
        }


config = Config()

if config.SECRET_KEY_AUTO_GENERATED:
    logging.warning("SECRET_KEY not provided; generated random value for this process (do not rely on this in production).")
if config.JWT_SECRET_KEY_AUTO_GENERATED:
    logging.warning("JWT_SECRET_KEY not provided; generated random value for this process (do not rely on this in production).")
if config.CSRF_SECRET_KEY_AUTO_GENERATED:
    logging.warning("CSRF_SECRET_KEY not provided; generated random value for this process (do not rely on this in production).")
if config.DATA_DIR_FELL_BACK:
    logging.warning(
        "DATA_DIR is not set and %s does not exist; using temporary directory %s. Snapshot versioning and the "
        "result cache are disabled; persistent deployments must set DATA_DIR.",
        DEFAULT_DATA_DIR,
        config.DATA_DIR,
    )

try:
    config.validate_config()
except ValueError as e:
    logging.error(f"Configuration validation failed: {e}")
    if config.ENV == 'production':
        raise
