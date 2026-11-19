"""Flask application entry point with authentication"""
import functools
import logging
import os
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from threading import RLock

from flask import Flask, jsonify, request, make_response, session
from flask_cors import CORS
from flask_compress import Compress
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, UnsupportedMediaType
import pybatfish
from pybatfish.datamodel.route import BgpRoute

from config import RESULT_IDENTITY_HEADERS, config
from services import BatfishQueryError, BatfishService, SnapshotService
from services.batfish_service import (
    BATFISH_NOT_INITIALIZED_MESSAGE,
    JAVA_STACK_FRAME_IN_TEXT,
    LIVE_RETRY_SECONDS,
    BatfishSnapshotLoadError,
)
from services.batfish_version_probe import BatfishVersionProbe
from services.result_cache import CacheEntryError, ResultCache, owner_scope_for
from services.snapshot_service import ConfigContentConflictError
from services.snapshot_history_service import (
    EXPECTED_HEAD_UNSET,
    CurrentNamespaceError,
    InvalidDiffPathError,
    NamespaceNotFoundError,
    PathClashError,
    SnapshotHistoryService,
    VersionConflictError,
    VersionNotFoundError,
    VersionUnchangedError,
    is_database_error,
)
from services.snapshot_state_service import (
    NAMESPACE_PATTERN,
    SnapshotStateService,
    StagingVanishedError,
    TreeMovedError,
    VersioningUnavailableError,
)
from security.validation import RequestValidationError

logging.basicConfig(
    level=logging.INFO if not config.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if config.AUTH_ENABLED:
    from flask_session import Session
    from security import (
        JWTManager, require_auth, require_role,
        sanitize_input, validate_file_upload,
        validate_snapshot_name, validate_node_name, validate_json_input,
        validate_positive_integer,
        SecurityHeaders, RateLimiter
    )
    from security.auth import TooManyAttemptsError
    if config.CSRF_MODE == 'double-submit':
        from security.csrf_double_submit import DoubleSubmitCSRFProtect as CSRFProtect
        logger.info("CSRF Mode: Double-Submit Cookie Pattern (stateless)")
    else:
        from security.csrf import CSRFProtect
        logger.info("CSRF Mode: Session-Based Synchronized Token Pattern")
    from database import init_db
    from database.seed import initialize_database
else:
    # No-op decorators when authentication is disabled
    def require_auth(f):
        return f

    def require_role(*roles):
        def decorator(f):
            return f
        return decorator

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

if config.BEHIND_REVERSE_PROXY:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=config.TRUSTED_PROXY_COUNT,
        x_proto=config.TRUSTED_PROXY_COUNT,
        x_host=config.TRUSTED_PROXY_COUNT,
        x_port=0,  # Don't trust X-Forwarded-Port
        x_prefix=0  # Don't trust X-Forwarded-Prefix
    )
    logger.info(f"ProxyFix middleware applied: trusting {config.TRUSTED_PROXY_COUNT} proxies")

if config.AUTH_ENABLED:
    app.config['SECRET_KEY'] = config.SECRET_KEY
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
    app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
    app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
    app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config.JWT_ACCESS_TOKEN_EXPIRES

if config.AUTH_ENABLED:
    CORS(app,
         origins=config.CORS_ORIGINS,
         allow_headers=config.CORS_ALLOW_HEADERS,
         expose_headers=config.CORS_EXPOSE_HEADERS,
         supports_credentials=config.CORS_SUPPORTS_CREDENTIALS,
         max_age=config.CORS_MAX_AGE)
else:
    CORS(app,
         origins=config.CORS_ORIGINS,
         allow_headers=['Content-Type', 'Cache-Control', 'Pragma'],
         expose_headers=list(RESULT_IDENTITY_HEADERS),
         supports_credentials=False)

Compress(app)
app.config['COMPRESS_ALGORITHM'] = 'gzip'
app.config['COMPRESS_LEVEL'] = 6  # Balanced compression level
app.config['COMPRESS_MIN_SIZE'] = 500

if config.AUTH_ENABLED:
    Session(app)
    jwt_manager = JWTManager(app, config.JWT_SECRET_KEY)
    csrf_protect = CSRFProtect(app, config.CSRF_SECRET_KEY)
    security_headers = SecurityHeaders(app)
    rate_limiter = RateLimiter(app)
    logger.info("Authentication and security features: ENABLED")

    try:
        app.config['AUTH_ENABLED'] = config.AUTH_ENABLED
        app.config['DEBUG'] = config.DEBUG

        db_manager = init_db(app)
        logger.info(f"Database initialized: {config.SQLALCHEMY_DATABASE_URI.split(':')[0]}")

        db_manager.create_all()
        logger.info("Database tables created/verified")

        with app.app_context():
            seed_result = initialize_database(
                admin_username=config.AUTH_DEFAULT_ADMIN_USER,
                admin_password=config.AUTH_DEFAULT_ADMIN_PASS if config.AUTH_DEFAULT_ADMIN_PASS else None,
                admin_email=f"{config.AUTH_DEFAULT_ADMIN_USER}@topologix.local"
            )
            logger.info(f"Database seeding: {seed_result}")

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise RuntimeError(f"Failed to initialize database: {e}")
else:
    logger.info("Authentication and security features: DISABLED (open access)")
    from database import init_db
    try:
        db_manager = init_db(app)
        db_manager.create_all()
        logger.info("Database initialized for snapshot versioning: %s", config.SQLALCHEMY_DATABASE_URI.split(':')[0])
    except Exception as e:
        db_manager = None
        logger.error("Database initialization failed; snapshot versioning is unavailable: %s", type(e).__name__)

if config.AUTH_ENABLED:
    AUTH_EXEMPT_ROUTES = {
        '/api/health',
        '/api/auth/login',
        '/api/auth/logout',
        '/api/auth/refresh',
        '/api/auth/password-reset-request',
        '/api/auth/password-reset',
        '/api/endpoints'
    }

    @app.before_request
    def check_authentication():
        if request.path in AUTH_EXEMPT_ROUTES:
            return None

        if request.method == 'OPTIONS':
            return None

        if request.path == '/api/users' and request.method == 'POST':
            return None

        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header:
            if not auth_header.startswith('Bearer '):
                logger.warning(f"Invalid Authorization header format: {request.path} from {request.remote_addr}")
                return error_response("Invalid authentication format", 401)
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('access_token')

        if not token:
            logger.warning(f"Missing authentication: {request.path} from {request.remote_addr}")
            return error_response("Authentication required", 401)

        try:
            payload = jwt_manager.decode_token(token)

            if payload.get('type') != 'access':
                logger.warning(f"Invalid token type: {request.path} from {request.remote_addr}")
                return error_response("Invalid token type", 401)

        except Exception as e:
            logger.warning(f"Token validation failed: {request.path} from {request.remote_addr} - {e}")
            return error_response("Invalid or expired token", 401)

        request.user_id = payload.get('user_id')
        request.username = payload.get('username')
        request.roles = payload.get('roles', [])

        logger.debug(f"Authenticated request: {request.username} -> {request.path}")

        return None

    # Periodic cleanup for expired revoked JWT tokens (runs at most once per hour)
    _last_token_cleanup = [0.0]  # mutable container for closure
    TOKEN_CLEANUP_INTERVAL = 3600  # seconds

    @app.after_request
    def periodic_revoked_token_cleanup(response):
        now = time.time()
        if now - _last_token_cleanup[0] > TOKEN_CLEANUP_INTERVAL:
            _last_token_cleanup[0] = now
            try:
                from database.models import RevokedToken
                from database.session import get_db
                with next(get_db()) as db:
                    count = RevokedToken.cleanup_expired(db)
                    if count:
                        logger.info(f"Cleaned up {count} expired revoked tokens")
            except Exception as e:
                logger.debug(f"Token cleanup skipped: {e}")
        return response

batfish_service = BatfishService()
snapshot_service = SnapshotService()
batfish_request_lock = RLock()
snapshot_state_service = SnapshotStateService(db_manager, snapshot_service)
snapshot_history_service = SnapshotHistoryService(db_manager, snapshot_state_service, config.SNAPSHOT_HISTORY_DIR)
snapshot_service.attach_state_service(snapshot_state_service)
batfish_service.attach_state_service(snapshot_state_service)
batfish_service.version_probe = BatfishVersionProbe(
    config.BATFISH_HOST,
    config.BATFISH_PORT,
    ttl_seconds=config.BATFISH_VERSION_PROBE_TTL_SECONDS,
    grace_seconds=config.BATFISH_VERSION_GRACE_SECONDS,
)
result_cache = ResultCache(
    config.RESULT_CACHE_DIR,
    max_bytes=config.RESULT_CACHE_MAX_BYTES,
    max_entries=config.RESULT_CACHE_MAX_ENTRIES,
    protect_seconds=config.RESULT_CACHE_PROTECT_SECONDS,
    build_id=config.BACKEND_BUILD_ID,
    pybatfish_version=str(getattr(pybatfish, '__version__', '')),
    schema_version=config.RESULT_CACHE_SCHEMA_VERSION,
    forced_off=snapshot_state_service.result_cache_forced_off,
)
result_cache.current_batfish_version = batfish_service.version_probe.peek
snapshot_history_service.attach_result_cache(result_cache)
snapshot_history_service.run_startup_tasks()


def seed_active_snapshot_from_file() -> None:
    """Seed the AUTH OFF snapshot selection from the stored active snapshot name."""
    if config.AUTH_ENABLED or not snapshot_state_service.result_cache_enabled:
        return
    name = snapshot_state_service.load_active_snapshot_once()
    if name:
        batfish_service.current_snapshot_name = name
        logger.info("Selected the stored active snapshot at start: snapshot=%s", name)


seed_active_snapshot_from_file()


@app.after_request
def schedule_snapshot_history_maintenance(response):
    """After-request hook that starts the hourly snapshot history maintenance when it is due."""
    snapshot_history_service.schedule_periodic_gc()
    return response


def _parse_gunicorn_workers(command_text: str | None) -> int | None:
    """Extract gunicorn worker count from a command string when it is explicit."""
    if not command_text:
        return None

    match = re.search(r"(?:--workers(?:=|\s+)|-w(?:\s+)?)(\d+)", command_text)
    if not match:
        return None
    return int(match.group(1))


def _get_process_command_line(pid: int) -> str | None:
    """Read a process command line on Linux containers when available."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as command_file:
            command = command_file.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
            return command or None
    except OSError:
        return None


def warn_if_multi_worker_batfish_state() -> None:
    """Warn when process-local Batfish state may be split across workers."""
    worker_values = [
        os.environ.get("WEB_CONCURRENCY"),
        os.environ.get("GUNICORN_WORKERS"),
    ]
    command_lines = [
        " ".join(sys.argv),
        _get_process_command_line(os.getpid()),
        _get_process_command_line(os.getppid()),
    ]
    worker_values.extend([
        str(_parse_gunicorn_workers(os.environ.get("GUNICORN_CMD_ARGS")) or ""),
        str(_parse_gunicorn_workers(os.environ.get("BACKEND_COMMAND")) or ""),
        *(str(_parse_gunicorn_workers(command) or "") for command in command_lines),
    ])

    for value in worker_values:
        if not value:
            continue
        try:
            if int(value) > 1:
                logger.warning(
                    "Multiple backend workers are not supported for process-local Batfish session state. "
                    "Use one backend worker or externalize snapshot/session state before scaling workers."
                )
                return
        except ValueError:
            continue


warn_if_multi_worker_batfish_state()

SNAPSHOT_QUERY_PREFIXES = (
    '/api/network/',
    '/api/ospf/',
    '/api/edges/',
    '/api/config/',
    '/api/validation/',
    '/api/analysis/',
    '/api/security/',
    '/api/bgp/',
    '/api/acl/',
    '/api/path/',
    '/api/ha/',
    '/api/protocols/',
    '/api/topology/',
    '/api/advanced/',
)


def get_batfish_request_network_name() -> str:
    """Return the Batfish network namespace for the current request."""
    if not config.AUTH_ENABLED:
        return config.BATFISH_NETWORK

    requester_user_id = getattr(request, 'user_id', None)
    if requester_user_id is None:
        return config.BATFISH_NETWORK

    return f"{config.BATFISH_NETWORK}_user_{int(requester_user_id)}"


# Snapshot version endpoints and whether each needs exclusive Batfish access
VERSION_ENDPOINT_USES_BATFISH = {
    'get_snapshot_version_state': False,
    'list_snapshot_versions': False,
    'commit_snapshot_version': False,
    'get_snapshot_version': False,
    'get_snapshot_version_diff': False,
    'get_snapshot_version_file_diff': False,
    'restore_snapshot_version': True,
    'delete_snapshot_version': False,
    'delete_snapshot_versions': False,
    'purge_snapshot_history_orphans': False,
    'list_snapshot_history_namespaces': False,
    'clear_snapshot_result_cache': False,
}

# Result-cached GET endpoints: (path, view). The views read neither request.args nor a body.
CACHED_QUERY_ROUTES = (
    ('/api/network/all-data', 'get_all_data'),
    ('/api/network/nodes', 'get_nodes'),
    ('/api/network/interfaces', 'get_interfaces'),
    ('/api/network/routes', 'get_routes'),
    ('/api/network/vlans', 'get_vlans'),
    ('/api/network/ip-owners', 'get_ip_owners'),
    ('/api/ospf/processes', 'get_ospf_processes'),
    ('/api/ospf/areas', 'get_ospf_areas'),
    ('/api/ospf/interfaces', 'get_ospf_interfaces'),
    ('/api/ospf/sessions', 'get_ospf_sessions'),
    ('/api/edges/ospf', 'get_ospf_edges'),
    ('/api/edges/physical', 'get_physical_edges'),
    ('/api/edges/layer3', 'get_layer3_edges'),
    ('/api/config/defined-structures', 'get_defined_structures'),
    ('/api/config/referenced-structures', 'get_referenced_structures'),
    ('/api/config/named-structures', 'get_named_structures'),
    ('/api/config/aaa-authentication', 'get_aaa_authentication'),
    ('/api/validation/file-parse-status', 'get_file_parse_status'),
    ('/api/validation/init-issues', 'get_init_issues'),
    ('/api/validation/parse-warnings', 'get_parse_warnings'),
    ('/api/validation/vi-conversion-status', 'get_vi_conversion_status'),
    ('/api/validation/unused-structures', 'get_unused_structures'),
    ('/api/validation/undefined-references', 'get_undefined_references'),
    ('/api/validation/detect-loops', 'get_detect_loops'),
    ('/api/validation/multipath-consistency', 'get_multipath_consistency'),
    ('/api/validation/loopback-multipath-consistency', 'get_loopback_multipath_consistency'),
    ('/api/security/snmp-communities', 'get_snmp_communities'),
    ('/api/bgp/edges', 'get_bgp_edges'),
    ('/api/bgp/peer-configuration', 'get_bgp_peer_configuration'),
    ('/api/bgp/process-configuration', 'get_bgp_process_configuration'),
    ('/api/bgp/session-status', 'get_bgp_session_status'),
    ('/api/bgp/session-compatibility', 'get_bgp_session_compatibility'),
    ('/api/bgp/rib', 'get_bgp_rib'),
    ('/api/ha/vrrp-properties', 'get_vrrp_properties'),
    ('/api/ha/hsrp-properties', 'get_hsrp_properties'),
    ('/api/ha/mlag-properties', 'get_mlag_properties'),
    ('/api/ha/duplicate-router-ids', 'get_duplicate_router_ids'),
    ('/api/ha/switching-properties', 'get_switching_properties'),
    ('/api/protocols/evpn/rib', 'get_evpn_rib'),
    ('/api/protocols/evpn/vxlan-edges', 'get_vxlan_edges'),
    ('/api/protocols/evpn/vxlan-vni-properties', 'get_vxlan_vni_properties'),
    ('/api/protocols/eigrp/edges', 'get_eigrp_edges'),
    ('/api/protocols/eigrp/interface-configuration', 'get_eigrp_interface_configuration'),
    ('/api/protocols/isis/edges', 'get_isis_edges'),
    ('/api/protocols/isis/interface-configuration', 'get_isis_interface_configuration'),
    ('/api/protocols/isis-loopback-interfaces', 'get_isis_loopback_interfaces'),
    ('/api/protocols/bfd-session-status', 'get_bfd_session_status'),
    ('/api/topology/layer1-edges', 'get_layer1_edges'),
    ('/api/topology/layer1-topology', 'get_layer1_topology'),
    ('/api/topology/ipsec-session-status', 'get_ipsec_session_status'),
    ('/api/topology/ipsec-edges', 'get_ipsec_edges'),
    ('/api/topology/ipsec-peer-configuration', 'get_ipsec_peer_configuration'),
    ('/api/topology/layer2-topology', 'get_layer2_topology'),
    ('/api/topology/switched-vlan-edges', 'get_switched_vlan_edges'),
    ('/api/topology/interface-mtu', 'get_interface_mtu'),
    ('/api/topology/ip-space-assignment', 'get_ip_space_assignment'),
    ('/api/advanced/f5-bigip-vip-configuration', 'get_f5_bigip_vip_configuration'),
    ('/api/advanced/questions', 'get_questions'),
    ('/api/advanced/node-roles', 'get_node_roles'),
    ('/api/advanced/interface-blacklist', 'get_interface_blacklist'),
    ('/api/advanced/vi-model', 'get_vi_model'),
)
CACHED_QUERY_EXCLUSIONS = {
    '/api/analysis/route-policies': 'reads request.args',
    '/api/acl/filter-line-reachability': 'reads request.args',
    '/api/advanced/route-policies': 'reads request.args',
    '/api/advanced/compare-peer-group-policies': 'reads request.args or a body and names snapshots',
}
CACHED_QUERY_ENDPOINTS = frozenset(view for _, view in CACHED_QUERY_ROUTES)


def cached_endpoint_skips_hooks() -> bool:
    """Return whether the current request is a cached endpoint that the Batfish hooks leave to the decorator."""
    return snapshot_state_service.result_cache_enabled and request.endpoint in CACHED_QUERY_ENDPOINTS


def request_uses_batfish() -> bool:
    """Check whether the current request needs exclusive Batfish access."""
    path = request.path

    if request.endpoint in VERSION_ENDPOINT_USES_BATFISH:
        return VERSION_ENDPOINT_USES_BATFISH[request.endpoint]

    if cached_endpoint_skips_hooks():
        return False

    if path.startswith(SNAPSHOT_QUERY_PREFIXES):
        return True

    if path == '/api/network/initialize':
        return True

    if path == '/api/snapshots/compare':
        return True

    if path.endswith('/activate') and path.startswith('/api/snapshots/'):
        return True

    if path.startswith('/api/snapshots/') and '/files' in path and request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return True

    if path.startswith('/api/snapshots/') and '/artifacts' in path and request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return True

    if path.endswith('/interfaces') and path.startswith('/api/snapshots/'):
        return True

    if path.endswith('/layer1-topology') and path.startswith('/api/snapshots/') and request.method in {'PUT', 'DELETE'}:
        return True

    return False


# Endpoints that read a multipart/form-data upload instead of a JSON body
NON_JSON_BODY_ENDPOINTS = frozenset({
    'upload_snapshot_file',
    'upload_snapshot_artifact',
    'replace_snapshot_artifact_content',
})

# POST/PUT/PATCH endpoints that run without a request body or read it optionally
OPTIONAL_BODY_ENDPOINTS = frozenset({
    'logout',
    'refresh_token',
    'get_reachability',
    'compare_peer_group_policies',
    'update_snapshot_file_content',
    'update_snapshot_file_format',
    'preview_snapshot_artifact_change',
    'update_snapshot_artifact',
    'validate_snapshot_artifacts',
    'activate_snapshot',
    'restore_snapshot_version',
    'clear_snapshot_result_cache',
})

BODY_METHODS = frozenset({'POST', 'PUT', 'PATCH'})


@app.before_request
def reject_unreadable_request_body():
    """Answer oversized, malformed, missing or non-JSON bodies before route handlers catch the parse errors."""
    max_content_length = request.max_content_length
    if max_content_length is not None and (request.content_length or 0) > max_content_length:
        raise RequestEntityTooLarge()

    if (
        request.method not in BODY_METHODS
        or request.endpoint is None
        or request.endpoint in NON_JSON_BODY_ENDPOINTS
    ):
        return None

    # The CSRF check may already have parsed a form body out of the request stream
    has_body = bool(request.get_data(cache=True).strip()) or bool(request.form) or bool(request.files)
    if not has_body:
        if request.endpoint in OPTIONAL_BODY_ENDPOINTS:
            return None
    elif request.is_json:
        try:
            data = request.get_json()
        except BadRequest:
            pass
        else:
            if data is None or isinstance(data, dict):
                return None
            return error_response(
                "Request body must be a JSON object",
                400,
                code="invalid_json",
                hints=["Send a JSON object (not an array or a scalar value) with Content-Type: application/json."],
            )
    return error_response(
        "Request body must be valid JSON",
        400,
        code="invalid_json",
        hints=["Send a well-formed JSON document with Content-Type: application/json."],
    )


@app.before_request
def prepare_batfish_request_context():
    """Serialize Batfish operations and switch to the request-specific network namespace."""
    if request.method == 'OPTIONS' or not request_uses_batfish():
        return None

    batfish_request_lock.acquire()
    request._batfish_lock_acquired = True
    batfish_service.set_network_context(get_batfish_request_network_name())

    if config.AUTH_ENABLED or not is_lazy_load_request():
        return None
    snapshot_name = batfish_service.current_snapshot_name
    if not snapshot_name:
        return None
    try:
        snapshot_path = snapshot_service.get_snapshot_path(snapshot_name, **get_snapshot_request_context())
    except Exception:
        return None
    return ensure_request_snapshot_loaded(snapshot_name, snapshot_path).error


@app.after_request
def release_batfish_request_lock(response):
    """Release Batfish lock after a response is produced."""
    if getattr(request, '_batfish_lock_acquired', False):
        batfish_request_lock.release()
        request._batfish_lock_acquired = False
    return response


@app.teardown_request
def cleanup_batfish_request_lock(error):
    """Ensure Batfish lock is released on error paths."""
    if getattr(request, '_batfish_lock_acquired', False):
        batfish_request_lock.release()
        request._batfish_lock_acquired = False
    return None

if config.AUTH_ENABLED:
    @app.before_request
    def ensure_authenticated_snapshot_context():
        """Restore the active snapshot for the authenticated browser session."""
        if request.method == 'OPTIONS':
            return None

        if request.path == '/api/network/initialize':
            return None

        if not request.path.startswith(SNAPSHOT_QUERY_PREFIXES):
            return None

        if cached_endpoint_skips_hooks():
            return None

        active_snapshot_name = session.get('current_snapshot_name')
        if not active_snapshot_name:
            return error_response(BATFISH_NOT_INITIALIZED_MESSAGE, 400)

        try:
            snapshot_path = snapshot_service.get_snapshot_path(
                active_snapshot_name,
                **get_snapshot_request_context(),
            )

            outcome = ensure_request_snapshot_loaded(active_snapshot_name, snapshot_path)
            if outcome.error is not None:
                return outcome.error
        except PermissionError:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared unauthorized active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                active_snapshot_name,
            )
            return error_response("Active snapshot access denied", 403)
        except FileNotFoundError:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared missing active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                active_snapshot_name,
            )
            return error_response("Active snapshot not found", 404)
        except Exception as e:
            logger.error(
                "Failed to synchronize Batfish snapshot for user=%s snapshot=%s: %s",
                getattr(request, 'username', 'unknown'),
                active_snapshot_name,
                e,
            )
            return snapshot_activation_error_response(active_snapshot_name, e)

        return None


@app.errorhandler(RequestEntityTooLarge)
def request_entity_too_large(error):
    return error_response("Request body exceeds the maximum allowed size", 413, code="request_too_large")


@app.errorhandler(UnsupportedMediaType)
def unsupported_media_type(error):
    return error_response("Request body must be valid JSON", 400, code="invalid_json")


@app.errorhandler(BadRequest)
def bad_request(error):
    return error_response("Bad request", 400, code="bad_request")


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({"error": "Internal server error"}), 500


def generate_etag(data: Any) -> str:
    json_str = json.dumps(data, sort_keys=True)
    return hashlib.md5(json_str.encode()).hexdigest()


def add_cache_headers(response, cache_time: int = 300, private: bool = False):
    cache_control = []
    if private:
        cache_control.append('private')
    else:
        cache_control.append('public')

    cache_control.append(f'max-age={cache_time}')
    cache_control.append('must-revalidate')

    response.headers['Cache-Control'] = ', '.join(cache_control)
    response.headers['Vary'] = 'Accept-Encoding, Authorization, Cookie' if private else 'Accept-Encoding'

    expires = datetime.utcnow() + timedelta(seconds=cache_time)
    response.headers['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')

    return response


def success_response(data: Any, message: str = "Success", cache_time: int = 0, use_etag: bool = False, status_code: int = 200) -> tuple:
    """Create success response with optional caching"""
    response_data = {"status": "success", "message": message, "data": data}

    if use_etag:
        etag = generate_etag(response_data)

        if request.headers.get('If-None-Match') == etag:
            return '', 304  # Not Modified

        response = make_response(jsonify(response_data), status_code)
        response.headers['ETag'] = etag
    else:
        response = make_response(jsonify(response_data), status_code)

    if cache_time > 0:
        add_cache_headers(response, cache_time, private=config.AUTH_ENABLED)

    return response


_SECRET_RESPONSE_KEY_PATTERN = re.compile(r"password|secret|token|communities|community", re.IGNORECASE)
_SECRET_RESPONSE_MARKER_PATTERN = re.compile(
    r"""(["']?[A-Za-z0-9_.-]*(?:password|secret|token|communities|community)[A-Za-z0-9_.-]*["']?)(\s*(?::|=)\s*|\s+)""",
    re.IGNORECASE,
)


def sanitize_error_text(value: str) -> str:
    """Redact secret-like values before returning API error payloads."""
    parts: list[str] = []
    cursor = 0
    search_pos = 0

    while True:
        match = _SECRET_RESPONSE_MARKER_PATTERN.search(value, search_pos)
        if match is None:
            break

        if match.start() > 0 and (value[match.start() - 1].isalnum() or value[match.start() - 1] == "_"):
            search_pos = match.end()
            continue

        delimiter = match.group(2)
        value_start = match.end()
        if not should_redact_secret_value(match.group(1), delimiter, value, value_start):
            search_pos = match.end()
            continue

        value_end = secret_value_end(value, value_start)
        if value_end <= value_start:
            search_pos = match.end()
            continue

        parts.append(value[cursor:value_start])
        parts.append("[redacted]")
        cursor = value_end
        search_pos = value_end

    parts.append(value[cursor:])
    return redact_standalone_bgp_communities("".join(parts))


def redact_standalone_bgp_communities(value: str) -> str:
    return re.sub(r"(?<![A-Za-z0-9_.:-])(?:\d{1,10}:){1,2}\d{1,10}(?![A-Za-z0-9_.:-])", "[redacted]", value)


def should_redact_secret_value(marker: str, delimiter: str, value: str, value_start: int) -> bool:
    if ":" in delimiter or "=" in delimiter:
        return True
    if value_start >= len(value):
        return False
    if value[value_start] in ("'", '"', "[", "{"):
        return True
    return "communit" in marker.lower() and starts_with_bgp_community(value, value_start)


def starts_with_bgp_community(value: str, value_start: int) -> bool:
    return re.match(r"(?:\d{1,10}:){1,2}\d{1,10}(?=$|[\s,;}\]])", value[value_start:]) is not None


def secret_value_end(value: str, start: int) -> int:
    if start >= len(value):
        return start

    first = value[start]
    if first in ("'", '"'):
        return consume_quoted_secret_value(value, start, first)
    if first in ("[", "{"):
        return consume_balanced_secret_value(value, start)

    index = start
    while index < len(value) and not value[index].isspace() and value[index] not in ",;}]":
        index += 1
    return index


def consume_quoted_secret_value(value: str, start: int, quote: str) -> int:
    index = start + 1
    escaped = False
    while index < len(value):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
        index += 1
    return len(value)


def consume_balanced_secret_value(value: str, start: int) -> int:
    pairs = {"[": "]", "{": "}"}
    stack = [pairs[value[start]]]
    index = start + 1
    quote: str | None = None
    escaped = False

    while index < len(value):
        char = value[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char in pairs:
            stack.append(pairs[char])
        elif stack and char == stack[-1]:
            stack.pop()
            if not stack:
                return index + 1
        index += 1

    return len(value)


def sanitize_error_payload(value: Any) -> Any:
    """Recursively redact secret-like values from structured API error payloads."""
    if isinstance(value, str):
        return sanitize_error_text(value)
    if isinstance(value, list):
        return [sanitize_error_payload(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_error_payload(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[redacted]" if _SECRET_RESPONSE_KEY_PATTERN.search(str(key)) else sanitize_error_payload(item)
            for key, item in value.items()
        }
    return value


def error_response(
    message: str,
    status_code: int = 400,
    code: str | None = None,
    details: Any | None = None,
    hints: list[str] | None = None,
) -> tuple:
    """Create error response"""
    payload: dict[str, Any] = {"status": "error", "message": sanitize_error_text(message)}
    if code:
        payload["code"] = code
    if details is not None:
        payload["details"] = sanitize_error_payload(details)
    if hints:
        payload["hints"] = sanitize_error_payload(hints)
    return jsonify(payload), status_code


def batfish_query_error_response(error: BatfishQueryError) -> tuple:
    """Create a structured Batfish query error response."""
    return error_response(
        error.message,
        error.status_code,
        code=error.error_type,
        details=error.details,
        hints=error.hints,
    )


def validation_error_response(error: RequestValidationError) -> tuple:
    """Create a structured response for request input rejected by validation."""
    return error_response(
        str(error),
        400,
        code="validation_error",
        details={"field": error.field} if error.field else None,
    )


_BATFISH_FAILURE_REASON_PATTERN = re.compile(
    r"(?:Caused by: |exception:)(?:[A-Za-z0-9_.$]+(?:Exception|Error): )?([^\n\"]+)"
)
_UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def extract_batfish_failure_reason(message: str) -> str | None:
    """Return the innermost exception reason of a Batfish work log without stack frames, ids or secret-like values."""
    reasons = _BATFISH_FAILURE_REASON_PATTERN.findall(message)
    if not reasons:
        return None
    reason = JAVA_STACK_FRAME_IN_TEXT.split(reasons[-1])[0]
    reason = sanitize_error_text(reason)
    reason = _UUID_PATTERN.sub("[id]", reason).strip()
    return reason[:300] or None


def snapshot_has_config_files(snapshot_path: Path) -> bool:
    """Check whether a snapshot holds a consumable file at depth >= 2 outside Batfish supplemental data (True when
    that cannot be determined)."""
    for _ in range(3):
        try:
            for relative_path, _absolute in snapshot_state_service.iter_consumable_files(snapshot_path):
                parts = relative_path.split('/')
                if len(parts) > 1 and parts[0] != 'batfish':
                    return True
            return False
        except TreeMovedError:
            continue
        except FileNotFoundError:
            return False
        except OSError:
            return True
    return True


def snapshot_empty_response(name: str) -> tuple:
    return error_response(
        f"Snapshot '{name}' has no configuration files to analyze",
        400,
        code="snapshot_empty",
        details={"snapshot": name},
        hints=["Upload at least one device configuration file to the snapshot, then activate it again."],
    )


def activation_snapshot_id(snapshot_path: Path) -> str | None:
    try:
        return snapshot_state_service.read_sidecar_id(snapshot_path)
    except Exception:
        return None


def activation_failure_key(snapshot_id: str | None, snapshot_name: str, content_hash: str | None = None) -> tuple:
    """Key of the activation negative cache: content-keyed when the hash is known, else the id or the name."""
    namespace = snapshot_state_service.namespace
    if snapshot_id and content_hash:
        return ('hash', namespace, snapshot_id, content_hash)
    if snapshot_id:
        return ('id', namespace, snapshot_id)
    return ('name', namespace, snapshot_name)


def record_activation_failure(snapshot_path: Path, name: str, error: Exception, content_hash: str | None) -> None:
    if isinstance(error, StagingVanishedError):
        return
    snapshot_id = activation_snapshot_id(snapshot_path)
    batfish_service.activation_failures.record(
        activation_failure_key(snapshot_id, name, content_hash), error, snapshot_id, name,
    )


def note_activation_success(snapshot_path: Path, name: str) -> None:
    """Bookkeeping after a successful parse of the requester's current snapshot."""
    snapshot_id = activation_snapshot_id(snapshot_path)
    batfish_service.activation_failures.remove_snapshot(snapshot_id, name)
    snapshot_state_service.consume_reparse(snapshot_id, batfish_service.loaded_clear_counter)
    if not config.AUTH_ENABLED:
        snapshot_state_service.persist_active_snapshot(name)


def clear_current_snapshot_after_failure(name: str) -> None:
    """Deselect a snapshot that is current in the requester's context after a failed activation."""
    if batfish_service.current_snapshot_name == name:
        batfish_service.clear_active_snapshot()
        if not config.AUTH_ENABLED:
            snapshot_state_service.clear_active_snapshot_file()
    if config.AUTH_ENABLED and session.get('current_snapshot_name') == name:
        session.pop('current_snapshot_name', None)


def activate_batfish_snapshot(snapshot_path: Path, name: str) -> dict[str, Any]:
    """Initialize Batfish with a snapshot, leaving the snapshot inactive when the activation fails."""
    previous_snapshot_name = batfish_service.current_snapshot_name
    batfish_service.last_upload_hash = None
    try:
        result = batfish_service.initialize_network(str(snapshot_path), name)
    except Exception as e:
        if previous_snapshot_name == name:
            batfish_service.current_snapshot_name = name
            clear_current_snapshot_after_failure(name)
        else:
            batfish_service.current_snapshot_name = previous_snapshot_name
            if config.AUTH_ENABLED and session.get('current_snapshot_name') == name:
                session.pop('current_snapshot_name', None)
        record_activation_failure(snapshot_path, name, e, batfish_service.last_upload_hash)
        raise
    note_activation_success(snapshot_path, name)
    return result


def snapshot_activation_error_response(name: str, error: Exception) -> tuple:
    """Create a sanitized response for a snapshot activation that Batfish did not complete."""
    message = str(error)
    if "Work terminated abnormally" not in message:
        return error_response(
            f"Failed to activate snapshot '{name}'",
            500,
            code="snapshot_activation_error",
            details={"snapshot": name},
            hints=["Check that the Batfish service is reachable, then retry."],
        )

    details: dict[str, Any] = {"snapshot": name}
    reason = extract_batfish_failure_reason(message)
    if reason:
        details["reason"] = reason
    return error_response(
        f"Batfish could not initialize snapshot '{name}'",
        422,
        code="snapshot_activation_failed",
        details=details,
        hints=[
            "Check that the snapshot contains device configuration files Batfish can parse.",
            "Fix the reported problem in the snapshot files, then activate the snapshot again.",
        ],
    )


def snapshot_load_error_response(error: BatfishSnapshotLoadError, role: str | None = None) -> tuple:
    """Create a sanitized 422 response for a snapshot Batfish rejected while loading it for queries by name."""
    name = error.snapshot_name
    reason = extract_batfish_failure_reason(str(error))
    role_label = f"{role} " if role and role != "snapshot" else ""
    message = f"Batfish could not load {role_label}snapshot '{name}'"
    details: dict[str, Any] = {"snapshot": name}
    if role:
        details["role"] = role
    if reason:
        message = f"{message}: {reason}"
        details["reason"] = reason
    return error_response(
        message,
        422,
        code="snapshot_load_failed",
        details=details,
        hints=[
            "Check that the snapshot contains device configuration files Batfish can parse.",
            "Fix the reported problem in the snapshot files, then retry.",
        ],
    )


def get_snapshot_request_context() -> dict[str, Any]:
    """Build per-request snapshot authorization context."""
    return {
        'requester_user_id': getattr(request, 'user_id', None),
        'auth_enabled': config.AUTH_ENABLED,
    }


def get_snapshot_creation_context() -> dict[str, Any]:
    """Build snapshot creation context including owner metadata."""
    return {
        'owner_user_id': getattr(request, 'user_id', None),
        'owner_username': getattr(request, 'username', None),
        'auth_enabled': config.AUTH_ENABLED,
    }


def require_snapshot_access(snapshot_name: str | None) -> Path | None:
    """Validate that the current requester can access a named snapshot and return its directory."""
    if not snapshot_name:
        return None
    return snapshot_service.get_snapshot_path(snapshot_name, **get_snapshot_request_context())


SNAPSHOT_ID_HEADER, CONTENT_HASH_HEADER, CACHE_STATUS_HEADER = RESULT_IDENTITY_HEADERS
LEGACY_CACHE_HEADERS = ('ETag', 'Expires', 'Last-Modified')
CACHED_QUERY_REPLANS = 2
STALE_SELECTION = object()
CACHE_BYPASSED = "the request is answered without the result cache"
_cache_degradations_logged: set[tuple[str, str]] = set()
_kept_selections_logged: set[tuple[str, str]] = set()


def log_cache_degradation(failure: str, consequence: str, error: Exception) -> None:
    """Log what failed, its exception type and what the request does instead: one WARNING per failure and
    consequence, DEBUG afterwards."""
    key = (failure, consequence)
    level = logging.DEBUG if key in _cache_degradations_logged else logging.WARNING
    _cache_degradations_logged.add(key)
    logger.log(level, "%s failed (%s); %s", failure, type(error).__name__, consequence)


def log_kept_selection(name: str, problem: str) -> None:
    """Log that the AUTH OFF active snapshot stays selected: one WARNING per snapshot name and problem, DEBUG
    afterwards."""
    key = (name, problem)
    level = logging.DEBUG if key in _kept_selections_logged else logging.WARNING
    _kept_selections_logged.add(key)
    logger.log(level, "Active snapshot %s %s; it stays selected", name, problem)


@dataclass
class LoadOutcome:
    """Result of making Batfish hold the requester's current snapshot"""
    error: Any = None
    parsed: bool = False
    consumed_reparse: bool = False
    stale_selection: bool = False


@dataclass
class CachePlan:
    """Everything a cached request needs before it looks the cache up"""
    snapshot_id: str
    working_hash: str
    clear_seq: int | None
    owner_scope: str
    db_id: str
    batfish_version: str
    reparse: bool
    state: Any = field(repr=False)


@dataclass
class Computation:
    """A cache miss computed under the Batfish lock"""
    response: Any = None
    hit: Any = None
    loaded_hash: str | None = None
    clear_counter: int | None = None
    batfish_version: str | None = None
    storable: bool = False
    stale_selection: bool = False


class CurrentSnapshotError(Exception):
    """The requester has no usable current snapshot; carries the error response"""

    def __init__(self, response):
        super().__init__("No usable current snapshot")
        self.response = response


def resolve_current_snapshot() -> tuple[str, Path]:
    """Return the requester's authorized current snapshot (session under AUTH ON, process name under AUTH OFF), or
    raise CurrentSnapshotError carrying the error response when there is no usable one."""
    name = session.get('current_snapshot_name') if config.AUTH_ENABLED else batfish_service.current_snapshot_name
    if not name:
        raise CurrentSnapshotError(error_response(BATFISH_NOT_INITIALIZED_MESSAGE, 400, code="no_active_snapshot"))
    try:
        return name, snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except PermissionError:
        if config.AUTH_ENABLED:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared unauthorized active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                name,
            )
        else:
            log_kept_selection(name, "cannot be accessed")
        raise CurrentSnapshotError(error_response("Active snapshot access denied", 403))
    except FileNotFoundError:
        if config.AUTH_ENABLED:
            session.pop('current_snapshot_name', None)
            logger.warning(
                "Cleared missing active snapshot for user=%s snapshot=%s",
                getattr(request, 'username', 'unknown'),
                name,
            )
        else:
            log_kept_selection(name, "is missing")
        raise CurrentSnapshotError(error_response("Active snapshot not found", 404))
    except ValueError as e:
        raise CurrentSnapshotError(error_response(str(e), 400))


def request_owner_scope() -> str | None:
    """Owner scope of the requester's cache entries: '' under AUTH OFF, <db_id>:<user id> under AUTH ON, else None."""
    if not config.AUTH_ENABLED:
        return ''
    try:
        owner = snapshot_service._normalize_owner_user_id(getattr(request, 'user_id', None))
    except ValueError:
        return None
    if owner is None:
        return None
    return owner_scope_for(True, snapshot_history_service.db_id, owner)


def is_lazy_load_request() -> bool:
    return request.path.startswith(SNAPSHOT_QUERY_PREFIXES) and request.path != '/api/network/initialize'


def live_marker_matches(name: str, working_hash: str | None) -> bool:
    marker = batfish_service.live_loaded
    return bool(
        batfish_service._initialized
        and marker is not None
        and working_hash is not None
        and tuple(marker[:3]) == (batfish_service.network_name, name, working_hash)
    )


def staging_recovered(snapshot_path: Path) -> bool:
    """Retry staging alone for a live-loaded snapshot and return whether it succeeded."""
    try:
        staged_dir, _ = snapshot_state_service.stage_for_upload(snapshot_path)
    except Exception as e:
        marker = batfish_service.live_loaded
        if marker is not None:
            batfish_service.live_loaded = (marker[0], marker[1], marker[2], time.monotonic())
        logger.info("Staging of snapshot %s is still unavailable (%s)", snapshot_path.name, type(e).__name__)
        return False
    try:
        snapshot_state_service.cleanup_staging(staged_dir)
    except Exception:
        pass
    return True


def loaded_hash_equals_disk(snapshot_path: Path) -> bool:
    loaded = batfish_service.loaded_content_hash
    if loaded is None:
        return False
    try:
        return snapshot_state_service.compute_manifest(snapshot_path).content_hash == loaded
    except Exception:
        return False


def activate_lazily(name: str, snapshot_path: Path, failure_key: tuple, snapshot_id: str | None,
                    reparse: bool) -> LoadOutcome:
    """Parse a snapshot on demand; a failure keeps the name, session and stored name and is negative-cached
    (except a snapshot that changed while it was staged or whose staging directory disappeared)."""
    batfish_service.last_upload_hash = None
    try:
        batfish_service.initialize_network(str(snapshot_path), name)
    except Exception as e:
        logger.error("Failed to load snapshot %s into Batfish on demand (%s)", name, type(e).__name__)
        batfish_service._initialized = False
        batfish_service.loaded_content_hash = None
        if not isinstance(e, StagingVanishedError):
            batfish_service.activation_failures.record(failure_key, e, snapshot_id, name)
        return LoadOutcome(error=snapshot_activation_error_response(name, e))
    note_activation_success(snapshot_path, name)
    logger.info("Loaded snapshot %s into Batfish on demand", name)
    consumed = reparse and not snapshot_state_service.reparse_requested(snapshot_id)
    return LoadOutcome(parsed=True, consumed_reparse=consumed)


def ensure_loaded(name: str, snapshot_path: Path, state) -> LoadOutcome:
    """Under the Batfish lock, parse the requester's current snapshot when Batfish does not hold its working content
    or a re-parse is due."""
    working_hash = state.content_hash
    snapshot_id = state.snapshot_id
    reparse = snapshot_state_service.reparse_requested(snapshot_id)
    probe = batfish_service.version_probe
    current_version = probe.current() if probe is not None else None
    version_changed = current_version is not None and batfish_service.loaded_batfish_version != current_version
    clear_pending = state.clear_seq is not None and (
        batfish_service.loaded_clear_counter is None or batfish_service.loaded_clear_counter < state.clear_seq
    )
    is_current = batfish_service._initialized and batfish_service.current_snapshot_name == name

    if not (reparse or version_changed or clear_pending):
        if is_current and batfish_service.loaded_content_hash is not None:
            if batfish_service.loaded_content_hash == working_hash:
                return LoadOutcome()
            if loaded_hash_equals_disk(snapshot_path):
                return LoadOutcome()
        if live_marker_matches(name, working_hash):
            marker_age = time.monotonic() - batfish_service.live_loaded[3]
            if marker_age < LIVE_RETRY_SECONDS or not staging_recovered(snapshot_path):
                return LoadOutcome()

    if version_changed and is_current:
        logger.info("Batfish version changed since snapshot %s was parsed; re-parsing it", name)
        batfish_service._drop_loaded_state()

    failure_key = activation_failure_key(snapshot_id, name, working_hash)
    failure = batfish_service.activation_failures.get(failure_key)
    if failure is not None:
        return LoadOutcome(error=snapshot_activation_error_response(name, failure))
    if not snapshot_has_config_files(snapshot_path):
        return LoadOutcome(error=snapshot_empty_response(name))
    return activate_lazily(name, snapshot_path, failure_key, snapshot_id, reparse)


def ensure_loaded_by_name(name: str, snapshot_path: Path) -> LoadOutcome:
    """Load the requester's current snapshot by name only, without comparing its content."""
    if config.AUTH_ENABLED and batfish_service.current_snapshot_name != name:
        try:
            activate_batfish_snapshot(snapshot_path, name)
        except Exception as e:
            logger.error(
                "Failed to synchronize Batfish snapshot for user=%s snapshot=%s: %s",
                getattr(request, 'username', 'unknown'),
                name,
                type(e).__name__,
            )
            return LoadOutcome(error=snapshot_activation_error_response(name, e))
        logger.info(
            "Synchronized Batfish snapshot for user=%s snapshot=%s", getattr(request, 'username', 'unknown'), name,
        )
        return LoadOutcome(parsed=True)
    if batfish_service.current_snapshot_name == name and not batfish_service._initialized:
        snapshot_id = activation_snapshot_id(snapshot_path)
        failure_key = activation_failure_key(snapshot_id, name)
        failure = batfish_service.activation_failures.get(failure_key)
        if failure is not None:
            return LoadOutcome(error=snapshot_activation_error_response(name, failure))
        return activate_lazily(name, snapshot_path, failure_key, snapshot_id, reparse=False)
    return LoadOutcome()


def ensure_request_snapshot_loaded(name: str, snapshot_path: Path) -> LoadOutcome:
    """Hook path of non-cached snapshot queries, under the Batfish lock."""
    if not snapshot_state_service.result_cache_enabled:
        return ensure_loaded_by_name(name, snapshot_path)
    try:
        state = snapshot_state_service.evaluate_snapshot(snapshot_path)
    except VersioningUnavailableError:
        return ensure_loaded_by_name(name, snapshot_path)
    except Exception as e:
        log_cache_degradation(
            "Snapshot state evaluation before a non-cached query",
            "the loaded snapshot is matched by name only, not by content",
            e,
        )
        return ensure_loaded_by_name(name, snapshot_path)
    if state.content_hash is None:
        return ensure_loaded_by_name(name, snapshot_path)
    return ensure_loaded(name, snapshot_path, state)


@contextmanager
def batfish_request_scope(name: str, snapshot_path: Path, state=None, bypass: bool = False):
    """Batfish lock, the requester's network context and a loaded snapshot for the enclosed computation; an AUTH
    OFF selection that changed while the request waited yields stale_selection without loading."""
    with batfish_request_lock:
        batfish_service.set_network_context(get_batfish_request_network_name())
        if not config.AUTH_ENABLED and batfish_service.current_snapshot_name != name:
            yield LoadOutcome(stale_selection=True)
        elif bypass or state is None or state.content_hash is None:
            yield ensure_loaded_by_name(name, snapshot_path)
        else:
            yield ensure_loaded(name, snapshot_path, state)


def without_legacy_cache_headers(response):
    for header in LEGACY_CACHE_HEADERS:
        response.headers.remove(header)
    response.headers['Cache-Control'] = 'no-store'
    return response


def with_identity_headers(response, snapshot_id: str | None, content_hash: str | None, status: str):
    response.headers[SNAPSHOT_ID_HEADER] = snapshot_id or ''
    response.headers[CONTENT_HASH_HEADER] = content_hash or ''
    response.headers[CACHE_STATUS_HEADER] = status
    return response


def if_none_match_matches(etag: str) -> bool:
    """Match If-None-Match (weak tags, lists, * and Flask-Compress :<algorithm> suffixes) against an ETag."""
    if not request.headers.get('If-None-Match'):
        return False
    tags = request.if_none_match
    if tags.star_tag:
        return True
    return any(tag.split(':', 1)[0] == etag for tag in tags.as_set(include_weak=True))


def cached_entry_response(entry, snapshot_id: str, status: str, allow_not_modified: bool = True):
    """Serve a stored body: 304 on a matching ETag (AUTH OFF), else the gzip or plain body."""
    etag = f"{snapshot_id[:8]}-{entry.content_hash[:16]}-{entry.key_hash[:8]}-{entry.body_sha256[:8]}"
    if allow_not_modified and not config.AUTH_ENABLED and if_none_match_matches(etag):
        response = app.response_class(status=304)
        response.headers['ETag'] = f'"{etag}"'
        response.headers['Cache-Control'] = 'private, no-cache'
        return with_identity_headers(response, snapshot_id, entry.content_hash, status)
    if request.accept_encodings.quality('gzip') > 0:
        response = app.response_class(entry.body, status=200, mimetype='application/json')
        response.headers['Content-Encoding'] = 'gzip'
    else:
        response = app.response_class(entry.plain_body(), status=200, mimetype='application/json')
    response.headers['Vary'] = 'Accept-Encoding'
    if config.AUTH_ENABLED:
        response.headers['Cache-Control'] = 'no-store'
    else:
        response.headers['ETag'] = f'"{etag}"'
        response.headers['Cache-Control'] = 'private, no-cache'
    return with_identity_headers(response, snapshot_id, entry.content_hash, status)


def is_storable_body(response) -> bool:
    if response.status_code != 200:
        return False
    payload = response.get_json(silent=True)
    if not isinstance(payload, dict) or payload.get('status') != 'success':
        return False
    data = payload.get('data')
    return not (isinstance(data, dict) and data.get('query_errors'))


def plan_cached_query(snapshot_path: Path) -> CachePlan | None:
    """Return the cache plan, or None when the request must bypass the cache."""
    try:
        state = snapshot_state_service.evaluate_snapshot(snapshot_path)
    except VersioningUnavailableError:
        return None
    except Exception as e:
        log_cache_degradation("Snapshot state evaluation of a cached endpoint", CACHE_BYPASSED, e)
        return None
    if state.content_hash is None:
        return None
    db_id = snapshot_history_service.db_id
    owner_scope = request_owner_scope()
    if not db_id or owner_scope is None:
        return None
    probe = batfish_service.version_probe
    batfish_version = probe.current() if probe is not None else None
    if batfish_version is None:
        return None
    return CachePlan(
        snapshot_id=state.snapshot_id,
        working_hash=state.content_hash,
        clear_seq=state.clear_seq,
        owner_scope=owner_scope,
        db_id=db_id,
        batfish_version=batfish_version,
        reparse=snapshot_state_service.reparse_requested(state.snapshot_id),
        state=state,
    )


def cache_lookup(plan: CachePlan, content_hash: str, endpoint_key: str):
    return result_cache.lookup(
        content_hash, endpoint_key, plan.owner_scope, plan.db_id, plan.clear_seq,
        batfish_version=plan.batfish_version,
    )


def serve_hit(plan: CachePlan, content_hash: str, endpoint_key: str):
    """Return the response for a valid stored entry, or None; a body that cannot be decoded is discarded."""
    entry = cache_lookup(plan, content_hash, endpoint_key)
    if entry is None:
        return None
    try:
        response = cached_entry_response(entry, plan.snapshot_id, 'hit')
    except CacheEntryError:
        result_cache.discard(entry)
        return None
    logger.debug("Result cache hit: %s", endpoint_key)
    return response


def serve_bypass(view, args, kwargs, name: str, snapshot_path: Path):
    snapshot_id = activation_snapshot_id(snapshot_path)
    with batfish_request_scope(name, snapshot_path, bypass=True) as outcome:
        if outcome.stale_selection:
            return STALE_SELECTION
        if outcome.error is not None:
            response = app.make_response(outcome.error)
        else:
            response = app.make_response(view(*args, **kwargs))
    return with_identity_headers(without_legacy_cache_headers(response), snapshot_id, '', 'bypass')


def serve_current_bypass(view, args, kwargs):
    """Bypass for the snapshot that is current while the Batfish lock is held."""
    with batfish_request_lock:
        batfish_service.set_network_context(get_batfish_request_network_name())
        try:
            name, snapshot_path = resolve_current_snapshot()
        except CurrentSnapshotError as e:
            return with_identity_headers(without_legacy_cache_headers(app.make_response(e.response)), '', '', 'bypass')
        outcome = ensure_loaded_by_name(name, snapshot_path)
        if outcome.error is not None:
            response = app.make_response(outcome.error)
        else:
            response = app.make_response(view(*args, **kwargs))
    return with_identity_headers(
        without_legacy_cache_headers(response), activation_snapshot_id(snapshot_path), '', 'bypass',
    )


def compute_cache_miss(view, args, kwargs, name: str, snapshot_path: Path, plan: CachePlan,
                       endpoint_key: str) -> Computation:
    """Compute a cache miss under the Batfish lock with the snapshot loaded, re-running the view once after a lost
    Batfish state."""
    with batfish_request_scope(name, snapshot_path, state=plan.state) as outcome:
        if outcome.stale_selection:
            return Computation(stale_selection=True)
        if outcome.error is not None:
            return Computation(response=app.make_response(outcome.error))
        loaded = batfish_service.loaded_content_hash
        if loaded and not outcome.consumed_reparse and not (
            plan.reparse and snapshot_state_service.reparse_requested(plan.snapshot_id)
        ):
            try:
                hit = serve_hit(plan, loaded, endpoint_key)
            except Exception as e:
                log_cache_degradation(
                    "Result cache lookup of the loaded content", "the result is computed and stored if possible", e,
                )
                hit = None
            if hit is not None:
                return Computation(hit=hit)
        for attempt in (1, 2):
            drops = batfish_service.state_drop_count
            loaded = batfish_service.loaded_content_hash
            clear_counter = batfish_service.loaded_clear_counter
            batfish_version = batfish_service.loaded_batfish_version
            batfish_service.reset_query_failure_count()
            response = app.make_response(view(*args, **kwargs))
            failures = batfish_service.query_failure_count()
            if batfish_service.state_drop_count == drops:
                unchanged = (
                    batfish_service._initialized
                    and batfish_service.current_snapshot_name == name
                    and batfish_service.loaded_content_hash == loaded
                )
                return Computation(
                    response=response,
                    loaded_hash=loaded,
                    clear_counter=clear_counter,
                    batfish_version=batfish_version,
                    storable=bool(loaded and batfish_version and unchanged and failures == 0),
                )
            if attempt == 2:
                return Computation(
                    response=app.make_response(
                        batfish_query_error_response(batfish_service._state_lost_failure(endpoint_key))
                    ),
                )
            logger.warning("Batfish lost snapshot %s while computing %s; re-parsing once", name, endpoint_key)
            retry = ensure_loaded(name, snapshot_path, plan.state)
            if retry.error is not None:
                return Computation(response=app.make_response(retry.error))


def serve_cached_query(endpoint_key: str, view, args, kwargs):
    """Serve a cached endpoint, planning it again when the AUTH OFF selection changed while the request waited."""
    for _ in range(CACHED_QUERY_REPLANS + 1):
        response = serve_cached_query_once(endpoint_key, view, args, kwargs)
        if response is not STALE_SELECTION:
            return response
    logger.info("Snapshot selection kept changing while %s waited for Batfish; answering uncached", endpoint_key)
    return serve_current_bypass(view, args, kwargs)


def serve_cached_query_once(endpoint_key: str, view, args, kwargs):
    try:
        name, snapshot_path = resolve_current_snapshot()
    except CurrentSnapshotError as e:
        return with_identity_headers(without_legacy_cache_headers(app.make_response(e.response)), '', '', 'bypass')

    plan = plan_cached_query(snapshot_path)
    if plan is None:
        return serve_bypass(view, args, kwargs, name, snapshot_path)

    if not plan.reparse:
        try:
            hit = serve_hit(plan, plan.working_hash, endpoint_key)
        except Exception as e:
            log_cache_degradation("Result cache lookup", CACHE_BYPASSED, e)
            return serve_bypass(view, args, kwargs, name, snapshot_path)
        if hit is not None:
            return hit

    try:
        key_lock = result_cache.key_lock((plan.working_hash, endpoint_key, plan.owner_scope))
        computing = result_cache.computing((plan.working_hash, plan.owner_scope))
    except Exception as e:
        log_cache_degradation("Result cache key lock", CACHE_BYPASSED, e)
        return serve_bypass(view, args, kwargs, name, snapshot_path)

    with key_lock, computing:
        if not plan.reparse:
            try:
                hit = serve_hit(plan, plan.working_hash, endpoint_key)
            except Exception as e:
                log_cache_degradation(
                    "Result cache lookup under the key lock", "the result is computed and stored if possible", e,
                )
                hit = None
            if hit is not None:
                return hit
        computation = compute_cache_miss(view, args, kwargs, name, snapshot_path, plan, endpoint_key)
        if computation.stale_selection:
            return STALE_SELECTION
        if computation.hit is not None:
            return computation.hit
        response = computation.response
        if computation.storable and is_storable_body(response):
            try:
                with result_cache.computing((computation.loaded_hash, plan.owner_scope)):
                    entry = result_cache.store(
                        computation.loaded_hash,
                        endpoint_key,
                        plan.owner_scope,
                        response.get_data(),
                        plan.db_id,
                        computation.clear_counter,
                        batfish_version=computation.batfish_version,
                    )
            except Exception as e:
                log_cache_degradation("Result cache store", "the result is served without being stored", e)
                entry = None
            if entry is not None:
                try:
                    result_cache.evict_if_needed()
                except Exception as e:
                    log_cache_degradation(
                        "Result cache eviction", "size limits are not enforced until it succeeds", e,
                    )
                return cached_entry_response(entry, plan.snapshot_id, 'stored', allow_not_modified=False)
        return with_identity_headers(
            without_legacy_cache_headers(response),
            plan.snapshot_id,
            computation.loaded_hash,
            'unstored' if computation.loaded_hash else 'bypass',
        )


def cached_query(endpoint_key: str):
    """Serve a parameterless snapshot query from the result cache; pass through with no-store when it is off."""
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if not snapshot_state_service.result_cache_enabled:
                return without_legacy_cache_headers(app.make_response(view(*args, **kwargs)))
            return serve_cached_query(endpoint_key, view, args, kwargs)
        wrapper.cached_endpoint_key = endpoint_key
        return wrapper
    return decorator


def normalize_batfish_specifier(value: Any, separator: str = ",") -> str | None:
    """Normalize UI list or comma text into a Batfish specifier."""
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        return separator.join(parts) if parts else None
    return str(value).strip() or None


def get_query_specifier(name: str) -> str | None:
    """Read a query parameter that may be encoded as name or name[]."""
    values = request.args.getlist(name) or request.args.getlist(f"{name}[]")
    if len(values) > 1:
        return normalize_batfish_specifier(values)
    if values:
        return normalize_batfish_specifier(values[0])
    return normalize_batfish_specifier(request.args.get(name))


def parse_optional_bool(value: Any, default: bool | None = None) -> bool | None:
    """Parse optional bools from JSON or query parameters."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return default


ROUTE_POLICY_DIRECTIONS = frozenset({"in", "out"})
SEARCH_ROUTE_POLICIES_PATH_OPTIONS = ("SINGLE", "PER_PATH", "NON_OVERLAP")
BGP_ROUTE_REQUIRED_FIELDS = ("network", "originatorIp", "originType", "protocol")
BGP_ROUTE_STRING_FIELDS = ("network", "originatorIp", "originType", "protocol", "nextHopIp", "sourceProtocol")
BGP_ROUTE_LIST_FIELDS = ("asPath", "communities")
BGP_ROUTE_INTEGER_FIELDS = ("localPreference", "metric", "tag", "weight")
BGP_ROUTE_FIELDS = frozenset(BGP_ROUTE_STRING_FIELDS + BGP_ROUTE_LIST_FIELDS + BGP_ROUTE_INTEGER_FIELDS)
BGP_ROUTE_IP_FIELDS = ("originatorIp", "nextHopIp")


def is_ipv4_prefix(value: str) -> bool:
    """Return True for an IPv4 prefix with an explicit length, such as 192.0.2.0/24 (host bits allowed)."""
    _, separator, length = value.partition("/")
    if not separator or not length.isdigit():
        return False
    try:
        return ipaddress.ip_network(value, strict=False).version == 4
    except ValueError:
        return False


def is_ipv4_address(value: str) -> bool:
    """Return True for a dotted-quad IPv4 address such as 192.0.2.1."""
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


def parse_route_policy_direction(value: Any) -> str:
    """Return a testRoutePolicies direction in the lowercase form Batfish accepts."""
    direction = value.strip().lower() if isinstance(value, str) else None
    if direction not in ROUTE_POLICY_DIRECTIONS:
        raise RequestValidationError("'direction' must be 'in' or 'out'", field="direction")
    return direction


def parse_bgp_input_routes(value: Any) -> list[BgpRoute]:
    """Convert one route object or a list of route objects into pybatfish BgpRoute values."""
    routes = [value] if isinstance(value, dict) else value
    if not isinstance(routes, list) or not routes:
        raise RequestValidationError(
            "'inputRoutes' must be a route object or a non-empty list of route objects",
            field="inputRoutes",
        )

    parsed: list[BgpRoute] = []
    for index, route in enumerate(routes):
        route_field = f"inputRoutes[{index}]"
        if not isinstance(route, dict):
            raise RequestValidationError(f"{route_field} must be a JSON object", field=route_field)

        fields = dict(route)
        fields.pop("class", None)
        if "srcProtocol" in fields and "sourceProtocol" not in fields:
            fields["sourceProtocol"] = fields.pop("srcProtocol")

        missing = [name for name in BGP_ROUTE_REQUIRED_FIELDS if fields.get(name) in (None, "")]
        if missing:
            raise RequestValidationError(
                f"{route_field} is missing required field(s): {', '.join(missing)}",
                field=f"{route_field}.{missing[0]}",
            )
        unknown = sorted(set(fields) - BGP_ROUTE_FIELDS)
        if unknown:
            raise RequestValidationError(
                f"{route_field} has unsupported field(s): {', '.join(unknown)}",
                field=f"{route_field}.{unknown[0]}",
            )
        for name in BGP_ROUTE_STRING_FIELDS:
            if fields.get(name) is not None and not isinstance(fields[name], str):
                raise RequestValidationError(f"{route_field}.{name} must be a string", field=f"{route_field}.{name}")
        for name in BGP_ROUTE_LIST_FIELDS:
            if name in fields and not isinstance(fields[name], list):
                raise RequestValidationError(f"{route_field}.{name} must be a list", field=f"{route_field}.{name}")
        for name in BGP_ROUTE_INTEGER_FIELDS:
            if name in fields and (not isinstance(fields[name], int) or isinstance(fields[name], bool)):
                raise RequestValidationError(f"{route_field}.{name} must be an integer", field=f"{route_field}.{name}")
        if not is_ipv4_prefix(fields["network"]):
            raise RequestValidationError(
                f"{route_field}.network must be an IPv4 prefix such as 192.0.2.0/24",
                field=f"{route_field}.network",
            )
        for name in BGP_ROUTE_IP_FIELDS:
            if fields.get(name) is not None and not is_ipv4_address(fields[name]):
                raise RequestValidationError(
                    f"{route_field}.{name} must be an IPv4 address such as 192.0.2.1",
                    field=f"{route_field}.{name}",
                )

        parsed.append(BgpRoute(**fields))
    return parsed


def parse_search_route_policies_path_option(value: Any) -> str | None:
    """Return a searchRoutePolicies pathOption in the enum form Batfish accepts, or None when unset."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    path_option = value.strip().upper() if isinstance(value, str) else None
    if path_option not in SEARCH_ROUTE_POLICIES_PATH_OPTIONS:
        raise RequestValidationError(
            f"'pathOption' must be one of {', '.join(SEARCH_ROUTE_POLICIES_PATH_OPTIONS)}",
            field="pathOption",
        )
    return path_option


def reload_active_snapshot_after_layer1_change(name: str) -> tuple | None:
    """Reload Batfish when Layer1 changes affect the active snapshot context.

    Returns the activation error response when Batfish fails to reload the snapshot.
    """
    if config.AUTH_ENABLED:
        if session.get('current_snapshot_name') != name:
            return None
    elif batfish_service.current_snapshot_name != name:
        return None

    snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    try:
        activate_batfish_snapshot(snapshot_path, name)
    except Exception as e:
        logger.error("Failed to reload Batfish snapshot after Layer1 change: snapshot=%s error=%s", name, e)
        return snapshot_activation_error_response(name, e)
    logger.info("Reloaded Batfish snapshot after Layer1 change: snapshot=%s", name)
    return None


def validate_password(password: str) -> tuple[bool, str]:
    """Validate password against security policy"""
    if not password:
        return False, "Password is required"

    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {config.MIN_PASSWORD_LENGTH} characters"

    if config.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if config.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if config.REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if config.REQUIRE_SPECIAL_CHARS and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"

    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format"""
    import re

    if not email:
        return False, "Email is required"

    # RFC 5322 simplified email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not re.match(email_pattern, email):
        return False, "Invalid email format"

    if len(email) > 255:
        return False, "Email address too long"

    return True, ""


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format"""
    import re

    if not username:
        return False, "Username is required"

    if len(username) < 3:
        return False, "Username must be at least 3 characters"

    if len(username) > 50:
        return False, "Username must be at most 50 characters"

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"

    return True, ""


@app.route('/api/health', methods=['GET'])
def health_check():
    return success_response({
        "service": "topologix-backend",
        "status": "healthy",
        "auth_enabled": config.AUTH_ENABLED,
        "batfish": batfish_service.get_batfish_version_info(),
        "result_cache": {"enabled": snapshot_state_service.result_cache_enabled},
    })


if config.AUTH_ENABLED:
    def set_token_cookies(response, tokens: dict) -> None:
        """Set a login session's access and refresh tokens as HTTP-only cookies"""
        is_secure = config.ENV == 'production'
        response.set_cookie(
            'access_token',
            tokens['access_token'],
            secure=is_secure,
            httponly=True,
            samesite='Lax',
            max_age=config.JWT_ACCESS_TOKEN_EXPIRES
        )
        response.set_cookie(
            'refresh_token',
            tokens['refresh_token'],
            secure=is_secure,
            httponly=True,
            samesite='Lax',
            path='/api/auth/refresh',
            max_age=config.JWT_REFRESH_TOKEN_EXPIRES
        )

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        """Authenticate user and return JWT tokens"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['username', 'password']
            )

            username = sanitize_input(data['username'], max_length=50)
            password = data['password']  # Don't sanitize passwords

            try:
                user = jwt_manager.authenticate_user(username, password)
            except TooManyAttemptsError as e:
                return jsonify({"status": "error", "message": "Too many attempts",
                                "retry_after": e.retry_after}), 429
            if not user:
                logger.warning(f"Failed login attempt for {username} from {request.remote_addr}")
                return error_response("Invalid credentials", 401)

            tokens = jwt_manager.generate_tokens(
                user['id'], user['username'], user['roles']
            )

            if config.CSRF_MODE == 'double-submit':
                csrf_token = csrf_protect.generate_csrf_token(
                    user_id=user['id'],
                    session_id=request.headers.get('X-Session-ID')
                )
            else:
                csrf_token = csrf_protect.generate_csrf_token()

            logger.info(f"Successful login for {username} from {request.remote_addr}")

            response = jsonify({
                "status": "success",
                "message": "Login successful",
                "data": {
                    "token_type": "Bearer",
                    "expires_in": tokens['expires_in'],
                    "user": {
                        "username": user['username'],
                        "roles": user['roles'],
                        "email": user['email']
                    },
                    "csrf_token": csrf_token
                }
            })

            if config.CSRF_MODE == 'double-submit':
                csrf_protect.set_csrf_cookie(response, csrf_token)

            set_token_cookies(response, tokens)

            return response, 200

        except RequestValidationError as e:
            return validation_error_response(e)
        except ValueError as e:
            return error_response(str(e), 400)
        except Exception as e:
            logger.error(f"Login error: {e}")
            return error_response("Login failed", 500)

    @app.route('/api/auth/logout', methods=['POST'])
    def logout():
        """Logout user and invalidate token

        Succeeds without a valid access token (expired, revoked, or of an inactive or
        deleted user) so clients can always end their login state; only a token whose
        signature verifies is revoked.
        """
        try:
            token = jwt_manager._extract_token()
            payload = jwt_manager.revoke_token(token) if token else None
            username = payload.get('username') if payload else None
            logger.info(f"Logout for {username or 'unknown user'} from {request.remote_addr}")
            if payload:
                logger.info(f"Token revoked for user {username}")

            session.clear()

            response = make_response(success_response({}, "Logout successful"))

            response.set_cookie('access_token', '', expires=0)
            response.set_cookie('refresh_token', '', expires=0, path='/api/auth/refresh')

            if config.CSRF_MODE == 'double-submit':
                csrf_protect.clear_csrf_cookie(response)
            else:
                response.set_cookie('csrf_token', '', expires=0)

            return response

        except Exception as e:
            logger.error(f"Logout error: {e}")
            return error_response("Logout failed", 500)

    @app.route('/api/auth/refresh', methods=['POST'])
    def refresh_token():
        """Refresh access token using refresh token from HTTP-only cookie"""
        try:
            refresh_token_str = request.cookies.get('refresh_token')
            if not refresh_token_str:
                return error_response("Refresh token required", 401)

            payload = jwt_manager.decode_token(refresh_token_str)

            if payload.get('type') != 'refresh':
                return error_response("Invalid token type", 401)

            user_id = payload.get('user_id')

            if config.AUTH_ENABLED:
                from database.models import User
                from database.session import get_db

                with next(get_db()) as db:
                    user_obj = db.get(User, user_id)
                    if not user_obj or not user_obj.is_active:
                        return error_response("User not found or inactive", 401)

                    user = {
                        'id': user_obj.id,
                        'username': user_obj.username,
                        'roles': [role.name for role in user_obj.roles]
                    }
            else:
                from security.auth import USERS_DB
                user = None
                for u in USERS_DB.values():
                    if u['id'] == user_id:
                        user = u
                        break

                if not user:
                    return error_response("User not found", 401)

            tokens = jwt_manager.generate_tokens(
                user['id'], user['username'], user['roles'],
                session_id=payload.get('sid') or payload.get('jti')
            )

            is_secure = config.ENV == 'production'
            response = jsonify({
                "status": "success",
                "message": "Token refreshed",
                "data": {
                    "token_type": "Bearer",
                    "expires_in": tokens['expires_in']
                }
            })
            response.set_cookie(
                'access_token',
                tokens['access_token'],
                secure=is_secure,
                httponly=True,
                samesite='Lax',
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES
            )

            return response

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return error_response("Token refresh failed", 401)

    @app.route('/api/auth/csrf-token', methods=['GET'])
    @require_auth
    def get_csrf_token():
        """Get CSRF token for authenticated user"""
        if config.CSRF_MODE == 'double-submit':
            csrf_token = csrf_protect.generate_csrf_token(
                user_id=request.user_id,
                session_id=request.headers.get('X-Session-ID')
            )
            response = make_response(success_response({'csrf_token': csrf_token}))
            csrf_protect.set_csrf_cookie(response, csrf_token)
            return response
        else:
            csrf_token = csrf_protect.generate_csrf_token()
            return success_response({'csrf_token': csrf_token})

    @app.route('/api/users', methods=['POST'])
    def create_user():
        """Create new user (self-registration or admin creation)"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['username', 'email', 'password'],
                optional_fields=['full_name', 'roles']
            )

            is_self_registration = True
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                try:
                    token = auth_header.split(' ')[1]
                    payload = jwt_manager.decode_token(token)
                    if payload.get('type') == 'access':
                        request.user_id = payload.get('user_id')
                        request.username = payload.get('username')
                        request.roles = payload.get('roles', [])
                        is_self_registration = False
                except Exception:
                    pass

            if is_self_registration:
                if not config.ALLOW_REGISTRATION:
                    return error_response("Self-registration is disabled", 403)
                roles_to_assign = ['viewer']
            else:
                from database.rbac import require_permission
                if not hasattr(request, 'user_id'):
                    return error_response("Authentication required", 401)

                from database.models import User
                from database.session import get_db
                with next(get_db()) as db:
                    admin_user = db.get(User, request.user_id)
                    if not admin_user or not admin_user.has_permission('user:write'):
                        return error_response("Permission denied: user:write required", 403)

                roles_to_assign = data.get('roles', ['viewer'])

            is_valid, error_msg = validate_username(data['username'])
            if not is_valid:
                return error_response(error_msg, 400)

            is_valid, error_msg = validate_email(data['email'])
            if not is_valid:
                return error_response(error_msg, 400)

            is_valid, error_msg = validate_password(data['password'])
            if not is_valid:
                return error_response(error_msg, 400)

            from database.models import User, Role
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                stmt = select(User).where(User.username == data['username'])
                if db.scalar(stmt):
                    return error_response("Username already exists", 409)

                stmt = select(User).where(User.email == data['email'])
                if db.scalar(stmt):
                    return error_response("Email already exists", 409)

                new_user = User(
                    username=data['username'],
                    email=data['email'],
                    full_name=data.get('full_name', ''),
                    is_active=True,
                    email_verified=False
                )
                new_user.set_password(data['password'])

                for role_name in roles_to_assign:
                    stmt = select(Role).where(Role.name == role_name)
                    role = db.scalar(stmt)
                    if role:
                        new_user.roles.append(role)

                db.add(new_user)
                db.commit()
                db.refresh(new_user)

                logger.info(f"User created: {new_user.username} (ID: {new_user.id}) by {'self-registration' if is_self_registration else f'admin {request.username}'}")

                return success_response(new_user.to_dict(), "User created successfully", status_code=201)

        except RequestValidationError as e:
            return validation_error_response(e)
        except Exception as e:
            logger.error(f"User creation error: {e}")
            return error_response(f"Failed to create user: {str(e)}", 500)

    @app.route('/api/users', methods=['GET'])
    @require_auth
    def list_users():
        """Get list of all users (admin only)

        Requires user:read permission
        """
        try:
            from database.models import User
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                admin_user = db.get(User, request.user_id)
                if not admin_user or not admin_user.has_permission('user:read'):
                    return error_response("Permission denied: user:read required", 403)

                stmt = select(User).order_by(User.created_at.desc())
                users = db.scalars(stmt).all()

                users_data = [user.to_dict() for user in users]
                return success_response(users_data)

        except Exception as e:
            logger.error(f"List users error: {e}")
            return error_response(f"Failed to list users: {str(e)}", 500)

    @app.route('/api/users/me', methods=['GET'])
    @require_auth
    def get_current_user_info():
        """Get current authenticated user information"""
        try:
            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                user = db.get(User, request.user_id)
                if not user:
                    return error_response("User not found", 404)

                return success_response(user.to_dict())

        except Exception as e:
            logger.error(f"Get current user error: {e}")
            return error_response(f"Failed to get user info: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['GET'])
    @require_auth
    def get_user(user_id: int):
        """Get user by ID

        Accessible by: user themselves or users with user:read permission
        """
        try:
            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                is_own_profile = request.user_id == user_id

                if not is_own_profile:
                    admin_user = db.get(User, request.user_id)
                    if not admin_user or not admin_user.has_permission('user:read'):
                        return error_response("Permission denied", 403)

                user = db.get(User, user_id)
                if not user:
                    return error_response("User not found", 404)

                return success_response(user.to_dict())

        except Exception as e:
            logger.error(f"Get user error: {e}")
            return error_response(f"Failed to get user: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['PUT'])
    @require_auth
    def update_user(user_id: int):
        """Update user information"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=[],
                optional_fields=['email', 'full_name', 'roles', 'is_active']
            )

            from database.models import User, Role
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                current_user = db.get(User, request.user_id)
                target_user = db.get(User, user_id)

                if not target_user:
                    return error_response("User not found", 404)

                is_own_profile = request.user_id == user_id
                has_admin_permission = current_user and current_user.has_permission('user:write')

                if is_own_profile:
                    if 'email' in data:
                        is_valid, error_msg = validate_email(data['email'])
                        if not is_valid:
                            return error_response(error_msg, 400)

                        stmt = select(User).where(User.email == data['email'], User.id != user_id)
                        if db.scalar(stmt):
                            return error_response("Email already exists", 409)

                        target_user.email = data['email']
                        target_user.email_verified = False

                    if 'full_name' in data:
                        target_user.full_name = data['full_name']

                    if 'roles' in data or 'is_active' in data:
                        return error_response("Cannot change roles or status on own profile", 403)

                elif has_admin_permission:
                    if 'email' in data:
                        is_valid, error_msg = validate_email(data['email'])
                        if not is_valid:
                            return error_response(error_msg, 400)

                        stmt = select(User).where(User.email == data['email'], User.id != user_id)
                        if db.scalar(stmt):
                            return error_response("Email already exists", 409)

                        target_user.email = data['email']

                    if 'full_name' in data:
                        target_user.full_name = data['full_name']

                    if 'is_active' in data:
                        is_active = bool(data['is_active'])
                        if target_user.is_active and not is_active:
                            target_user.tokens_invalid_before = datetime.now(timezone.utc)
                        target_user.is_active = is_active

                    if 'roles' in data:
                        target_user.roles.clear()
                        for role_name in data['roles']:
                            stmt = select(Role).where(Role.name == role_name)
                            role = db.scalar(stmt)
                            if role:
                                target_user.roles.append(role)

                else:
                    return error_response("Permission denied", 403)

                db.commit()
                db.refresh(target_user)

                logger.info(f"User updated: {target_user.username} (ID: {user_id}) by {request.username}")
                return success_response(target_user.to_dict(), "User updated successfully")

        except RequestValidationError as e:
            return validation_error_response(e)
        except Exception as e:
            logger.error(f"Update user error: {e}")
            return error_response(f"Failed to update user: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>/password', methods=['PUT'])
    @require_auth
    def change_password(user_id: int):
        """Change user password"""
        try:
            if request.user_id != user_id:
                return error_response("Can only change own password", 403)

            data = validate_json_input(
                request.get_json(),
                required_fields=['current_password', 'new_password'],
                optional_fields=[]
            )

            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                user = db.get(User, user_id)
                if not user:
                    return error_response("User not found", 404)

                if not user.check_password(data['current_password']):
                    return error_response("Current password is incorrect", 401)

                is_valid, error_msg = validate_password(data['new_password'])
                if not is_valid:
                    return error_response(error_msg, 400)

                user.set_password(data['new_password'])
                db.commit()

                tokens = jwt_manager.generate_tokens(user.id, user.username, [role.name for role in user.roles])
                response = make_response(success_response(None, "Password changed successfully"))
                set_token_cookies(response, tokens)

                logger.info(f"Password changed for user: {user.username} (ID: {user_id})")
                return response

        except RequestValidationError as e:
            return validation_error_response(e)
        except Exception as e:
            logger.error(f"Change password error: {e}")
            return error_response(f"Failed to change password: {str(e)}", 500)

    @app.route('/api/users/<int:user_id>', methods=['DELETE'])
    @require_auth
    def delete_user(user_id: int):
        """Delete user (admin only)"""
        try:
            if request.user_id == user_id:
                return error_response("Cannot delete own account", 403)

            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                admin_user = db.get(User, request.user_id)
                if not admin_user or not admin_user.has_permission('user:delete'):
                    return error_response("Permission denied: user:delete required", 403)

                target_user = db.get(User, user_id)
                if not target_user:
                    return error_response("User not found", 404)

                username = target_user.username
                db.delete(target_user)
                db.commit()

                logger.info(f"User deleted: {username} (ID: {user_id}) by {request.username}")
                return success_response(None, "User deleted successfully")

        except Exception as e:
            logger.error(f"Delete user error: {e}")
            return error_response(f"Failed to delete user: {str(e)}", 500)

    @app.route('/api/admin/security-logs', methods=['GET'])
    @require_role('admin')
    def get_security_logs():
        """Get security logs (login attempts) - Admin only"""
        try:
            from database.models import LoginAttempt
            from database.session import get_db
            from sqlalchemy import select, func, and_
            from datetime import datetime, timezone

            page = max(1, int(request.args.get('page', 1)))
            per_page = min(200, max(1, int(request.args.get('per_page', 50))))
            ip_address = request.args.get('ip_address')
            username = request.args.get('username')
            success_filter = request.args.get('success')
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            sort_order = request.args.get('sort', 'desc')

            with next(get_db()) as db:
                query = select(LoginAttempt)
                filters = []

                if ip_address:
                    filters.append(LoginAttempt.ip_address == ip_address)

                if username:
                    filters.append(LoginAttempt.username == username)

                if success_filter is not None:
                    success_bool = success_filter.lower() == 'true'
                    filters.append(LoginAttempt.success == success_bool)

                if start_date:
                    try:
                        start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                        filters.append(LoginAttempt.attempt_time >= start_dt)
                    except ValueError:
                        return error_response("Invalid start_date format. Use ISO format.", 400)

                if end_date:
                    try:
                        end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                        filters.append(LoginAttempt.attempt_time <= end_dt)
                    except ValueError:
                        return error_response("Invalid end_date format. Use ISO format.", 400)

                if filters:
                    query = query.where(and_(*filters))

                if sort_order == 'asc':
                    query = query.order_by(LoginAttempt.attempt_time.asc())
                else:
                    query = query.order_by(LoginAttempt.attempt_time.desc())

                count_query = select(func.count()).select_from(LoginAttempt)
                if filters:
                    count_query = count_query.where(and_(*filters))
                total = db.scalar(count_query)

                offset = (page - 1) * per_page
                query = query.offset(offset).limit(per_page)

                attempts = db.scalars(query).all()

                logs = []
                for attempt in attempts:
                    logs.append({
                        'id': attempt.id,
                        'ip_address': attempt.ip_address,
                        'username': attempt.username,
                        'attempt_time': attempt.attempt_time.isoformat(),
                        'success': attempt.success,
                        'user_agent': attempt.user_agent
                    })

                total_pages = (total + per_page - 1) // per_page

                logger.info(f"Security logs retrieved: page={page}, total={total}, user={request.username}")

                return success_response({
                    'logs': logs,
                    'total': total,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                })

        except ValueError as e:
            return error_response(f"Invalid parameter: {str(e)}", 400)
        except Exception as e:
            logger.error(f"Get security logs error: {e}")
            return error_response(f"Failed to retrieve security logs: {str(e)}", 500)

    @app.route('/api/admin/security-logs/stats', methods=['GET'])
    @require_role('admin')
    def get_security_stats():
        """Get security statistics - Admin only"""
        try:
            from database.models import LoginAttempt
            from database.session import get_db
            from sqlalchemy import select, func, and_
            from datetime import datetime, timezone, timedelta

            with next(get_db()) as db:
                now = datetime.now(timezone.utc)

                total_attempts = db.scalar(select(func.count()).select_from(LoginAttempt))

                failed_attempts = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.success == False
                    )
                )

                success_rate = ((total_attempts - failed_attempts) / total_attempts * 100) if total_attempts > 0 else 0

                unique_ips = db.scalar(
                    select(func.count(func.distinct(LoginAttempt.ip_address))).select_from(LoginAttempt)
                )

                rate_limit_window = now - timedelta(minutes=15)
                blocked_ips_query = select(func.count(func.distinct(LoginAttempt.ip_address))).select_from(LoginAttempt).where(
                    and_(
                        LoginAttempt.attempt_time > rate_limit_window.replace(tzinfo=None),
                        LoginAttempt.success == False
                    )
                ).group_by(LoginAttempt.ip_address).having(
                    func.count() >= 10
                )
                blocked_ips = len(list(db.execute(blocked_ips_query)))

                most_targeted = db.execute(
                    select(
                        LoginAttempt.username,
                        func.count().label('count')
                    ).where(
                        and_(
                            LoginAttempt.username.isnot(None),
                            LoginAttempt.success == False
                        )
                    ).group_by(LoginAttempt.username).order_by(func.count().desc()).limit(5)
                ).all()

                most_targeted_accounts = [
                    {'username': row[0], 'count': row[1]} for row in most_targeted
                ]

                recent_24h_start = now - timedelta(hours=24)
                recent_24h_total = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.attempt_time > recent_24h_start.replace(tzinfo=None)
                    )
                )
                recent_24h_failed = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        and_(
                            LoginAttempt.attempt_time > recent_24h_start.replace(tzinfo=None),
                            LoginAttempt.success == False
                        )
                    )
                )

                recent_7d_start = now - timedelta(days=7)
                recent_7d_total = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        LoginAttempt.attempt_time > recent_7d_start.replace(tzinfo=None)
                    )
                )
                recent_7d_failed = db.scalar(
                    select(func.count()).select_from(LoginAttempt).where(
                        and_(
                            LoginAttempt.attempt_time > recent_7d_start.replace(tzinfo=None),
                            LoginAttempt.success == False
                        )
                    )
                )

                logger.info(f"Security stats retrieved by user={request.username}")

                return success_response({
                    'total_attempts': total_attempts or 0,
                    'failed_attempts': failed_attempts or 0,
                    'success_rate': round(success_rate, 2),
                    'unique_ips': unique_ips or 0,
                    'blocked_ips': blocked_ips,
                    'most_targeted_accounts': most_targeted_accounts,
                    'recent_24h': {
                        'total': recent_24h_total or 0,
                        'failed': recent_24h_failed or 0
                    },
                    'recent_7d': {
                        'total': recent_7d_total or 0,
                        'failed': recent_7d_failed or 0
                    }
                })

        except Exception as e:
            logger.error(f"Get security stats error: {e}")
            return error_response(f"Failed to retrieve security statistics: {str(e)}", 500)

    @app.route('/api/admin/snapshot-migrations/unowned', methods=['GET'])
    @require_role('admin')
    def list_unowned_snapshot_migrations():
        """List legacy or unowned snapshots that need explicit owner assignment."""
        try:
            snapshots = snapshot_service.list_unowned_snapshots()
            logger.info(
                "Unowned snapshot migration candidates retrieved: count=%s user=%s",
                len(snapshots),
                request.username,
            )
            return success_response(snapshots)
        except Exception as e:
            logger.error(f"Failed to list unowned snapshot migration candidates: {e}")
            return error_response("Failed to list unowned snapshot migration candidates", 500)

    @app.route('/api/admin/snapshot-migrations/assign-owner', methods=['POST'])
    @require_role('admin')
    def assign_unowned_snapshot_owner():
        """Assign one unowned snapshot to a selected active user."""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['snapshot_name', 'owner_user_id'],
                optional_fields=['folder_name', 'dry_run'],
            )

            owner_user_id = validate_positive_integer(data['owner_user_id'], 'owner_user_id')

            dry_run_value = data.get('dry_run', False)
            if isinstance(dry_run_value, bool):
                dry_run = dry_run_value
            elif isinstance(dry_run_value, str) and dry_run_value.lower() in {'true', 'false'}:
                dry_run = dry_run_value.lower() == 'true'
            else:
                return error_response("dry_run must be a boolean", 400)

            from database.models import User
            from database.session import get_db

            with next(get_db()) as db:
                target_user = db.get(User, owner_user_id)
                if not target_user:
                    return error_response("Target owner user not found", 404)
                if not target_user.is_active:
                    return error_response("Target owner user is inactive", 400)

                result = snapshot_service.assign_snapshot_owner(
                    snapshot_name=data['snapshot_name'],
                    owner_user_id=target_user.id,
                    owner_username=target_user.username,
                    folder_name=data.get('folder_name'),
                    dry_run=dry_run,
                )

            logger.info(
                "Snapshot owner migration completed: snapshot=%s owner_user_id=%s dry_run=%s admin=%s",
                result.get('name'),
                result.get('owner_user_id'),
                result.get('dry_run'),
                request.username,
            )
            return success_response(result, "Snapshot owner assignment completed")

        except PermissionError as e:
            return error_response(str(e), 403)
        except FileNotFoundError as e:
            return error_response(str(e), 404)
        except RequestValidationError as e:
            return validation_error_response(e)
        except ValueError as e:
            return error_response(str(e), 400)
        except (BadRequest, UnsupportedMediaType):
            return error_response("Request body must be valid JSON", 400)
        except Exception as e:
            logger.error(f"Failed to assign snapshot owner: {e}")
            return error_response("Failed to assign snapshot owner", 500)

    @app.route('/api/auth/password-reset-request', methods=['POST'])
    def password_reset_request():
        """Request password reset link"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['email'],
                optional_fields=[]
            )

            email = data['email'].strip().lower()

            is_valid, error_msg = validate_email(email)
            if not is_valid:
                # Still return success to prevent enumeration
                return success_response(
                    None,
                    "If the email exists, a password reset link has been sent"
                )

            from database.models import User, PasswordResetToken
            from database.session import get_db
            from sqlalchemy import select
            from datetime import datetime, timezone, timedelta
            import secrets

            with next(get_db()) as db:
                stmt = select(User).where(User.email == email)
                user = db.scalar(stmt)

                if user and user.is_active:
                    reset_token, token = PasswordResetToken.create_for_user(
                        user_id=user.id,
                        expiry_seconds=config.PASSWORD_RESET_TOKEN_EXPIRY
                    )
                    reset_token.ip_address = request.remote_addr
                    db.add(reset_token)
                    db.commit()

                    from utils.email import send_password_reset_email
                    send_password_reset_email(user.email, user.username, token)

                    logger.info(f"Password reset requested for user: {user.username} from {request.remote_addr}")

            # Always return same message (security: prevent email enumeration)
            return success_response(
                None,
                "If the email exists, a password reset link has been sent"
            )

        except Exception as e:
            logger.error(f"Password reset request error: {e}")
            # Still return success to prevent information leakage
            return success_response(
                None,
                "If the email exists, a password reset link has been sent"
            )

    @app.route('/api/auth/password-reset', methods=['POST'])
    def password_reset():
        """Reset password using valid token"""
        try:
            data = validate_json_input(
                request.get_json(),
                required_fields=['token', 'new_password'],
                optional_fields=[]
            )

            token = data['token'].strip()
            new_password = data['new_password']

            if not token:
                return error_response("Token is required", 400)

            from database.models import User, PasswordResetToken
            from database.session import get_db
            from sqlalchemy import select

            with next(get_db()) as db:
                token_hash = PasswordResetToken.hash_token(token)
                stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
                reset_token = db.scalar(stmt)

                if not reset_token or not reset_token.is_valid():
                    return error_response("Invalid or expired reset token", 400)

                is_valid, error_msg = validate_password(new_password)
                if not is_valid:
                    return error_response(error_msg, 400)

                user = reset_token.user

                user.set_password(new_password)

                reset_token.mark_used()

                db.commit()

                logger.info(f"Password reset successful for user: {user.username} from {request.remote_addr}")

                return success_response(None, "Password has been reset successfully")

        except RequestValidationError as e:
            return validation_error_response(e)
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return error_response("Failed to reset password", 500)


@app.route('/api/network/initialize', methods=['POST'])
def initialize_network():
    """Initialize Batfish network with configuration snapshot"""
    try:
        data = request.get_json()
        if not data or ('snapshot_dir' not in data and 'snapshot_name' not in data):
            return error_response("Missing 'snapshot_dir' or 'snapshot_name' in request body", 400)

        snapshot_dir = data.get('snapshot_dir', '')
        snapshot_name = data.get('snapshot_name')

        if config.AUTH_ENABLED:
            snapshot_name = snapshot_name or Path(str(snapshot_dir)).name
            safe_path = snapshot_service.get_snapshot_path(
                snapshot_name,
                **get_snapshot_request_context(),
            )
        else:
            snapshot_name = snapshot_name or os.path.basename(str(snapshot_dir or ''))
            expected_path = snapshot_service.get_snapshot_path(snapshot_name, **get_snapshot_request_context())
            if snapshot_dir:
                requested_path = Path(str(snapshot_dir))
                if not requested_path.is_absolute():
                    requested_path = Path(snapshot_service.snapshots_dir) / requested_path
                if requested_path.resolve() != expected_path.resolve():
                    return error_response(
                        "Invalid snapshot directory: it must be the store directory of the named snapshot", 400,
                    )
            safe_path = expected_path.resolve()
            if not snapshot_has_config_files(safe_path):
                return snapshot_empty_response(snapshot_name)

        snapshot_name = snapshot_name or safe_path.name
        result = activate_batfish_snapshot(safe_path, snapshot_name)
        result['parsed'] = True

        if config.AUTH_ENABLED:
            session['current_snapshot_name'] = result.get('snapshot')

        return success_response(result, "Network initialized successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to initialize network: {e}")
        return snapshot_activation_error_response(snapshot_name, e)


@app.route('/api/network/nodes', methods=['GET'])
def get_nodes():
    """Get all node properties"""
    try:
        nodes = batfish_service.get_node_properties()
        return success_response(nodes)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get nodes: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/interfaces', methods=['GET'])
def get_interfaces():
    """Get all interface properties"""
    try:
        interfaces = batfish_service.get_interface_properties()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/routes', methods=['GET'])
def get_routes():
    """Get all routing table entries"""
    try:
        routes = batfish_service.get_routes()
        return success_response(routes)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get routes: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/processes', methods=['GET'])
def get_ospf_processes():
    """Get OSPF process configurations"""
    try:
        processes = batfish_service.get_ospf_process_configuration()
        return success_response([p.to_dict() for p in processes])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF processes: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/areas', methods=['GET'])
def get_ospf_areas():
    """Get OSPF area configurations"""
    try:
        areas = batfish_service.get_ospf_area_configuration()
        return success_response([a.to_dict() for a in areas])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF areas: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/interfaces', methods=['GET'])
def get_ospf_interfaces():
    """Get OSPF interface configurations"""
    try:
        interfaces = batfish_service.get_ospf_interface_configuration()
        return success_response([i.to_dict() for i in interfaces])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF interfaces: {e}")
        return error_response(str(e), 500)


@app.route('/api/ospf/sessions', methods=['GET'])
def get_ospf_sessions():
    """Get OSPF session compatibility status"""
    try:
        sessions = batfish_service.get_ospf_session_compatibility()
        return success_response([s.to_dict() for s in sessions])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF sessions: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/ospf', methods=['GET'])
def get_ospf_edges():
    """Get OSPF topology edges"""
    try:
        edges = batfish_service.get_ospf_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/physical', methods=['GET'])
def get_physical_edges():
    """Get layer 1 physical edges"""
    try:
        edges = batfish_service.get_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get physical edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/edges/layer3', methods=['GET'])
def get_layer3_edges():
    """Get layer 3 edges"""
    try:
        edges = batfish_service.get_layer3_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer 3 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/vlans', methods=['GET'])
def get_vlans():
    """Get switched VLAN properties"""
    try:
        vlans = batfish_service.get_switched_vlan_properties()
        return success_response(vlans)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VLANs: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/ip-owners', methods=['GET'])
def get_ip_owners():
    """Get IP address ownership mapping"""
    try:
        owners = batfish_service.get_ip_owners()
        return success_response(owners)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IP owners: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/defined-structures', methods=['GET'])
def get_defined_structures():
    """Get defined configuration structures"""
    try:
        structures = batfish_service.get_defined_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get defined structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/referenced-structures', methods=['GET'])
def get_referenced_structures():
    """Get referenced configuration structures"""
    try:
        structures = batfish_service.get_referenced_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get referenced structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/named-structures', methods=['GET'])
def get_named_structures():
    """Get named structures with full definitions"""
    try:
        structures = batfish_service.get_named_structures()
        return success_response([s.to_dict() for s in structures])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get named structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/file-parse-status', methods=['GET'])
def get_file_parse_status():
    """Get file parse status"""
    try:
        statuses = batfish_service.get_file_parse_status()
        return success_response([s.to_dict() for s in statuses])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get file parse status: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/init-issues', methods=['GET'])
def get_init_issues():
    """Get initialization issues"""
    try:
        issues = batfish_service.get_init_issues()
        return success_response([i.to_dict() for i in issues])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get init issues: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/parse-warnings', methods=['GET'])
def get_parse_warnings():
    """Get parse warnings"""
    try:
        warnings = batfish_service.get_parse_warnings()
        return success_response([w.to_dict() for w in warnings])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get parse warnings: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/vi-conversion-status', methods=['GET'])
def get_vi_conversion_status():
    """Get vendor-independent conversion status"""
    try:
        statuses = batfish_service.get_vi_conversion_status()
        return success_response([s.to_dict() for s in statuses])
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VI conversion status: {e}")
        return error_response(str(e), 500)


@app.route('/api/analysis/reachability', methods=['POST'])
def get_reachability():
    """Get reachability analysis results"""
    try:
        data = request.get_json(silent=True) or {}
        headers = data.get('headers') if data else None

        flow_traces = batfish_service.get_reachability(headers)
        return success_response([f.to_dict() for f in flow_traces])
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/analysis/route-policies', methods=['GET'])
def get_route_policies():
    """Search route policies"""
    try:
        nodes = get_query_specifier('nodes') or '.*'
        action = request.args.get('action') or 'permit'

        policies = batfish_service.get_search_route_policies(nodes, action)
        return success_response(policies)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/config/aaa-authentication', methods=['GET'])
def get_aaa_authentication():
    """Get AAA authentication login configuration"""
    try:
        aaa_configs = batfish_service.get_aaa_authentication_login()
        return success_response(aaa_configs)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get AAA authentication: {e}")
        return error_response(str(e), 500)


@app.route('/api/security/snmp-communities', methods=['GET'])
def get_snmp_communities():
    """Get SNMP community configurations for security validation."""
    try:
        snmp_configs = batfish_service.get_snmp_community_clients()
        return success_response(snmp_configs)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get SNMP community clients: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/edges', methods=['GET'])
def get_bgp_edges():
    """Get BGP adjacencies/neighbors topology"""
    try:
        edges = batfish_service.get_bgp_edges()
        return success_response(edges)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/peer-configuration', methods=['GET'])
def get_bgp_peer_configuration():
    """Get BGP peer settings and configurations"""
    try:
        peers = batfish_service.get_bgp_peer_configuration()
        return success_response(peers)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP peer configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/process-configuration', methods=['GET'])
def get_bgp_process_configuration():
    """Get BGP process-wide settings"""
    try:
        processes = batfish_service.get_bgp_process_configuration()
        return success_response(processes)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP process configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/session-status', methods=['GET'])
def get_bgp_session_status():
    """Get BGP session operational status"""
    try:
        sessions = batfish_service.get_bgp_session_status()
        return success_response(sessions)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP session status: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/session-compatibility', methods=['GET'])
def get_bgp_session_compatibility():
    """Get BGP session configuration validation"""
    try:
        compatibility = batfish_service.get_bgp_session_compatibility()
        return success_response(compatibility)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP session compatibility: {e}")
        return error_response(str(e), 500)


@app.route('/api/bgp/rib', methods=['GET'])
def get_bgp_rib():
    """Get BGP Routing Information Base entries"""
    try:
        rib = batfish_service.get_bgp_rib()
        return success_response(rib)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BGP RIB: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/test-filters', methods=['POST'])
def test_filters():
    """Test flows against ACLs/firewall rules"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        if not isinstance(headers, dict) or not headers:
            return error_response("Missing required 'headers' object for testFilters", 400)

        nodes = normalize_batfish_specifier(data.get('nodes'))
        filters = normalize_batfish_specifier(data.get('filters'))
        startLocation = data.get('startLocation')

        results = batfish_service.test_filters(headers, nodes, filters, startLocation)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to test filters: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/filter-line-reachability', methods=['GET'])
def get_filter_line_reachability():
    """Identify unreachable/shadowed ACL lines"""
    try:
        filters = get_query_specifier('filters')
        nodes = get_query_specifier('nodes')
        ignore_composites = parse_optional_bool(request.args.get('ignoreComposites'))

        results = batfish_service.get_filter_line_reachability(
            filters=filters,
            nodes=nodes,
            ignoreComposites=ignore_composites,
        )
        return success_response(results)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get filter line reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/search-filters', methods=['POST'])
def search_filters():
    """Search for flows matching conditions (permit/deny)"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        action = data.get('action')
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))

        results = batfish_service.search_filters(headers, action, filters, nodes)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to search filters: {e}")
        return error_response(str(e), 500)


@app.route('/api/acl/find-matching-lines', methods=['POST'])
def find_matching_filter_lines():
    """Find ACL lines matching specific flows"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))

        results = batfish_service.find_matching_filter_lines(headers, filters, nodes)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to find matching filter lines: {e}")
        return error_response(str(e), 500)


@app.route('/api/path/traceroute', methods=['POST'])
def traceroute():
    """Virtual traceroute through network"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        startLocation = data.get('startLocation')
        ignoreFilters = data.get('ignoreFilters', False)
        maxTraces = data.get('maxTraces')

        results = batfish_service.traceroute(
            headers=headers,
            startLocation=startLocation,
            ignoreFilters=ignoreFilters,
            maxTraces=maxTraces,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run traceroute: {e}")
        return error_response(str(e), 500)


@app.route('/api/path/bidirectional-traceroute', methods=['POST'])
def bidirectional_traceroute():
    """Bidirectional traceroute validation"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        startLocation = data.get('startLocation')
        ignoreFilters = data.get('ignoreFilters', False)
        maxTraces = data.get('maxTraces')

        results = batfish_service.bidirectional_traceroute(
            headers=headers,
            startLocation=startLocation,
            ignoreFilters=ignoreFilters,
            maxTraces=maxTraces,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run bidirectional traceroute: {e}")
        return error_response(str(e), 500)


@app.route('/api/network/all-data', methods=['GET'])
def get_all_data():
    """Fetch all types of Batfish data in one request"""
    try:
        all_data = batfish_service.fetch_all_data()
        all_data['snapshot_version'] = batfish_service.snapshot_version_info()
        return success_response(all_data, "All network data fetched successfully")
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to fetch all data: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/unused-structures', methods=['GET'])
def get_unused_structures():
    """Get unused configuration structures (defined but not referenced)"""
    try:
        unused = batfish_service.get_unused_structures()
        return success_response(unused)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get unused structures: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/undefined-references', methods=['GET'])
def get_undefined_references():
    """Get undefined references (referenced but not defined)"""
    try:
        undefined = batfish_service.get_undefined_references()
        return success_response(undefined)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get undefined references: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-filter-specifier', methods=['POST'])
def resolve_filter_specifier():
    """Resolve filter specifier to actual filters"""
    try:
        data = request.get_json() or {}
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        if not filters:
            return error_response("Missing required 'filters' for resolveFilterSpecifier", 400)

        results = batfish_service.resolve_filter_specifier(filters, nodes, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve filter specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-node-specifier', methods=['POST'])
def resolve_node_specifier():
    """Resolve node specifier to actual nodes"""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_node_specifier(nodes, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve node specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/resolve-interface-specifier', methods=['POST'])
def resolve_interface_specifier():
    """Resolve interface specifier to actual interfaces"""
    try:
        data = request.get_json() or {}
        interfaces = normalize_batfish_specifier(data.get('interfaces'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        grammar_version = data.get('grammarVersion')

        if not interfaces:
            return error_response("Missing required 'interfaces' for resolveInterfaceSpecifier", 400)

        results = batfish_service.resolve_interface_specifier(interfaces, nodes, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve interface specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/detect-loops', methods=['GET'])
def get_detect_loops():
    """Detect forwarding loops in the network"""
    try:
        loops = batfish_service.get_detect_loops()
        return success_response(loops)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to detect loops: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/multipath-consistency', methods=['GET'])
def get_multipath_consistency():
    """Check multipath routing consistency"""
    try:
        consistency = batfish_service.get_multipath_consistency()
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/loopback-multipath-consistency', methods=['GET'])
def get_loopback_multipath_consistency():
    """Check loopback multipath routing consistency"""
    try:
        consistency = batfish_service.get_loopback_multipath_consistency()
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check loopback multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/subnet-multipath-consistency', methods=['POST'])
def get_subnet_multipath_consistency():
    """Subnet multipath consistency check"""
    try:
        data = request.get_json() or {}
        max_traces = data.get('maxTraces')
        consistency = batfish_service.get_subnet_multipath_consistency(maxTraces=max_traces)
        return success_response(consistency)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to check subnet multipath consistency: {e}")
        return error_response(str(e), 500)


@app.route('/api/validation/compare-filters', methods=['POST'])
def compare_filters():
    """Compare filters/ACLs for equivalence"""
    try:
        data = request.get_json() or {}
        filters = normalize_batfish_specifier(data.get('filters'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        ignore_composites = parse_optional_bool(data.get('ignoreComposites'))
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot'))
        snapshot = data.get('snapshot')

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for compare filters", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_filters(
            filters=filters,
            nodes=nodes,
            ignoreComposites=ignore_composites,
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare filters: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/vrrp-properties', methods=['GET'])
def get_vrrp_properties():
    """Get VRRP (Virtual Router Redundancy Protocol) properties"""
    try:
        vrrp = batfish_service.get_vrrp_properties()
        return success_response(vrrp)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VRRP properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/hsrp-properties', methods=['GET'])
def get_hsrp_properties():
    """Get HSRP (Hot Standby Router Protocol) properties"""
    try:
        hsrp = batfish_service.get_hsrp_properties()
        return success_response(hsrp)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get HSRP properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/mlag-properties', methods=['GET'])
def get_mlag_properties():
    """Get MLAG (Multi-chassis LAG) properties"""
    try:
        mlag = batfish_service.get_mlag_properties()
        return success_response(mlag)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get MLAG properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/duplicate-router-ids', methods=['GET'])
def get_duplicate_router_ids():
    """Get duplicate router IDs detected in OSPF or BGP"""
    try:
        duplicates = batfish_service.get_duplicate_router_ids()
        return success_response([d.to_dict() for d in duplicates])
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get duplicate router IDs: {e}")
        return error_response(str(e), 500)


@app.route('/api/ha/switching-properties', methods=['GET'])
def get_switching_properties():
    """Get switching properties"""
    try:
        switching = batfish_service.get_switched_vlan_properties()
        return success_response(switching)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get switching properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/evpn/rib', methods=['GET'])
def get_evpn_rib():
    """Get EVPN Routing Information Base"""
    try:
        evpn_rib = batfish_service.get_evpn_rib()
        return success_response(evpn_rib)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EVPN RIB: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/evpn/vxlan-edges', methods=['GET'])
def get_vxlan_edges():
    """Get VXLAN tunnel edges/topology"""
    try:
        edges = batfish_service.get_vxlan_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VXLAN edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/evpn/vxlan-vni-properties', methods=['GET'])
def get_vxlan_vni_properties():
    """Get VXLAN VNI (Virtual Network Identifier) properties"""
    try:
        vni_props = batfish_service.get_vxlan_vni_properties()
        return success_response(vni_props)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VXLAN VNI properties: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/eigrp/edges', methods=['GET'])
def get_eigrp_edges():
    """Get EIGRP neighbor relationships/topology"""
    try:
        edges = batfish_service.get_eigrp_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EIGRP edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/eigrp/interface-configuration', methods=['GET'])
def get_eigrp_interface_configuration():
    """Get EIGRP interface configuration"""
    try:
        interfaces = batfish_service.get_eigrp_interface_configuration()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get EIGRP interface configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/isis/edges', methods=['GET'])
def get_isis_edges():
    """Get IS-IS neighbor relationships/topology"""
    try:
        edges = batfish_service.get_isis_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IS-IS edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/isis/interface-configuration', methods=['GET'])
def get_isis_interface_configuration():
    """Get IS-IS interface configuration"""
    try:
        interfaces = batfish_service.get_isis_interface_configuration()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IS-IS interface configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/isis-loopback-interfaces', methods=['GET'])
def get_isis_loopback_interfaces():
    """Get IS-IS loopback interfaces"""
    try:
        return success_response([])
    except Exception as e:
        logger.error(f"Failed to get IS-IS loopback interfaces: {e}")
        return error_response(str(e), 500)


@app.route('/api/protocols/bfd-session-status', methods=['GET'])
def get_bfd_session_status():
    """Get BFD session status"""
    try:
        sessions = batfish_service.get_bfd_session_status()
        return success_response(sessions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get BFD session status: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/layer1-edges', methods=['GET'])
def get_layer1_edges():
    """Get Layer 1 physical topology edges"""
    try:
        edges = batfish_service.get_layer1_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer 1 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/layer1-topology', methods=['GET'])
def get_layer1_topology():
    """Get Layer 1 topology"""
    try:
        layer1 = batfish_service.get_layer1_edges()
        return success_response(layer1)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/user-provided-layer1-edges', methods=['POST'])
def get_user_provided_layer1_edges():
    """Get Batfish-normalized user-provided Layer1 edges."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        remote_nodes = normalize_batfish_specifier(data.get('remoteNodes'))

        edges = batfish_service.get_user_provided_layer1_edges(nodes, remote_nodes)
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get user-provided Layer1 edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-session-status', methods=['GET'])
def get_ipsec_session_status():
    """Get IPsec session status"""
    try:
        sessions = batfish_service.get_ipsec_session_status()
        return success_response(sessions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec session status: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-edges', methods=['GET'])
def get_ipsec_edges():
    """Get IPsec VPN edges"""
    try:
        edges = batfish_service.get_ipsec_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ipsec-peer-configuration', methods=['GET'])
def get_ipsec_peer_configuration():
    """Get IPsec peer configuration"""
    try:
        config = batfish_service.get_ipsec_peer_configuration()
        return success_response(config)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IPsec peer configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/layer2-topology', methods=['GET'])
def get_layer2_topology():
    """Get Layer 2 topology"""
    try:
        layer2 = batfish_service.get_layer2_topology()
        return success_response(layer2)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get layer2 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/switched-vlan-edges', methods=['GET'])
def get_switched_vlan_edges():
    """Get switched VLAN topology edges"""
    try:
        edges = batfish_service.get_switched_vlan_edges()
        return success_response(edges)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get switched VLAN edges: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/interface-mtu', methods=['GET'])
def get_interface_mtu():
    """Get interface MTU configurations"""
    try:
        mtu = batfish_service.get_interface_mtu()
        return success_response(mtu)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interface MTU: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/ip-space-assignment', methods=['GET'])
def get_ip_space_assignment():
    """Get IP space assignments across the network"""
    try:
        assignments = batfish_service.get_ip_space_assignment()
        return success_response(assignments)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get IP space assignment: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/lpm-routes', methods=['POST'])
def get_lpm_routes():
    """Get Longest Prefix Match routes for an IP"""
    try:
        data = request.get_json() or {}
        ip = data.get('ip')
        nodes = normalize_batfish_specifier(data.get('nodes'))
        vrfs = normalize_batfish_specifier(data.get('vrfs'), separator='|')

        if not ip:
            return error_response("Missing 'ip' parameter", 400)

        routes = batfish_service.get_lpm_routes(ip, nodes, vrfs)
        return success_response(routes)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get LPM routes: {e}")
        return error_response(str(e), 500)


@app.route('/api/topology/prefix-tracer', methods=['POST'])
def get_prefix_tracer():
    """Trace prefix propagation through network"""
    try:
        data = request.get_json() or {}
        prefix = data.get('prefix')
        nodes = normalize_batfish_specifier(data.get('nodes'))

        if not prefix:
            return error_response("Missing 'prefix' parameter", 400)

        traces = batfish_service.get_prefix_tracer(prefix, nodes)
        return success_response(traces)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to trace prefix: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/differential-reachability', methods=['POST'])
def get_differential_reachability():
    """Get differential reachability analysis"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        reference_snapshot = data.get('reference_snapshot')
        snapshot = data.get('snapshot')
        path_constraints = data.get('pathConstraints')
        actions = data.get('actions')
        max_traces = data.get('maxTraces')
        invert_search = parse_optional_bool(data.get('invertSearch'))
        ignore_filters = parse_optional_bool(data.get('ignoreFilters'))

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for differential reachability", 400)

        reference_snapshot_path = require_snapshot_access(reference_snapshot)
        snapshot_path = require_snapshot_access(snapshot or batfish_service.current_snapshot_name)

        results = batfish_service.get_differential_reachability(
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
            headers=headers,
            pathConstraints=path_constraints,
            actions=actions,
            maxTraces=max_traces,
            invertSearch=invert_search,
            ignoreFilters=ignore_filters,
            reference_snapshot_path=reference_snapshot_path,
            snapshot_path=snapshot_path,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except BatfishSnapshotLoadError as e:
        role = "reference" if e.snapshot_name == reference_snapshot else "snapshot"
        logger.error(f"Failed to load {role} snapshot '{e.snapshot_name}' for differential reachability")
        return snapshot_load_error_response(e, role)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to get differential reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/bidirectional-reachability', methods=['POST'])
def get_bidirectional_reachability():
    """Get bidirectional reachability analysis"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        path_constraints = data.get('pathConstraints')
        return_flow_type = data.get('returnFlowType')

        if not headers:
            return error_response("Missing required 'headers' for bidirectional reachability", 400)

        results = batfish_service.get_bidirectional_reachability(
            headers=headers,
            pathConstraints=path_constraints,
            returnFlowType=return_flow_type,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get bidirectional reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-location-specifier', methods=['POST'])
def resolve_location_specifier():
    """Resolve location specifier to actual locations"""
    try:
        data = request.get_json() or {}
        locations = data.get('locations')
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_location_specifier(locations, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve location specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-ip-specifier', methods=['POST'])
def resolve_ip_specifier():
    """Resolve IP specifier to actual IPs"""
    try:
        data = request.get_json() or {}
        ips = data.get('ips')
        grammar_version = data.get('grammarVersion')

        results = batfish_service.resolve_ip_specifier(ips, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve IP specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/resolve-ips-of-location-specifier', methods=['POST'])
def resolve_ips_of_location_specifier():
    """Resolve location specifier to source IP spaces."""
    try:
        data = request.get_json() or {}
        locations = data.get('locations')
        grammar_version = data.get('grammarVersion')

        if not locations:
            return error_response("Missing required 'locations' for resolveIpsOfLocationSpecifier", 400)

        results = batfish_service.resolve_ips_of_location_specifier(locations, grammar_version)
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to resolve IPs of location specifier: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/f5-bigip-vip-configuration', methods=['GET'])
def get_f5_bigip_vip_configuration():
    """Get F5 BIG-IP VIP configuration"""
    try:
        vip_config = batfish_service.get_f5_bigip_vip_configuration()
        return success_response(vip_config)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get F5 VIP configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/a10-virtual-server-configuration', methods=['POST'])
def get_a10_virtual_server_configuration():
    """Get A10 virtual server configuration."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        virtual_server_ips = data.get('virtualServerIps')

        virtual_servers = batfish_service.get_a10_virtual_server_configuration(
            nodes=nodes,
            virtualServerIps=virtual_server_ips,
        )
        return success_response(virtual_servers)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get A10 virtual server configuration: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/route-policies', methods=['GET'])
def get_route_policies_advanced():
    """Get route policies/maps configuration"""
    try:
        nodes = request.args.get('nodes')

        policies = batfish_service.get_route_policies(nodes)
        return success_response(policies)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/test-route-policies', methods=['POST'])
def test_route_policies():
    """Test route policies against input routes"""
    try:
        data = request.get_json() or {}
        direction = data.get('direction')
        inputRoutes = data.get('inputRoutes', data.get('inputRoute'))
        nodes = normalize_batfish_specifier(data.get('nodes'))
        policies = normalize_batfish_specifier(data.get('policies'))
        bgpSessionProperties = data.get('bgpSessionProperties')

        if not direction:
            return error_response("Missing required 'direction' for testRoutePolicies", 400)
        if inputRoutes is None:
            return error_response("Missing required 'inputRoutes' for testRoutePolicies", 400)

        results = batfish_service.test_route_policies(
            direction=parse_route_policy_direction(direction),
            inputRoutes=parse_bgp_input_routes(inputRoutes),
            nodes=nodes,
            policies=policies,
            bgpSessionProperties=bgpSessionProperties,
        )
        return success_response(results)
    except RequestValidationError as e:
        return validation_error_response(e)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to test route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/transfer-bdd-validation', methods=['POST'])
def transfer_bdd_validation():
    """Run symbolic route policy transfer BDD validation."""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes'))
        policies = normalize_batfish_specifier(data.get('policies'))
        retain_all_paths = parse_optional_bool(data.get('retainAllPaths'))
        seed = data.get('seed')

        if seed is not None:
            if isinstance(seed, bool):
                return error_response("'seed' must be an integer", 400)
            if isinstance(seed, int):
                pass
            elif isinstance(seed, str) and re.fullmatch(r'-?\d+', seed.strip()):
                seed = int(seed.strip())
            else:
                return error_response("'seed' must be an integer", 400)

        results = batfish_service.get_transfer_bdd_validation(
            nodes=nodes,
            policies=policies,
            retainAllPaths=retain_all_paths,
            seed=seed,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to run transfer BDD validation: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/compare-peer-group-policies', methods=['GET', 'POST'])
def compare_peer_group_policies():
    """Compare peer group policies."""
    try:
        data = request.get_json(silent=True) or {}
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot', request.args.get('reference_snapshot')))
        snapshot = data.get('snapshot', request.args.get('snapshot'))

        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for comparePeerGroupPolicies", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_peer_group_policies(
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare peer group policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/compare-route-policies', methods=['POST'])
def compare_route_policies():
    """Compare symbolic behavior of two route policies."""
    try:
        data = request.get_json() or {}
        policy = data.get('policy')
        reference_policy = data.get('referencePolicy')
        nodes = normalize_batfish_specifier(data.get('nodes'))
        reference_snapshot = data.get('reference_snapshot', data.get('referenceSnapshot'))
        snapshot = data.get('snapshot')

        if not policy:
            return error_response("Missing required 'policy' for compareRoutePolicies", 400)
        if not reference_policy:
            return error_response("Missing required 'referencePolicy' for compareRoutePolicies", 400)
        if not reference_snapshot:
            return error_response("Missing required 'reference_snapshot' for compareRoutePolicies", 400)

        require_snapshot_access(reference_snapshot)
        require_snapshot_access(snapshot)

        results = batfish_service.compare_route_policies(
            policy,
            reference_policy,
            nodes,
            reference_snapshot=reference_snapshot,
            snapshot=snapshot,
        )
        return success_response(results)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except PermissionError:
        return error_response("Snapshot access denied", 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to compare route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/questions', methods=['GET'])
def get_questions():
    """Get list of available Batfish questions"""
    try:
        questions = batfish_service.get_questions()
        return success_response(questions)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get questions: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/node-roles', methods=['GET'])
def get_node_roles():
    """Get node role definitions"""
    try:
        roles = batfish_service.get_node_roles()
        return success_response(roles)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get node roles: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/interface-blacklist', methods=['GET'])
def get_interface_blacklist():
    """Get interface blacklist configuration"""
    try:
        blacklist = batfish_service.get_interface_blacklist()
        return success_response(blacklist)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get interface blacklist: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/vi-model', methods=['GET'])
def get_vi_model():
    """Get Vendor Independent model"""
    try:
        vi_model = batfish_service.get_vi_model()
        return success_response(vi_model)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get VI model: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/search-route-policies', methods=['POST'])
def advanced_search_route_policies():
    """Search route policies"""
    try:
        data = request.get_json() or {}
        nodes = normalize_batfish_specifier(data.get('nodes', '.*'))
        action = data.get('action', 'permit')
        policies = normalize_batfish_specifier(data.get('policies'))
        input_constraints = data.get('inputConstraints')
        output_constraints = data.get('outputConstraints')
        per_path = parse_optional_bool(data.get('perPath'))
        path_option = parse_search_route_policies_path_option(data.get('pathOption'))
        if path_option is not None:
            if per_path:
                raise RequestValidationError(
                    "'perPath' and 'pathOption' cannot both be set; use pathOption 'PER_PATH' instead of perPath",
                    field="pathOption",
                )
            per_path = None

        results = batfish_service.get_search_route_policies(
            nodes=nodes,
            action=action,
            policies=policies,
            inputConstraints=input_constraints,
            outputConstraints=output_constraints,
            perPath=per_path,
            pathOption=path_option,
        )
        return success_response(results)
    except RequestValidationError as e:
        return validation_error_response(e)
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to search route policies: {e}")
        return error_response(str(e), 500)


@app.route('/api/advanced/reduce-reachability', methods=['POST'])
def reduce_reachability():
    """Reduced reachability analysis"""
    try:
        data = request.get_json() or {}
        headers = data.get('headers')
        path_constraints = data.get('pathConstraints')
        actions = data.get('actions')
        max_traces = data.get('maxTraces')
        invert_search = parse_optional_bool(data.get('invertSearch'))
        ignore_filters = parse_optional_bool(data.get('ignoreFilters'))

        flow_traces = batfish_service.get_reachability(
            headers=headers,
            pathConstraints=path_constraints,
            actions=actions,
            maxTraces=max_traces,
            invertSearch=invert_search,
            ignoreFilters=ignore_filters,
        )
        return success_response([f.to_dict() for f in flow_traces])
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except RuntimeError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get reduced reachability: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots', methods=['GET'])
def list_snapshots():
    """List all available snapshots"""
    try:
        snapshots = snapshot_service.list_snapshots(**get_snapshot_request_context())
        active_snapshot_name = (
            session.get('current_snapshot_name') if config.AUTH_ENABLED else batfish_service.current_snapshot_name
        )
        for snapshot in snapshots:
            snapshot['active'] = snapshot['name'] == active_snapshot_name
        return success_response(snapshots)
    except PermissionError as e:
        return error_response(str(e), 403)
    except Exception as e:
        logger.error(f"Failed to list snapshots: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots', methods=['POST'])
def create_snapshot():
    """Create a new empty snapshot"""
    try:
        data = request.get_json()
        if not data or 'name' not in data:
            return error_response("Missing 'name' in request body", 400)

        name = data['name']
        folder_name = data.get('folder_name')
        snapshot = snapshot_service.create_snapshot(
            name,
            folder_name=folder_name,
            **get_snapshot_creation_context(),
        )

        return success_response(snapshot, "Snapshot created successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to create snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>', methods=['PATCH'])
def update_snapshot(name: str):
    """Update snapshot metadata such as folder classification."""
    try:
        data = request.get_json()
        if data is None or 'folder_name' not in data:
            return error_response("Missing 'folder_name' in request body", 400)

        snapshot = snapshot_service.update_snapshot_metadata(
            name,
            folder_name=data.get('folder_name'),
            **get_snapshot_request_context(),
        )

        return success_response(snapshot, "Snapshot updated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>', methods=['DELETE'])
def delete_snapshot(name: str):
    """Delete a snapshot"""
    try:
        # Serialized with Batfish requests so that an activation in progress
        # cannot leave the deleted snapshot active.
        with batfish_request_lock:
            snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
            purged_snapshot_id = resolve_snapshot_id_for_history_purge(snapshot_path)
            owner_scope = request_owner_scope()
            snapshot_service.delete_snapshot(name, **get_snapshot_request_context())
            snapshot_state_service.drop_name_marks(name)
            if purged_snapshot_id is not None:
                snapshot_history_service.remove_staging_copy(purged_snapshot_id, snapshot_path.name)

            if config.AUTH_ENABLED and session.get('current_snapshot_name') == name:
                session.pop('current_snapshot_name', None)

            if (
                batfish_service.network_name == get_batfish_request_network_name()
                and batfish_service.current_snapshot_name == name
            ):
                batfish_service.clear_active_snapshot()
                logger.info("Cleared the active Batfish snapshot after deletion: snapshot=%s", name)
                if not config.AUTH_ENABLED:
                    snapshot_state_service.clear_active_snapshot_file()

            if not config.AUTH_ENABLED:
                snapshot_state_service.clear_active_snapshot_file(snapshot_path.name)

        if purged_snapshot_id is not None and snapshot_history_service.delete_all_for_snapshot(
            purged_snapshot_id, snapshot_path.name, owner_scope, False,
        ):
            snapshot_state_service.clear_versioning_unavailable(snapshot_state_service.id_key(purged_snapshot_id))

        return success_response({"name": name}, "Snapshot deleted successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except Exception as e:
        logger.error(f"Failed to delete snapshot: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files', methods=['GET'])
def get_snapshot_files(name: str):
    """Get list of files in a snapshot"""
    try:
        files = snapshot_service.get_snapshot_files(name, **get_snapshot_request_context())
        return success_response(files)

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot files: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>/content', methods=['GET'])
def get_snapshot_file_content(name: str, filename: str):
    """Get one uploaded snapshot config file's UTF-8 content."""
    try:
        file_content = snapshot_service.get_config_file_content(
            name,
            filename,
            **get_snapshot_request_context(),
        )
        return success_response(file_content, "Snapshot file content retrieved successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot file content: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>/content', methods=['PUT'])
def update_snapshot_file_content(name: str, filename: str):
    """Replace one uploaded snapshot config file's UTF-8 content."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        content = data.get('content')
        expected_sha256 = data.get('expected_sha256')
        if not isinstance(content, str):
            return error_response("Missing or invalid 'content' in request body", 400)
        if not isinstance(expected_sha256, str) or not expected_sha256:
            return error_response("Missing or invalid 'expected_sha256' in request body", 400)
        if not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
            raise ValueError("expected_sha256 must be a 64-character lowercase hexadecimal string")

        file_info = snapshot_service.update_config_file_content(
            name,
            filename,
            content,
            expected_sha256,
            **get_snapshot_request_context(),
        )
        return success_response(file_info, "Snapshot file content updated successfully")

    except RequestEntityTooLarge:
        raise
    except ConfigContentConflictError:
        return error_response(
            "Config file changed since it was opened. Reload the file before saving again.",
            409,
            code="config_content_conflict",
        )
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot file content: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files', methods=['POST'])
def upload_snapshot_file(name: str):
    """
    Upload a configuration file to a snapshot

    Multipart form data with 'file' field
    """
    try:
        if 'file' not in request.files:
            return error_response("No file provided", 400)

        file = request.files['file']
        if file.filename == '':
            return error_response("No file selected", 400)

        file_info = snapshot_service.upload_file(
            name,
            file,
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "File uploaded successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>/format', methods=['PATCH'])
def update_snapshot_file_format(name: str, filename: str):
    """Update a snapshot file's Batfish configuration format override."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        if 'configuration_format_override' not in data:
            return error_response("Missing 'configuration_format_override' in request body", 400)

        file_info = snapshot_service.update_snapshot_file_format(
            name,
            filename,
            data.get('configuration_format_override'),
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "Snapshot file format updated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot file format: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/files/<filename>', methods=['DELETE'])
def delete_snapshot_file(name: str, filename: str):
    """Delete one uploaded file from a snapshot."""
    try:
        file_info = snapshot_service.delete_snapshot_file(
            name,
            filename,
            **get_snapshot_request_context(),
        )

        return success_response(file_info, "Snapshot file deleted successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to delete snapshot file: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifact-types', methods=['GET'])
def get_snapshot_artifact_types(name: str):
    """Get typed Batfish artifact definitions for an accessible snapshot."""
    try:
        artifact_types = snapshot_service.get_artifact_types(name, **get_snapshot_request_context())
        return success_response(artifact_types, "Snapshot artifact types retrieved successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot artifact types: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifact-tree', methods=['GET'])
def get_snapshot_artifact_tree(name: str):
    """Get indexed Batfish artifacts for a snapshot."""
    try:
        artifact_tree = snapshot_service.get_artifact_tree(name, **get_snapshot_request_context())
        return success_response(artifact_tree, "Snapshot artifact tree retrieved successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot artifact tree: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts/preview-change', methods=['POST'])
def preview_snapshot_artifact_change(name: str):
    """Preview a typed artifact mutation before writing to disk."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        preview = snapshot_service.preview_artifact_change(
            name,
            data,
            **get_snapshot_request_context(),
        )
        return success_response(preview, "Snapshot artifact change previewed successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to preview snapshot artifact change: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts', methods=['POST'])
def upload_snapshot_artifact(name: str):
    """Upload a typed Batfish artifact to a snapshot."""
    try:
        if 'file' not in request.files:
            return error_response("No artifact file provided", 400)

        artifact_type = request.form.get('artifact_type')
        metadata = request.form.get('metadata')
        preview_token = request.form.get('preview_token')
        artifact = snapshot_service.upload_artifact(
            name,
            artifact_type,
            request.files['file'],
            metadata=metadata,
            preview_token=preview_token,
            **get_snapshot_request_context(),
        )
        return success_response(artifact, "Snapshot artifact uploaded successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to upload snapshot artifact: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts/<artifact_id>', methods=['PATCH'])
def update_snapshot_artifact(name: str, artifact_id: str):
    """Update metadata for a typed artifact, relocating it when safe."""
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        artifact = snapshot_service.update_artifact_metadata(
            name,
            artifact_id,
            data,
            **get_snapshot_request_context(),
        )
        return success_response(artifact, "Snapshot artifact updated successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to update snapshot artifact: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts/<artifact_id>/content', methods=['PUT'])
def replace_snapshot_artifact_content(name: str, artifact_id: str):
    """Replace typed artifact file content without changing its destination."""
    try:
        if 'file' not in request.files:
            return error_response("No artifact file provided", 400)

        artifact = snapshot_service.replace_artifact_content(
            name,
            artifact_id,
            request.files['file'],
            preview_token=request.form.get('preview_token'),
            **get_snapshot_request_context(),
        )
        return success_response(artifact, "Snapshot artifact content replaced successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to replace snapshot artifact content: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts/<artifact_id>', methods=['DELETE'])
def delete_snapshot_artifact(name: str, artifact_id: str):
    """Delete one typed artifact file from a snapshot."""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return error_response("Request body must be a JSON object", 400)

        result = snapshot_service.delete_artifact(
            name,
            artifact_id,
            preview_token=data.get('preview_token'),
            **get_snapshot_request_context(),
        )
        return success_response(result, "Snapshot artifact deleted successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to delete snapshot artifact: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/artifacts/validate', methods=['POST'])
def validate_snapshot_artifacts(name: str):
    """Validate typed artifact layout for a snapshot."""
    try:
        result = snapshot_service.validate_snapshot_artifacts(
            name,
            **get_snapshot_request_context(),
        )
        return success_response(result, "Snapshot artifacts validated successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to validate snapshot artifacts: {e}")
        return error_response(str(e), 500)


def activate_if_stale(name: str, snapshot_path: Path) -> tuple | None:
    """Answer an if_stale activation without parsing when Batfish holds the working content, or answer a
    negative-cached failure of that content after deselecting the snapshot; None parses."""
    try:
        state = snapshot_state_service.evaluate_snapshot(snapshot_path)
        working_hash = state.content_hash
        snapshot_id = state.snapshot_id
    except Exception:
        working_hash = None
        snapshot_id = None
    if working_hash is None:
        return None

    holds_working_content = (
        batfish_service._initialized
        and batfish_service.current_snapshot_name == name
        and batfish_service.loaded_content_hash == working_hash
    ) or live_marker_matches(name, working_hash)
    if holds_working_content and batfish_service.activation_payload is not None:
        if config.AUTH_ENABLED:
            session['current_snapshot_name'] = name
        return success_response(
            {**batfish_service.activation_payload, 'parsed': False}, f"Snapshot '{name}' activated successfully",
        )

    failure = batfish_service.activation_failures.get(activation_failure_key(snapshot_id, name, working_hash))
    if failure is not None:
        clear_current_snapshot_after_failure(name)
        return snapshot_activation_error_response(name, failure)
    return None


@app.route('/api/snapshots/<name>/activate', methods=['POST'])
def activate_snapshot(name: str):
    """Activate a snapshot (initialize Batfish with this snapshot)"""
    data = read_json_object_body(required=False)
    if data is None:
        return invalid_json_body_response()
    if_stale = data.get('if_stale', False)
    if not isinstance(if_stale, bool):
        return validation_error_response(RequestValidationError("'if_stale' must be a boolean", field="if_stale"))

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
        if not snapshot_has_config_files(snapshot_path):
            return snapshot_empty_response(name)

        if if_stale:
            stale_response = activate_if_stale(name, snapshot_path)
            if stale_response is not None:
                return stale_response

        result = activate_batfish_snapshot(snapshot_path, name)
        result['parsed'] = True

        if config.AUTH_ENABLED:
            session['current_snapshot_name'] = name

        return success_response(result, f"Snapshot '{name}' activated successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        import traceback
        logger.error(f"Failed to activate snapshot: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return snapshot_activation_error_response(name, e)


VERSION_LIST_DEFAULT_LIMIT = 50
VERSION_LIST_MAX_LIMIT = 200
VERSION_LIST_MAX_OFFSET = 2 ** 63 - 1
VERSION_MESSAGE_MAX_LENGTH = 500
VERSION_DELETE_MODES = ('all', 'oldest', 'newest')
_DECIMAL_DIGITS_PATTERN = re.compile(r'[0-9]+')


def versioning_unavailable_response(reason: str) -> tuple:
    return error_response(
        "Snapshot versioning is unavailable",
        503,
        code="versioning_unavailable",
        details={"reason": reason},
    )


def snapshot_authorization_error_response(error: Exception) -> tuple:
    """Map the authorization step of a version route to 403, 404 snapshot_not_found or 400."""
    if isinstance(error, PermissionError):
        return error_response(str(error), 403)
    if isinstance(error, FileNotFoundError):
        return error_response(str(error), 404, code="snapshot_not_found")
    return error_response(str(error), 400)


def versioning_error_response(error: Exception, action: str) -> tuple:
    """Map a failure after the authorization step of a version route to its response."""
    if isinstance(error, VersioningUnavailableError):
        return versioning_unavailable_response(error.reason)
    if isinstance(error, VersionNotFoundError):
        return error_response("Version not found for this snapshot", 404, code="version_not_found")
    if isinstance(error, NamespaceNotFoundError):
        return error_response("Namespace not found", 404, code="namespace_not_found")
    if isinstance(error, VersionUnchangedError):
        return error_response(str(error), 409, code="version_unchanged")
    if isinstance(error, VersionConflictError):
        return error_response(str(error), 409, code="version_conflict")
    if is_database_error(error, db_manager):
        return versioning_unavailable_response('database')
    log_failure_cause(f"Failed to {action}", error.__cause__ or error)
    return error_response(f"Failed to {action}", 500)


def log_failure_cause(failure: str, cause: BaseException) -> None:
    """Log a failure with its cause's type, and with the cause's text unless it is a database error."""
    if is_database_error(cause, db_manager):
        logger.error("%s: %s", failure, type(cause).__name__)
    else:
        logger.error("%s: %s: %s", failure, type(cause).__name__, cause)


def restore_error_response(error: Exception) -> tuple:
    """Map a failure of the restore route after its authorization step; unmapped failures are restore_failed."""
    if isinstance(error, PathClashError):
        return error_response(
            str(error),
            409,
            code="version_conflict",
            details={"reason": "path_clash", "path": error.path},
        )
    if isinstance(error, (VersioningUnavailableError, VersionNotFoundError, VersionConflictError)) or (
        is_database_error(error, db_manager)
    ):
        return versioning_error_response(error, "restore snapshot version")
    log_failure_cause("Failed to restore snapshot version", error.__cause__ or error)
    return error_response("Failed to restore snapshot version", 500, code="restore_failed")


def batfish_loaded_state(snapshot_name: str, working_hash: str | None) -> dict[str, Any]:
    """Report what Batfish has loaded for the snapshot in the requester's network context."""
    network_name = get_batfish_request_network_name()
    context_matches = (
        batfish_service._initialized
        and batfish_service.current_snapshot_name == snapshot_name
        and batfish_service.network_name == network_name
    )
    live_marker = getattr(batfish_service, 'live_loaded', None)
    loaded_live = bool(
        batfish_service._initialized
        and live_marker is not None
        and working_hash is not None
        and tuple(live_marker[:3]) == (network_name, snapshot_name, working_hash)
    )
    return {
        'loaded_content_hash': getattr(batfish_service, 'loaded_content_hash', None) if context_matches else None,
        'loaded_batfish_version': (
            getattr(batfish_service, 'loaded_batfish_version', None) if context_matches else None
        ),
        'loaded_live': loaded_live,
    }


def parse_version_list_parameter(name: str, default: int, minimum: int, maximum: int | None = None) -> int:
    raw_value = request.args.get(name)
    if raw_value is None:
        return default
    if not _DECIMAL_DIGITS_PATTERN.fullmatch(raw_value):
        raise RequestValidationError(f"'{name}' must be a non-negative integer", field=name)
    digits = raw_value.lstrip('0') or '0'
    if len(digits) > len(str(VERSION_LIST_MAX_OFFSET)):
        value = VERSION_LIST_MAX_OFFSET + 1
    else:
        value = int(digits)
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise RequestValidationError(f"'{name}' must be {bounds}", field=name)
    return value


def parse_version_message(value: Any) -> str:
    if not isinstance(value, str):
        raise RequestValidationError("'message' must be a string", field="message")
    message = value.strip()
    if not message:
        raise RequestValidationError("'message' must not be empty", field="message")
    if len(message) > VERSION_MESSAGE_MAX_LENGTH:
        raise RequestValidationError(
            f"'message' must be at most {VERSION_MESSAGE_MAX_LENGTH} characters", field="message"
        )
    return message


def parse_expected_head(data: dict[str, Any]) -> Any:
    if 'expected_head' not in data:
        return EXPECTED_HEAD_UNSET
    value = data['expected_head']
    if value is None or isinstance(value, str):
        return value
    raise RequestValidationError("'expected_head' must be a string or null", field="expected_head")


def read_json_object_body(required: bool) -> dict[str, Any] | None:
    """Return the request body as a JSON object ({} for an optional empty body), or None when it is not one."""
    if not request.get_data(cache=True).strip():
        return None if required else {}
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def invalid_json_body_response() -> tuple:
    return error_response(
        "Request body must be a JSON object",
        400,
        code="invalid_json",
        hints=["Send a JSON object with Content-Type: application/json."],
    )


def parse_json_integer(data: dict[str, Any], name: str, minimum: int) -> int | None:
    """Return an optional JSON integer field of at least minimum; booleans, null and other types are rejected."""
    if name not in data:
        return None
    value = data[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        kind = "a positive" if minimum > 0 else "a non-negative"
        raise RequestValidationError(f"'{name}' must be {kind} integer", field=name)
    return value


def parse_required_query_string(name: str) -> str:
    value = request.args.get(name)
    if not value:
        raise RequestValidationError(f"'{name}' is required", field=name)
    return value


def parse_json_string(data: dict[str, Any], name: str) -> str | None:
    if name not in data:
        return None
    value = data[name]
    if not isinstance(value, str):
        raise RequestValidationError(f"'{name}' must be a string", field=name)
    return value


def current_namespace_refusal_response() -> tuple:
    return validation_error_response(
        RequestValidationError("The current namespace cannot be purged", field="namespace")
    )


def resolve_snapshot_id_for_history_purge(snapshot_path: Path) -> str | None:
    """Resolve the snapshot_id whose history a snapshot deletion purges, or None when the purge is skipped."""
    try:
        return snapshot_state_service.resolve_available_snapshot(snapshot_path, allowed_reason='missing_objects')
    except VersioningUnavailableError as e:
        cause = f"snapshot versioning is unavailable ({e.reason})"
    except Exception as e:
        cause = f"its identity could not be resolved ({type(e).__name__})"
    logger.warning(
        "Snapshot %s: its history is not purged with the snapshot because %s; the orphan scan and the admin "
        "purge handle the rows",
        snapshot_path.name,
        cause,
    )
    return None


def current_version_author() -> dict[str, Any] | None:
    if not config.AUTH_ENABLED:
        return None
    try:
        user_id = snapshot_service._normalize_owner_user_id(getattr(request, 'user_id', None))
    except ValueError:
        user_id = None
    return {'user_id': user_id, 'username': getattr(request, 'username', None)}


@app.route('/api/snapshots/<name>/version-state', methods=['GET'])
def get_snapshot_version_state(name: str):
    """Report the snapshot's working content hash, head version and loaded Batfish state."""
    try:
        state = snapshot_state_service.get_state(name, get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)
    except Exception as e:
        return versioning_error_response(e, "evaluate snapshot version state")

    return success_response({
        'snapshot_id': state.snapshot_id,
        'content_hash': state.content_hash,
        **batfish_loaded_state(state.snapshot_name, state.content_hash),
        'result_cache_enabled': snapshot_state_service.result_cache_enabled,
        'head': state.head,
        'uncommitted': state.uncommitted,
        'pending_external': state.pending_external,
        'external_settling': state.external_settling,
        'restored_from': state.restored_from,
    })


@app.route('/api/snapshots/<name>/versions', methods=['GET'])
def list_snapshot_versions(name: str):
    """List a snapshot's versions, newest first."""
    try:
        limit = parse_version_list_parameter('limit', VERSION_LIST_DEFAULT_LIMIT, 1, VERSION_LIST_MAX_LIMIT)
        offset = min(parse_version_list_parameter('offset', 0, 0), VERSION_LIST_MAX_OFFSET)
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        versions = snapshot_history_service.list_versions(snapshot_id, limit=limit, offset=offset)
    except Exception as e:
        return versioning_error_response(e, "list snapshot versions")
    return success_response(versions)


@app.route('/api/snapshots/<name>/versions', methods=['POST'])
def commit_snapshot_version(name: str):
    """Commit the snapshot's working tree as a new version."""
    data = read_json_object_body(required=True)
    if data is None:
        return invalid_json_body_response()
    try:
        message = parse_version_message(data.get('message'))
        expected_head = parse_expected_head(data)
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        version = snapshot_history_service.commit(
            snapshot_id,
            snapshot_path,
            message,
            author=current_version_author(),
            expected_head=expected_head,
        )
    except Exception as e:
        return versioning_error_response(e, "commit snapshot version")

    logger.info("Committed snapshot version: snapshot=%s seq=%s files=%s", name, version['seq'], version['file_count'])
    return success_response(version, "Snapshot version created", status_code=201)


@app.route('/api/snapshots/<name>/versions/<version_id>', methods=['GET'])
def get_snapshot_version(name: str, version_id: str):
    """Get one version of a snapshot with its file manifest."""
    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        version = snapshot_history_service.get_version(snapshot_id, version_id)
    except Exception as e:
        return versioning_error_response(e, "get snapshot version")
    return success_response(version)


@app.route('/api/snapshots/<name>/versions/<version_id>/diff', methods=['GET'])
def get_snapshot_version_diff(name: str, version_id: str):
    """List the files changed from a version to another version of the snapshot or to the working tree."""
    try:
        against = parse_required_query_string('against')
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        diff = snapshot_history_service.diff_summary(snapshot_id, snapshot_path, version_id, against)
    except Exception as e:
        return versioning_error_response(e, "diff snapshot version")
    return success_response(diff)


@app.route('/api/snapshots/<name>/versions/<version_id>/diff/file', methods=['GET'])
def get_snapshot_version_file_diff(name: str, version_id: str):
    """Return one file's unified diff hunks from a version to another version or to the working tree."""
    try:
        against = parse_required_query_string('against')
        path = parse_required_query_string('path')
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        diff = snapshot_history_service.diff_file(snapshot_id, snapshot_path, version_id, against, path)
    except InvalidDiffPathError as e:
        return validation_error_response(RequestValidationError(str(e), field='path'))
    except Exception as e:
        return versioning_error_response(e, "diff snapshot version file")
    return success_response(diff)


@app.route('/api/snapshots/<name>/versions/<version_id>/restore', methods=['POST'])
def restore_snapshot_version(name: str, version_id: str):
    """Write a version's files into the snapshot's working tree, leaving the change uncommitted."""
    data = read_json_object_body(required=False)
    if data is None:
        return invalid_json_body_response()
    try:
        expected_working_hash = parse_json_string(data, 'expected_working_hash')
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        result = snapshot_history_service.restore(snapshot_id, snapshot_path, version_id, expected_working_hash)
    except Exception as e:
        return restore_error_response(e)

    logger.info("Restored snapshot version: snapshot=%s seq=%s", name, result['restored_from']['seq'])
    return success_response(result, "Snapshot version restored")


@app.route('/api/snapshots/<name>/versions/<version_id>', methods=['DELETE'])
def delete_snapshot_version(name: str, version_id: str):
    """Delete one version of a snapshot."""
    data = read_json_object_body(required=False)
    if data is None:
        return invalid_json_body_response()
    try:
        expected_head = parse_expected_head(data)
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(snapshot_path)
        result = snapshot_history_service.delete_versions(
            snapshot_id, snapshot_path, 'single', version_id=version_id, expected_head=expected_head,
            owner_scope=request_owner_scope(),
        )
    except Exception as e:
        return versioning_error_response(e, "delete snapshot version")

    logger.info("Deleted snapshot version: snapshot=%s deleted=%s", name, result['deleted'])
    return success_response(result, "Snapshot version deleted")


@app.route('/api/snapshots/<name>/versions', methods=['DELETE'])
def delete_snapshot_versions(name: str):
    """Delete all, the oldest or the newest versions of a snapshot."""
    data = read_json_object_body(required=True)
    if data is None:
        return invalid_json_body_response()
    try:
        mode = data.get('mode')
        if not isinstance(mode, str) or mode not in VERSION_DELETE_MODES:
            raise RequestValidationError("'mode' must be one of all, oldest, newest", field="mode")
        count = parse_json_integer(data, 'count', 1)
        expected_total = parse_json_integer(data, 'expected_total', 0)
        expected_head = parse_expected_head(data)
        expected_unavailable = parse_json_string(data, 'expected_unavailable')
        if mode != 'all' and count is None:
            raise RequestValidationError("'count' is required for the oldest and newest modes", field="count")
    except RequestValidationError as e:
        return validation_error_response(e)

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_id = snapshot_state_service.resolve_available_snapshot(
            snapshot_path, allowed_reason='missing_objects' if mode == 'all' else None,
        )
        result = snapshot_history_service.delete_versions(
            snapshot_id,
            snapshot_path,
            mode,
            count=None if mode == 'all' else count,
            expected_head=expected_head,
            expected_total=None if mode == 'all' else expected_total,
            expected_unavailable=expected_unavailable,
            owner_scope=request_owner_scope(),
        )
    except Exception as e:
        return versioning_error_response(e, "delete snapshot versions")

    logger.info("Deleted snapshot versions: snapshot=%s mode=%s deleted=%s", name, mode, result['deleted'])
    return success_response(result, "Snapshot versions deleted")


@app.route('/api/snapshots/<name>/cache/clear', methods=['POST'])
def clear_snapshot_result_cache(name: str):
    """Invalidate the snapshot's cached results of its working content, removing them unless another snapshot
    shares that content, and request a re-parse."""
    data = read_json_object_body(required=False)
    if data is None:
        return invalid_json_body_response()

    try:
        snapshot_path = snapshot_service.get_snapshot_path(name, **get_snapshot_request_context())
    except (PermissionError, FileNotFoundError, ValueError) as e:
        return snapshot_authorization_error_response(e)

    try:
        snapshot_state_service.resolve_available_snapshot(snapshot_path)
    except Exception as e:
        return versioning_error_response(e, "clear cached results")
    if not snapshot_state_service.result_cache_enabled:
        return success_response({'cleared': False}, "The result cache is disabled")

    try:
        state = snapshot_state_service.evaluate_snapshot(snapshot_path)
        if state.content_hash is None:
            snapshot_state_service.request_reparse(state.snapshot_id)
            return success_response({'cleared': False}, "Snapshot content is not settled yet; it is re-parsed")
        owner_scope = request_owner_scope()
        if owner_scope is None:
            raise VersioningUnavailableError('database')
        shared = snapshot_history_service.working_hash_shared(state.snapshot_id, state.content_hash, owner_scope)
        snapshot_state_service.record_cache_clear(state.snapshot_id)
        result_cache.clear_snapshot_cache(state.content_hash, owner_scope, keep_if_shared=shared)
    except Exception as e:
        return versioning_error_response(e, "clear cached results")

    logger.info("Cleared cached results: snapshot=%s", name)
    return success_response({'cleared': True}, "Cached results cleared")


@app.route('/api/cache/stats', methods=['GET'])
@require_role('admin')
def get_result_cache_stats():
    """Report result cache entry and byte counts."""
    try:
        return success_response(result_cache.stats())
    except Exception as e:
        logger.warning("Result cache statistics are unavailable (%s)", type(e).__name__)
        return error_response("Result cache statistics are unavailable", 500)


@app.route('/api/admin/snapshot-history/orphans', methods=['DELETE'])
@require_role('admin')
def purge_snapshot_history_orphans():
    """Purge orphaned history of the current namespace, or every row of a detached namespace."""
    data = read_json_object_body(required=True)
    if data is None:
        return invalid_json_body_response()
    try:
        older_than_days = parse_json_integer(data, 'older_than_days', 0)
        namespace = parse_json_string(data, 'namespace')
        confirm = parse_json_string(data, 'confirm')
        if namespace is None:
            if older_than_days is None:
                raise RequestValidationError(
                    "'older_than_days' is required without 'namespace'", field="older_than_days",
                )
        else:
            if not NAMESPACE_PATTERN.fullmatch(namespace):
                raise RequestValidationError("'namespace' must match ^[A-Za-z0-9_-]{1,64}$", field="namespace")
            if confirm != namespace:
                raise RequestValidationError("'confirm' must repeat 'namespace'", field="confirm")
    except RequestValidationError as e:
        return validation_error_response(e)

    reason = snapshot_state_service.global_unavailable_reason()
    if reason:
        return versioning_unavailable_response(reason)
    if namespace is not None and namespace == snapshot_state_service.namespace:
        return current_namespace_refusal_response()

    try:
        if namespace is None:
            result = snapshot_history_service.purge_orphans(older_than_days)
        else:
            purged, last_seen_at = snapshot_history_service.purge_namespace(namespace)
            result = {'purged': purged, 'last_seen_at': last_seen_at}
    except CurrentNamespaceError:
        return current_namespace_refusal_response()
    except Exception as e:
        return versioning_error_response(e, "purge snapshot history")

    logger.info(
        "Purged snapshot history: namespace=%s mode=%s purged=%s",
        namespace or snapshot_state_service.namespace,
        'namespace' if namespace is not None else 'orphans',
        result['purged'],
    )
    return success_response(result, "Snapshot history purged")


@app.route('/api/admin/snapshot-history/namespaces', methods=['GET'])
@require_role('admin')
def list_snapshot_history_namespaces():
    """List every namespace that holds snapshot history in this database."""
    reason = snapshot_state_service.global_unavailable_reason()
    if reason:
        return versioning_unavailable_response(reason)
    try:
        result = snapshot_history_service.list_namespaces()
    except Exception as e:
        return versioning_error_response(e, "list snapshot history namespaces")
    return success_response(result)


@app.route('/api/snapshots/compare', methods=['POST'])
def compare_snapshots():
    """Compare two network snapshots"""
    try:
        data = request.get_json()

        if not data:
            return error_response("Request body is required", 400)

        base_snapshot = data.get('base_snapshot')
        comparison_snapshot = data.get('comparison_snapshot')

        if not base_snapshot or not comparison_snapshot:
            return error_response("Both 'base_snapshot' and 'comparison_snapshot' are required", 400)

        snapshot_context = get_snapshot_request_context()
        base_snapshot_path = snapshot_service.get_snapshot_path(base_snapshot, **snapshot_context)
        comparison_snapshot_path = snapshot_service.get_snapshot_path(comparison_snapshot, **snapshot_context)

        result = batfish_service.compare_snapshots(
            base_snapshot,
            comparison_snapshot,
            base_snapshot_path=base_snapshot_path,
            comparison_snapshot_path=comparison_snapshot_path,
        )

        return success_response(result, "Snapshots compared successfully")

    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except BatfishSnapshotLoadError as e:
        role = "base" if e.snapshot_name == base_snapshot else "comparison"
        logger.error(f"Failed to load {role} snapshot '{e.snapshot_name}' for comparison: {e}")
        return snapshot_load_error_response(e, role)
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to compare snapshots: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/layer1-topology', methods=['GET'])
def get_snapshot_layer1_topology(name: str):
    """Get Layer1 topology configuration for a snapshot"""
    try:
        topology = snapshot_service.get_layer1_topology(name, **get_snapshot_request_context())
        return success_response(topology, "Layer1 topology retrieved successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get Layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/layer1-topology', methods=['PUT'])
def save_snapshot_layer1_topology(name: str):
    """Save Layer1 topology configuration for a snapshot"""
    try:
        topology_data = request.get_json()

        if not topology_data:
            return error_response("Request body is required", 400)

        if 'edges' not in topology_data:
            return error_response("'edges' field is required in request body", 400)

        result = snapshot_service.save_layer1_topology(
            name,
            topology_data,
            **get_snapshot_request_context(),
        )

        reload_error = reload_active_snapshot_after_layer1_change(name)
        if reload_error:
            return reload_error

        return success_response(result, "Layer1 topology saved successfully")

    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to save Layer1 topology: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/layer1-topology', methods=['DELETE'])
def delete_snapshot_layer1_topology(name: str):
    """Delete Layer1 topology configuration for a snapshot"""
    try:
        snapshot_service.delete_layer1_topology(name, **get_snapshot_request_context())
        reload_error = reload_active_snapshot_after_layer1_change(name)
        if reload_error:
            return reload_error
        return success_response({"snapshot": name}, "Layer1 topology deleted successfully")
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to delete Layer1 topology: {e}")
        return error_response(str(e), 500)


@app.route('/api/snapshots/<name>/interfaces', methods=['GET'])
def get_snapshot_interfaces(name: str):
    """Get all interfaces for devices in a snapshot"""
    try:
        interfaces = snapshot_service.get_snapshot_interfaces(
            name,
            batfish_service,
            **get_snapshot_request_context(),
        )
        return success_response(interfaces, "Snapshot interfaces retrieved successfully")
    except BatfishQueryError as e:
        return batfish_query_error_response(e)
    except BatfishSnapshotLoadError as e:
        logger.error(f"Failed to load snapshot '{e.snapshot_name}' for interface lookup: {e}")
        return snapshot_load_error_response(e)
    except PermissionError as e:
        return error_response(str(e), 403)
    except FileNotFoundError as e:
        return error_response(str(e), 404)
    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to get snapshot interfaces: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return error_response(str(e), 500)


@app.route('/api/endpoints', methods=['GET'])
def list_endpoints():
    """List all available API endpoints"""
    endpoints = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            endpoints.append({
                "path": str(rule),
                "methods": list(rule.methods - {'HEAD', 'OPTIONS'}),
                "endpoint": rule.endpoint
            })

    return success_response(sorted(endpoints, key=lambda x: x['path']))


if config.AUTH_ENABLED and config.CSRF_MODE == 'double-submit':
    @app.after_request
    def set_enhanced_security_headers(response):
        """Enhanced security headers for Double-Submit Cookie Pattern"""
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        response.headers['X-Frame-Options'] = 'DENY'

        response.headers['X-Content-Type-Options'] = 'nosniff'

        response.headers['X-XSS-Protection'] = '1; mode=block'

        if config.ENV == 'production':
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )

        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        response.headers['Permissions-Policy'] = (
            'geolocation=(), '
            'microphone=(), '
            'camera=(), '
            'payment=(), '
            'usb=(), '
            'magnetometer=(), '
            'gyroscope=(), '
            'accelerometer=()'
        )

        return response

def install_cached_query_views() -> None:
    """Wrap every allowlisted view with the result cache decorator."""
    for _, endpoint in CACHED_QUERY_ROUTES:
        app.view_functions[endpoint] = cached_query(endpoint)(app.view_functions[endpoint])


install_cached_query_views()

if __name__ == '__main__':
    logger.info(f"Starting Topologix Backend on {config.HOST}:{config.PORT}")
    logger.info(f"Debug mode: {config.DEBUG}")
    logger.info(f"Batfish connection: {config.BATFISH_HOST}:{config.BATFISH_PORT}")
    logger.info(f"Authentication: {'ENABLED' if config.AUTH_ENABLED else 'DISABLED (open access)'}")
    if config.AUTH_ENABLED:
        logger.info("JWT Authentication: ENABLED")
        logger.info("CSRF Protection: ENABLED")
        logger.info("Rate Limiting: ENABLED")
        logger.info("Security Headers: ENABLED")
        logger.warning("Default credentials in use - CHANGE IMMEDIATELY in production!")
    else:
        logger.info("All endpoints are publicly accessible without authentication")

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )
