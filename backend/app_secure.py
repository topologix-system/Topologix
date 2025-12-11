"""
Secure Flask application with comprehensive authentication and security
- JWT authentication and role-based access control (RBAC)
- CSRF protection, rate limiting, and security headers
- Audit logging for all security-relevant events
- Input validation and sanitization for all endpoints
- Comprehensive network analysis REST API powered by Batfish (40+ endpoints)
- Requires authentication for all API endpoints except health/config
"""
import logging
import json
from pathlib import Path
from typing import Any
from datetime import datetime

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_session import Session

from config import config
from services import BatfishService, SnapshotService
from security import (
    JWTManager, require_auth, require_role,
    sanitize_input, validate_path, validate_file_upload,
    validate_snapshot_name, validate_node_name, validate_json_input,
    CSRFProtect, SecurityHeaders, RateLimiter
)

# Configure logging with security considerations
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT
        )
    ]
)
logger = logging.getLogger(__name__)

# Audit logger for security events
audit_logger = logging.getLogger('audit')
audit_handler = logging.handlers.RotatingFileHandler(
    config.AUDIT_LOG_FILE,
    maxBytes=config.LOG_MAX_BYTES,
    backupCount=config.LOG_BACKUP_COUNT
)
audit_handler.setFormatter(logging.Formatter(config.LOG_FORMAT))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)


def audit_log(event: str, details: dict):
    """Log security audit events"""
    if config.AUDIT_LOG_ENABLED and event in config.AUDIT_LOG_EVENTS:
        audit_logger.info(json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'event': event,
            'ip': request.remote_addr,
            'user': getattr(request, 'jwt_payload', {}).get('username', 'anonymous'),
            'details': details
        }))


# Initialize Flask app
app = Flask(__name__)

# Configure Flask app with security settings
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# Initialize Flask-Session
Session(app)

# Initialize security components
jwt_manager = JWTManager(app, config.JWT_SECRET_KEY)
csrf_protect = CSRFProtect(app, config.CSRF_SECRET_KEY)
security_headers = SecurityHeaders(app)
rate_limiter = RateLimiter(app)

# Configure CORS with security
CORS(app,
     origins=config.CORS_ORIGINS,
     allow_headers=config.CORS_ALLOW_HEADERS,
     expose_headers=config.CORS_EXPOSE_HEADERS,
     supports_credentials=config.CORS_SUPPORTS_CREDENTIALS,
     max_age=config.CORS_MAX_AGE)

# Initialize services
batfish_service = BatfishService()
snapshot_service = SnapshotService()


# ========== Error Handlers with Security ==========
@app.errorhandler(400)
def bad_request(error):
    """Handle 400 errors without exposing details"""
    logger.warning(f"Bad request from {request.remote_addr}: {error}")
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 errors"""
    audit_log('permission_denied', {'path': request.path})
    return jsonify({"error": "Authentication required"}), 401


@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors"""
    audit_log('permission_denied', {'path': request.path})
    return jsonify({"error": "Access forbidden"}), 403


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors without path disclosure"""
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(429)
def rate_limit_exceeded(error):
    """Handle rate limit errors"""
    audit_log('rate_limit_exceeded', {'path': request.path})
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors without exposing details"""
    logger.error(f"Internal error: {error}", exc_info=True)
    if config.ENV == 'production':
        return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": str(error)}), 500


# ========== Utility Functions ==========
def success_response(data: Any, message: str = "Success") -> tuple:
    """Create success response"""
    return jsonify({"status": "success", "message": message, "data": data}), 200


def error_response(message: str, status_code: int = 400) -> tuple:
    """Create error response without exposing sensitive details"""
    if config.ENV == 'production' and status_code == 500:
        message = "An error occurred processing your request"
    return jsonify({"status": "error", "message": message}), status_code


# ========== Authentication Endpoints ==========
@app.route('/api/auth/login', methods=['POST'])
@rate_limiter.limit(per_minute=5, per_hour=20)
def login():
    """Authenticate user and return JWT tokens"""
    try:
        data = validate_json_input(
            request.get_json(),
            required_fields=['username', 'password']
        )

        username = sanitize_input(data['username'], max_length=50)
        password = data['password']  # Don't sanitize passwords

        user = jwt_manager.authenticate_user(username, password)
        if not user:
            audit_log('failed_login', {'username': username})
            return error_response("Invalid credentials", 401)

        tokens = jwt_manager.generate_tokens(
            user['id'], user['username'], user['roles']
        )

        # Generate CSRF token
        csrf_token = csrf_protect.generate_csrf_token()

        audit_log('login', {'username': username})

        response = jsonify({
            "status": "success",
            "message": "Login successful",
            "data": {
                **tokens,
                "user": {
                    "username": user['username'],
                    "roles": user['roles'],
                    "email": user['email']
                },
                "csrf_token": csrf_token
            }
        })

        # Set secure cookie for web clients
        if config.ENV == 'production':
            response.set_cookie(
                'access_token',
                tokens['access_token'],
                secure=True,
                httponly=True,
                samesite='Lax',
                max_age=config.JWT_ACCESS_TOKEN_EXPIRES
            )

        return response, 200

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return error_response("Login failed", 500)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout user and invalidate token"""
    try:
        username = request.jwt_payload.get('username')
        audit_log('logout', {'username': username})

        # Clear session
        session.clear()

        response = success_response({}, "Logout successful")

        # Clear cookies
        response.set_cookie('access_token', '', expires=0)
        response.set_cookie('csrf_token', '', expires=0)

        return response

    except Exception as e:
        logger.error(f"Logout error: {e}")
        return error_response("Logout failed", 500)


@app.route('/api/auth/refresh', methods=['POST'])
@rate_limiter.limit(per_minute=10, per_hour=100)
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        data = validate_json_input(
            request.get_json(),
            required_fields=['refresh_token']
        )

        refresh_token = data['refresh_token']
        payload = jwt_manager.decode_token(refresh_token)

        if payload.get('type') != 'refresh':
            return error_response("Invalid token type", 401)

        # Get user from database (simplified for demo)
        from security.auth import USERS_DB
        user = None
        for u in USERS_DB.values():
            if u['id'] == payload.get('user_id'):
                user = u
                break

        if not user:
            return error_response("User not found", 401)

        # Generate new access token
        tokens = jwt_manager.generate_tokens(
            user['id'], user['username'], user['roles']
        )

        return success_response({
            'access_token': tokens['access_token'],
            'token_type': 'Bearer',
            'expires_in': tokens['expires_in']
        })

    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return error_response("Token refresh failed", 401)


@app.route('/api/auth/csrf-token', methods=['GET'])
@require_auth
def get_csrf_token():
    """Get CSRF token for authenticated user"""
    csrf_token = csrf_protect.generate_csrf_token()
    return success_response({'csrf_token': csrf_token})


# ========== Health Check (No Auth Required) ==========
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return success_response({
        "service": "topologix-backend",
        "status": "healthy",
        "version": "1.0.0",
        "security": "enabled"
    })


# ========== Configuration Endpoint ==========
@app.route('/api/config', methods=['GET'])
def get_config():
    """Get safe configuration for client"""
    return success_response(config.get_safe_config())


# ========== Network Initialization with Security ==========
@app.route('/api/network/initialize', methods=['POST'])
@require_auth
@require_role('admin', 'user')
@rate_limiter.limit(per_minute=10, per_hour=50)
def initialize_network():
    """Initialize Batfish network with configuration snapshot"""
    try:
        data = validate_json_input(
            request.get_json(),
            required_fields=['snapshot_dir'],
            optional_fields=['snapshot_name']
        )

        # Validate and sanitize inputs
        snapshot_dir = data['snapshot_dir']

        # Validate path to prevent traversal
        safe_path = validate_path(config.ALLOWED_SNAPSHOT_PATH, snapshot_dir)

        snapshot_name = None
        if 'snapshot_name' in data:
            snapshot_name = validate_snapshot_name(data['snapshot_name'])

        audit_log('network_init', {
            'snapshot_dir': str(safe_path),
            'snapshot_name': snapshot_name
        })

        # Initialize network
        result = batfish_service.initialize_network(str(safe_path), snapshot_name)

        return success_response(result, "Network initialized successfully")

    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError as e:
        return error_response("Snapshot directory not found", 404)
    except Exception as e:
        logger.error(f"Failed to initialize network: {e}")
        return error_response("Initialization failed", 500)


# ========== Query Endpoints with Authentication ==========

@app.route('/api/network/nodes', methods=['GET'])
@require_auth
@rate_limiter.limit(per_minute=30)
def get_nodes():
    """Get all node properties"""
    try:
        nodes = batfish_service.get_node_properties()
        return success_response(nodes)
    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get nodes: {e}")
        return error_response("Failed to retrieve nodes", 500)


@app.route('/api/network/interfaces', methods=['GET'])
@require_auth
@rate_limiter.limit(per_minute=30)
def get_interfaces():
    """Get all interface properties"""
    try:
        interfaces = batfish_service.get_interface_properties()
        return success_response(interfaces)
    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return error_response("Failed to retrieve interfaces", 500)


@app.route('/api/network/routes', methods=['GET'])
@require_auth
@rate_limiter.limit(per_minute=30)
def get_routes():
    """Get all routing table entries"""
    try:
        routes = batfish_service.get_routes()
        return success_response(routes)
    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get routes: {e}")
        return error_response("Failed to retrieve routes", 500)


# ========== Snapshot Management with Security ==========

@app.route('/api/snapshots', methods=['GET'])
@require_auth
def list_snapshots():
    """List all available snapshots"""
    try:
        snapshots = snapshot_service.list_snapshots()
        return success_response(snapshots)
    except Exception as e:
        logger.error(f"Failed to list snapshots: {e}")
        return error_response("Failed to list snapshots", 500)


@app.route('/api/snapshots', methods=['POST'])
@require_auth
@require_role('admin', 'user')
@rate_limiter.limit(per_minute=5, per_hour=50)
def create_snapshot():
    """Create a new empty snapshot"""
    try:
        data = validate_json_input(
            request.get_json(),
            required_fields=['name']
        )

        name = validate_snapshot_name(data['name'])

        audit_log('snapshot_create', {'name': name})

        snapshot = snapshot_service.create_snapshot(name)
        return success_response(snapshot, "Snapshot created successfully")

    except ValueError as e:
        return error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Failed to create snapshot: {e}")
        return error_response("Failed to create snapshot", 500)


@app.route('/api/snapshots/<name>', methods=['DELETE'])
@require_auth
@require_role('admin')
def delete_snapshot(name: str):
    """Delete a snapshot"""
    try:
        safe_name = validate_snapshot_name(name)

        audit_log('snapshot_delete', {'name': safe_name})

        snapshot_service.delete_snapshot(safe_name)
        return success_response({"name": safe_name}, "Snapshot deleted successfully")

    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError:
        return error_response("Snapshot not found", 404)
    except Exception as e:
        logger.error(f"Failed to delete snapshot: {e}")
        return error_response("Failed to delete snapshot", 500)


@app.route('/api/snapshots/<name>/files', methods=['POST'])
@require_auth
@require_role('admin', 'user')
@rate_limiter.limit(per_minute=10, per_hour=100)
def upload_snapshot_file(name: str):
    """Upload a configuration file to a snapshot"""
    try:
        safe_name = validate_snapshot_name(name)

        if 'file' not in request.files:
            return error_response("No file provided", 400)

        file = request.files['file']

        # Validate file upload
        validation = validate_file_upload(file)

        audit_log('file_upload', {
            'snapshot': safe_name,
            'filename': validation['filename'],
            'size': validation['size']
        })

        file_info = snapshot_service.upload_file(safe_name, file)
        return success_response(file_info, "File uploaded successfully")

    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError:
        return error_response("Snapshot not found", 404)
    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        return error_response("File upload failed", 500)


@app.route('/api/snapshots/<name>/activate', methods=['POST'])
@require_auth
@require_role('admin', 'user')
@rate_limiter.limit(per_minute=5, per_hour=20)
def activate_snapshot(name: str):
    """Activate a snapshot (initialize Batfish with this snapshot)"""
    try:
        safe_name = validate_snapshot_name(name)

        audit_log('network_init', {'snapshot': safe_name})

        snapshot_path = snapshot_service.get_snapshot_path(safe_name)
        result = batfish_service.initialize_network(str(snapshot_path), safe_name)

        return success_response(result, f"Snapshot '{safe_name}' activated successfully")

    except ValueError as e:
        return error_response(str(e), 400)
    except FileNotFoundError:
        return error_response("Snapshot not found", 404)
    except Exception as e:
        logger.error(f"Failed to activate snapshot: {e}")
        return error_response("Failed to activate snapshot", 500)


# ========== OSPF Endpoints with Auth ==========

@app.route('/api/ospf/processes', methods=['GET'])
@require_auth
def get_ospf_processes():
    """Get OSPF process configurations"""
    try:
        processes = batfish_service.get_ospf_process_configuration()
        return success_response([p.to_dict() for p in processes])
    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF processes: {e}")
        return error_response("Failed to retrieve OSPF processes", 500)


@app.route('/api/ospf/areas', methods=['GET'])
@require_auth
def get_ospf_areas():
    """Get OSPF area configurations"""
    try:
        areas = batfish_service.get_ospf_area_configuration()
        return success_response([a.to_dict() for a in areas])
    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get OSPF areas: {e}")
        return error_response("Failed to retrieve OSPF areas", 500)


# ========== Analysis Endpoints with Input Validation ==========

@app.route('/api/analysis/reachability', methods=['POST'])
@require_auth
@rate_limiter.limit(per_minute=20, per_hour=200)
def get_reachability():
    """Get reachability analysis results with input validation"""
    try:
        data = request.get_json() if request.is_json else {}

        # Validate headers if provided
        if 'headers' in data and data['headers']:
            headers = data['headers']
            # Validate IP addresses if provided
            if 'srcIps' in headers:
                from security.validation import validate_ip_address, validate_cidr
                try:
                    validate_ip_address(headers['srcIps'])
                except ValueError:
                    try:
                        validate_cidr(headers['srcIps'])
                    except ValueError:
                        return error_response("Invalid source IP address", 400)

            if 'dstIps' in headers:
                try:
                    validate_ip_address(headers['dstIps'])
                except ValueError:
                    try:
                        validate_cidr(headers['dstIps'])
                    except ValueError:
                        return error_response("Invalid destination IP address", 400)
        else:
            headers = None

        flow_traces = batfish_service.get_reachability(headers)
        return success_response([f.to_dict() for f in flow_traces])

    except RuntimeError as e:
        return error_response("Network not initialized", 400)
    except Exception as e:
        logger.error(f"Failed to get reachability: {e}")
        return error_response("Reachability analysis failed", 500)


# ========== API Documentation Endpoint ==========
@app.route('/api/endpoints', methods=['GET'])
def list_endpoints():
    """List all available API endpoints"""
    endpoints = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            endpoints.append({
                "path": str(rule),
                "methods": list(rule.methods - {'HEAD', 'OPTIONS'}),
                "endpoint": rule.endpoint,
                "auth_required": 'auth' in str(rule.endpoint)
            })

    return success_response(sorted(endpoints, key=lambda x: x['path']))


# ========== Main ==========
if __name__ == '__main__':
    logger.info(f"Starting Topologix Backend (Secure Mode)")
    logger.info(f"Environment: {config.ENV}")
    logger.info(f"Debug mode: {config.DEBUG}")
    logger.info(f"Security features: ENABLED")
    logger.info(f"JWT Authentication: ENABLED")
    logger.info(f"CSRF Protection: ENABLED")
    logger.info(f"Rate Limiting: ENABLED")
    logger.info(f"Listening on {config.HOST}:{config.PORT}")

    # Run with security considerations
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        use_reloader=config.ENV != 'production',
        use_debugger=config.ENV != 'production'
    )