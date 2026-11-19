"""Comprehensive input validation and sanitization"""
import logging
import re
import os
import magic
from pathlib import Path
from typing import Any, Optional, List, Union
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
NODE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
SNAPSHOT_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,50}$')
IP_ADDRESS_PATTERN = re.compile(
    r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
)
CIDR_PATTERN = re.compile(
    r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/(3[0-2]|[12]?\d)$'
)

ALLOWED_EXTENSIONS = {'.cfg', '.conf', '.txt', '.log'}
ALLOWED_MIME_TYPES = {
    'text/plain',
    'text/x-cisco-ios',
    'text/x-cisco-nxos',
    'application/x-cisco-ios',
    'application/octet-stream'
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


class RequestValidationError(ValueError):
    """Request input rejected by validation; field names the offending input when known."""

    def __init__(self, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.field = field

# Dangerous patterns in file content
DANGEROUS_PATTERNS = [
    re.compile(rb'<\s*script', re.IGNORECASE),
    re.compile(rb'javascript\s*:', re.IGNORECASE),
    re.compile(rb'on\w+\s*=', re.IGNORECASE),  # Event handlers
    re.compile(rb'<\s*iframe', re.IGNORECASE),
    re.compile(rb'<\s*object', re.IGNORECASE),
    re.compile(rb'<\s*embed', re.IGNORECASE),
    re.compile(rb'eval\s*\(', re.IGNORECASE),
    re.compile(rb'exec\s*\(', re.IGNORECASE),
    re.compile(rb'__import__', re.IGNORECASE),
    re.compile(rb'os\s*\.\s*system', re.IGNORECASE),
    re.compile(rb'subprocess', re.IGNORECASE),
    re.compile(rb';\s*rm\s+-rf'),
    re.compile(rb'&&\s*rm\s+-rf'),
    re.compile(rb'\|\s*rm\s+-rf'),
    re.compile(rb'`.*`'),  # Backticks for command substitution
    re.compile(rb'\$\(.*\)'),  # Command substitution
]


def sanitize_input(value: Any, max_length: int = 255,
                  allow_special_chars: bool = False) -> str:
    """Sanitize user input to prevent injection attacks"""
    if value is None:
        return ""

    value = str(value).strip()

    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")

    value = value.replace('\0', '')

    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')

    if not allow_special_chars:
        value = re.sub(r'[<>&\'"`;|$(){}\\]', '', value)
    else:
        value = (value
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

    return value


def validate_path(base_dir: Union[str, Path], requested_path: str) -> Path:
    """Validate and sanitize file paths to prevent directory traversal"""
    base_dir = Path(base_dir).resolve()

    requested_path = requested_path.replace('\0', '')

    safe_path = secure_filename(requested_path)
    if not safe_path:
        raise ValueError("Invalid path provided")

    full_path = (base_dir / safe_path).resolve()

    if not str(full_path).startswith(str(base_dir)):
        logger.warning(f"Path traversal attempt detected: {requested_path}")
        raise ValueError("Path traversal detected")

    path_str = str(full_path)
    suspicious_patterns = ['..', '~', '$', '`', '|', ';', '&', '>', '<']
    for pattern in suspicious_patterns:
        if pattern in requested_path:
            logger.warning(f"Suspicious pattern '{pattern}' in path: {requested_path}")
            raise ValueError("Invalid path characters detected")

    return full_path


def validate_file_upload(file_storage: Any) -> dict:
    """Validate uploaded file for security issues"""
    if not file_storage or not file_storage.filename:
        raise ValueError("No file provided")

    filename = secure_filename(file_storage.filename)
    if not filename:
        raise ValueError("Invalid filename")

    file_ext = Path(filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File type '{file_ext}' not allowed. "
            f"Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    file_storage.seek(0, os.SEEK_END)
    file_size = file_storage.tell()
    file_storage.seek(0)

    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds "
            f"maximum allowed size ({MAX_FILE_SIZE / 1024 / 1024}MB)"
        )

    if file_size == 0:
        raise ValueError("File is empty")

    content = file_storage.read(MAX_FILE_SIZE)
    file_storage.seek(0)

    if b'\x00' in content:
        raise ValueError("Binary files are not allowed")

    try:
        content.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError("Uploaded file must be valid UTF-8 text") from exc

    mime = None
    try:
        mime = magic.from_buffer(content, mime=True)
    except Exception as e:
        logger.error(f"Error checking file MIME type: {e}")

    if mime and mime not in ALLOWED_MIME_TYPES:
        logger.warning(f"Rejected file with MIME type: {mime}")
        if not mime.startswith('text/'):
            raise ValueError(f"File type not allowed: {mime}")

    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(content):
            logger.warning(f"Dangerous pattern detected in uploaded file: {filename}")
            raise ValueError("File contains potentially malicious content")

    if not _is_valid_network_text_content(content, file_ext):
        raise ValueError("File does not appear to be a valid network configuration or log")

    logger.info(f"File validation successful for: {filename}")

    return {
        'filename': filename,
        'size': file_size,
        'extension': file_ext,
        'validated': True
    }


def _is_valid_network_text_content(content: bytes, file_ext: str) -> bool:
    """Check if content appears to be valid network configuration or operational log"""
    try:
        text = content.decode('utf-8', errors='ignore')
        text_lower = text.lower()

        if file_ext == '.log':
            log_indicators = [
                '%', 'link-', 'line protocol', 'ospf-', 'bgp-', 'adjacency',
                'error', 'warning', 'notice', 'info', 'up', 'down', 'changed state',
                'interface', 'hostname', 'router', 'vlan', 'access-list',
                'tcp', 'udp', 'icmp', 'denied', 'permitted', 'session'
            ]
            return any(indicator in text_lower for indicator in log_indicators)

        config_keywords = [
            'interface', 'hostname', 'router', 'ip address',
            'vlan', 'spanning-tree', 'access-list', 'route',
            'bgp', 'ospf', 'eigrp', 'version', 'enable',
            'line', 'service', 'crypto', 'logging'
        ]

        keyword_count = sum(1 for keyword in config_keywords
                          if keyword.lower() in text_lower)

        return keyword_count >= 2

    except Exception as e:
        logger.error(f"Error validating network text content: {e}")
        return False


def validate_snapshot_name(name: str) -> str:
    """Validate snapshot name"""
    if not name or not name.strip():
        raise ValueError("Snapshot name cannot be empty")

    name = name.strip()

    if len(name) > 50:
        raise ValueError("Snapshot name cannot exceed 50 characters")

    if not SNAPSHOT_NAME_PATTERN.match(name):
        raise ValueError(
            "Snapshot name can only contain letters, numbers, "
            "underscores, and hyphens"
        )

    return secure_filename(name)


def validate_node_name(name: str) -> str:
    """Validate network node name"""
    if not name or not name.strip():
        raise ValueError("Node name cannot be empty")

    name = name.strip()

    if not NODE_NAME_PATTERN.match(name):
        raise ValueError(
            "Node name can only contain letters, numbers, "
            "underscores, hyphens, and dots (max 64 characters)"
        )

    return name


def validate_ip_address(ip: str) -> str:
    """Validate IP address"""
    ip = ip.strip()

    if not IP_ADDRESS_PATTERN.match(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    return ip


def validate_cidr(cidr: str) -> str:
    """Validate CIDR notation"""
    cidr = cidr.strip()

    if not CIDR_PATTERN.match(cidr):
        raise ValueError(f"Invalid CIDR notation: {cidr}")

    return cidr


def validate_json_input(data: dict, required_fields: List[str],
                       optional_fields: Optional[List[str]] = None) -> dict:
    """Validate JSON input data"""
    if not isinstance(data, dict):
        raise RequestValidationError("Input must be a JSON object")

    validated = {}

    for field in required_fields:
        if field not in data:
            raise RequestValidationError(f"Missing required field: {field}", field=field)
        validated[field] = data[field]

    if optional_fields:
        for field in optional_fields:
            if field in data:
                validated[field] = data[field]

    all_allowed = set(required_fields + (optional_fields or []))
    for field in data:
        if field not in all_allowed:
            logger.warning(f"Unexpected field in input: {field}")

    return validated


def validate_positive_integer(value: Any, field_name: str) -> int:
    """Validate a JSON field as a positive integer.

    JSON booleans must be rejected explicitly because Python bool is a subclass
    of int and would otherwise allow true to become user ID 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be a positive integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value
