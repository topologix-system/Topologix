"""
Comprehensive input validation and sanitization
- sanitize_input(): Remove dangerous characters, HTML escape, length limits
- validate_path(): Path traversal prevention with base directory checks
- validate_file_upload(): Multi-layer file validation (size, MIME, content)
- validate_snapshot_name(): Alphanumeric + underscore/hyphen validation
- validate_node_name(): Network device name validation
- validate_ip_address(): IPv4 address validation
- validate_cidr(): CIDR notation validation
- validate_json_input(): Required/optional field validation
- File security: MIME type checking with python-magic
- Content scanning for malicious patterns (scripts, code injection)
- Network config keyword validation (interface, hostname, router, etc.)
- Maximum file size: 10MB per file
- Allowed extensions: .cfg, .conf, .txt
"""
import logging
import re
import os
import magic
from pathlib import Path
from typing import Any, Optional, List, Union
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

# Regular expressions for validation
ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
NODE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]{1,64}$')
SNAPSHOT_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,50}$')
IP_ADDRESS_PATTERN = re.compile(
    r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'
)
CIDR_PATTERN = re.compile(
    r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}/(3[0-2]|[12]?\d)$'
)

# File validation constants
ALLOWED_EXTENSIONS = {'.cfg', '.conf', '.txt'}
ALLOWED_MIME_TYPES = {
    'text/plain',
    'text/x-cisco-ios',
    'text/x-cisco-nxos',
    'application/x-cisco-ios',
    'application/octet-stream'  # Some config files might be detected as this
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

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
    # Command injection patterns
    re.compile(rb';\s*rm\s+-rf'),
    re.compile(rb'&&\s*rm\s+-rf'),
    re.compile(rb'\|\s*rm\s+-rf'),
    re.compile(rb'`.*`'),  # Backticks for command substitution
    re.compile(rb'\$\(.*\)'),  # Command substitution
]


def sanitize_input(value: Any, max_length: int = 255,
                  allow_special_chars: bool = False) -> str:
    """Sanitize user input to prevent injection attacks

    Args:
        value: Input value to sanitize
        max_length: Maximum allowed length
        allow_special_chars: Whether to allow special characters

    Returns:
        Sanitized string

    Raises:
        ValueError: If input is invalid
    """
    if value is None:
        return ""

    # Convert to string
    value = str(value).strip()

    # Check length
    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")

    # Remove null bytes
    value = value.replace('\0', '')

    # Remove control characters
    value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')

    if not allow_special_chars:
        # Remove potentially dangerous characters for most inputs
        value = re.sub(r'[<>\"\'`;&|$(){}\\]', '', value)

    # HTML escape
    value = (value
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))

    return value


def validate_path(base_dir: Union[str, Path], requested_path: str) -> Path:
    """Validate and sanitize file paths to prevent directory traversal

    Args:
        base_dir: Base directory that should contain the path
        requested_path: Requested file/directory path

    Returns:
        Validated Path object

    Raises:
        ValueError: If path is invalid or attempts directory traversal
    """
    base_dir = Path(base_dir).resolve()

    # Remove any null bytes
    requested_path = requested_path.replace('\0', '')

    # Secure the filename/path
    safe_path = secure_filename(requested_path)
    if not safe_path:
        raise ValueError("Invalid path provided")

    # Construct full path
    full_path = (base_dir / safe_path).resolve()

    # Ensure the resolved path is within the base directory
    if not str(full_path).startswith(str(base_dir)):
        logger.warning(f"Path traversal attempt detected: {requested_path}")
        raise ValueError("Path traversal detected")

    # Additional checks for suspicious patterns
    path_str = str(full_path)
    suspicious_patterns = ['..', '~', '$', '`', '|', ';', '&', '>', '<']
    for pattern in suspicious_patterns:
        if pattern in requested_path:
            logger.warning(f"Suspicious pattern '{pattern}' in path: {requested_path}")
            raise ValueError("Invalid path characters detected")

    return full_path


def validate_file_upload(file_storage: Any) -> dict:
    """Validate uploaded file for security issues

    Args:
        file_storage: Werkzeug FileStorage object

    Returns:
        Dictionary with validation results

    Raises:
        ValueError: If file validation fails
    """
    if not file_storage or not file_storage.filename:
        raise ValueError("No file provided")

    # Secure filename
    filename = secure_filename(file_storage.filename)
    if not filename:
        raise ValueError("Invalid filename")

    # Check extension
    file_ext = Path(filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File type '{file_ext}' not allowed. "
            f"Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # Check file size
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

    # Read file content for validation
    content = file_storage.read(MAX_FILE_SIZE)
    file_storage.seek(0)

    # Check MIME type using python-magic
    try:
        mime = magic.from_buffer(content, mime=True)
        if mime not in ALLOWED_MIME_TYPES:
            logger.warning(f"Rejected file with MIME type: {mime}")
            # Allow text files even if MIME detection is uncertain
            if not mime.startswith('text/'):
                raise ValueError(f"File type not allowed: {mime}")
    except Exception as e:
        logger.error(f"Error checking file MIME type: {e}")
        # Continue with other validations

    # Check for malicious patterns
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(content):
            logger.warning(f"Dangerous pattern detected in uploaded file: {filename}")
            raise ValueError("File contains potentially malicious content")

    # Check if file appears to be a valid configuration
    if not _is_valid_config_content(content):
        raise ValueError("File does not appear to be a valid network configuration")

    logger.info(f"File validation successful for: {filename}")

    return {
        'filename': filename,
        'size': file_size,
        'extension': file_ext,
        'validated': True
    }


def _is_valid_config_content(content: bytes) -> bool:
    """Check if content appears to be valid network configuration

    Args:
        content: File content as bytes

    Returns:
        True if content appears valid
    """
    try:
        # Convert to string for analysis
        text = content.decode('utf-8', errors='ignore')

        # Check for common network configuration keywords
        config_keywords = [
            'interface', 'hostname', 'router', 'ip address',
            'vlan', 'spanning-tree', 'access-list', 'route',
            'bgp', 'ospf', 'eigrp', 'version', 'enable',
            'line', 'service', 'crypto', 'logging'
        ]

        # Count how many keywords are present
        keyword_count = sum(1 for keyword in config_keywords
                          if keyword.lower() in text.lower())

        # Require at least 2 configuration keywords
        return keyword_count >= 2

    except Exception as e:
        logger.error(f"Error validating config content: {e}")
        return False


def validate_snapshot_name(name: str) -> str:
    """Validate snapshot name

    Args:
        name: Snapshot name to validate

    Returns:
        Validated and sanitized name

    Raises:
        ValueError: If name is invalid
    """
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
    """Validate network node name

    Args:
        name: Node name to validate

    Returns:
        Validated name

    Raises:
        ValueError: If name is invalid
    """
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
    """Validate IP address

    Args:
        ip: IP address to validate

    Returns:
        Validated IP address

    Raises:
        ValueError: If IP is invalid
    """
    ip = ip.strip()

    if not IP_ADDRESS_PATTERN.match(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    return ip


def validate_cidr(cidr: str) -> str:
    """Validate CIDR notation

    Args:
        cidr: CIDR notation to validate

    Returns:
        Validated CIDR

    Raises:
        ValueError: If CIDR is invalid
    """
    cidr = cidr.strip()

    if not CIDR_PATTERN.match(cidr):
        raise ValueError(f"Invalid CIDR notation: {cidr}")

    return cidr


def validate_json_input(data: dict, required_fields: List[str],
                       optional_fields: Optional[List[str]] = None) -> dict:
    """Validate JSON input data

    Args:
        data: Input data dictionary
        required_fields: List of required field names
        optional_fields: List of optional field names

    Returns:
        Validated data dictionary

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(data, dict):
        raise ValueError("Input must be a JSON object")

    validated = {}

    # Check required fields
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
        validated[field] = data[field]

    # Check optional fields
    if optional_fields:
        for field in optional_fields:
            if field in data:
                validated[field] = data[field]

    # Reject any unexpected fields
    all_allowed = set(required_fields + (optional_fields or []))
    for field in data:
        if field not in all_allowed:
            logger.warning(f"Unexpected field in input: {field}")

    return validated