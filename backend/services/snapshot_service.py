"""
Network configuration snapshot management service
- Create, list, delete, and manage configuration snapshots
- Upload configuration files (.cfg, .conf, .txt, .log) to snapshots
- File size validation (10MB limit per file)
- Secure filename handling with werkzeug.secure_filename
- Snapshot metadata sidecar for owner access control and folder classification
- Calculate snapshot directory sizes
- List files within snapshots with metadata
"""
import json
import logging
import os
import re
import shutil
import tempfile
import base64
import hashlib
import hmac
import time
from pathlib import Path
from typing import Any, Optional
from datetime import datetime
from werkzeug.utils import secure_filename
import magic

from config import config
from security.validation import DANGEROUS_PATTERNS, validate_file_upload

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.cfg', '.conf', '.txt', '.log'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
PROTECTED_SNAPSHOTS = set()  # No protected snapshots - all can be deleted
METADATA_FILENAME = '.topologix-snapshot.json'
FOLDER_SEGMENT_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$')
RANCID_CONTENT_TYPE_HEADER = '!RANCID-CONTENT-TYPE:'
SUPPORTED_RANCID_FORMATS = {
    'a10',
    'arista',
    'bigip',
    'ios',
    'cisco-nx',
    'cisco-xr',
    'force10',
    'fortigate',
    'foundry',
    'juniper',
    'mrv',
    'paloalto',
}
CONFIG_FORMAT_EXTENSIONS = ALLOWED_EXTENSIONS
ARTIFACT_ALLOWED_TEXT_EXTENSIONS = {'.cfg', '.conf', '.txt', '.log', '.iptables'}
ARTIFACT_ALLOWED_JSON_EXTENSIONS = {'.json'}
ARTIFACT_ALLOWED_SONIC_SUFFIXES = ('config_db.json', 'frr.conf', 'resolv.conf', 'snmp.yml')
ARTIFACT_ALLOWED_MIME_TYPES = {
    'application/json',
    'application/octet-stream',
}
ARTIFACT_PREVIEW_TOKEN_TTL_SECONDS = 15 * 60
CHECKPOINT_DOMAIN_FILES = {
    'show-gateways-and-servers.json',
    'show-groups.json',
    'show-hosts.json',
    'show-networks.json',
    'show-package.json',
    'show-service-groups.json',
    'show-services-icmp.json',
    'show-services-other.json',
    'show-services-tcp.json',
    'show-services-udp.json',
}
CHECKPOINT_PACKAGE_FILES = {
    'show-access-rulebase.json',
    'show-nat-rulebase.json',
    'show-package.json',
}
ARTIFACT_SEGMENT_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')


def _artifact_definition(
    artifact_type: str,
    label: str,
    category: str,
    description: str,
    content_kind: str,
    placement: str,
    fields: list[dict[str, Any]],
    allowed_extensions: Optional[list[str]] = None,
    allowed_suffixes: Optional[list[str]] = None,
    fixed_destination: Optional[str] = None,
    mutation_policy: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a JSON-serializable artifact type definition."""
    return {
        'id': artifact_type,
        'label': label,
        'category': category,
        'description': description,
        'content_kind': content_kind,
        'placement': placement,
        'fields': fields,
        'allowed_extensions': allowed_extensions or [],
        'allowed_suffixes': allowed_suffixes or [],
        'fixed_destination': fixed_destination,
        'mutation_policy': mutation_policy or {
            'metadata_edit': 'restricted',
            'content_replace': 'allowed',
            'safe_relocate': 'restricted',
            'type_change': 'replace_required',
            'active_snapshot_effect': 'requires_reactivate',
            'preview_required': True,
            'validation_required': True,
            'rollback_required': True,
        },
    }


ARTIFACT_TYPE_DEFINITIONS: dict[str, dict[str, Any]] = {
    'network_config': _artifact_definition(
        'network_config',
        'Network device config',
        'device_config',
        'Text device configuration or operational log stored under configs/.',
        'text',
        'configs/<filename>',
        fields=[],
        allowed_extensions=sorted(ALLOWED_EXTENSIONS),
    ),
    'aws_config': _artifact_definition(
        'aws_config',
        'AWS config JSON',
        'cloud_config',
        'AWS API JSON output stored under aws_configs/<account>/<region>/ when metadata is supplied.',
        'json',
        'aws_configs/<account>/<region>/<filename>',
        fields=[
            {'name': 'account', 'label': 'Account', 'required': False, 'placeholder': 'production'},
            {'name': 'region', 'label': 'Region', 'required': False, 'placeholder': 'us-east-1'},
        ],
        allowed_extensions=['.json'],
    ),
    'azure_config': _artifact_definition(
        'azure_config',
        'Azure resource JSON',
        'cloud_config',
        'Azure resource JSON view stored under azure_configs/. ARM templates are not accepted.',
        'json',
        'azure_configs/<filename>',
        fields=[],
        allowed_extensions=['.json'],
    ),
    'checkpoint_management': _artifact_definition(
        'checkpoint_management',
        'Check Point management JSON',
        'management_config',
        'Check Point Management API JSON stored under checkpoint_management/<manager>/<domain>/<package>/ as needed.',
        'json',
        'checkpoint_management/<manager>/<domain>/<package>/<filename>',
        fields=[
            {'name': 'manager', 'label': 'Manager', 'required': True, 'placeholder': 'manager1'},
            {'name': 'domain', 'label': 'Domain', 'required': True, 'placeholder': 'DomainA'},
            {'name': 'package', 'label': 'Package', 'required': False, 'placeholder': 'Package1'},
        ],
        allowed_extensions=['.json'],
    ),
    'sonic_config': _artifact_definition(
        'sonic_config',
        'SONiC device file',
        'device_config',
        'SONiC device files stored under sonic_configs/<device>/.',
        'mixed',
        'sonic_configs/<device>/<supported filename>',
        fields=[
            {'name': 'device', 'label': 'Device', 'required': True, 'placeholder': 'leaf01'},
        ],
        allowed_suffixes=list(ARTIFACT_ALLOWED_SONIC_SUFFIXES),
    ),
    'host_model': _artifact_definition(
        'host_model',
        'Host model JSON',
        'supplemental_data',
        'End-host model JSON stored under hosts/.',
        'json',
        'hosts/<filename>',
        fields=[],
        allowed_extensions=['.json'],
    ),
    'host_iptables': _artifact_definition(
        'host_iptables',
        'Host iptables file',
        'supplemental_data',
        'iptables-save output referenced by host model JSON.',
        'text',
        'iptables/<filename>',
        fields=[],
        allowed_extensions=['.iptables', '.txt', '.conf'],
    ),
    'layer1_topology': _artifact_definition(
        'layer1_topology',
        'Layer 1 topology JSON',
        'supplemental_data',
        'Manual cabling data stored as batfish/layer1_topology.json.',
        'json',
        'batfish/layer1_topology.json',
        fields=[],
        allowed_extensions=['.json'],
        fixed_destination='batfish/layer1_topology.json',
        mutation_policy={
            'metadata_edit': 'none',
            'content_replace': 'allowed',
            'safe_relocate': 'none',
            'type_change': 'replace_required',
            'active_snapshot_effect': 'requires_reactivate',
            'preview_required': True,
            'validation_required': True,
            'rollback_required': True,
        },
    ),
    'isp_config': _artifact_definition(
        'isp_config',
        'ISP modeling JSON',
        'supplemental_data',
        'ISP modeling data stored as batfish/isp_config.json.',
        'json',
        'batfish/isp_config.json',
        fields=[],
        allowed_extensions=['.json'],
        fixed_destination='batfish/isp_config.json',
    ),
    'runtime_data': _artifact_definition(
        'runtime_data',
        'Runtime data JSON',
        'supplemental_data',
        'Runtime interface information stored as batfish/runtime_data.json.',
        'json',
        'batfish/runtime_data.json',
        fields=[],
        allowed_extensions=['.json'],
        fixed_destination='batfish/runtime_data.json',
    ),
    'external_bgp_announcements': _artifact_definition(
        'external_bgp_announcements',
        'External BGP announcements JSON',
        'supplemental_data',
        'External BGP route injection data stored at snapshot root.',
        'json',
        'external_bgp_announcements.json',
        fields=[],
        allowed_extensions=['.json'],
        fixed_destination='external_bgp_announcements.json',
    ),
}


class SnapshotService:
    """Service for managing network configuration snapshots"""

    def __init__(self):
        """Initialize snapshot service"""
        self.snapshots_dir = Path(config.SNAPSHOTS_DIR)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _metadata_path(self, snapshot_path: Path) -> Path:
        """Return metadata sidecar path for a snapshot directory."""
        return snapshot_path / METADATA_FILENAME

    def _normalize_owner_user_id(self, owner_user_id: Any) -> Optional[int]:
        """Normalize owner user ID for stable metadata comparison."""
        if owner_user_id in (None, ''):
            return None

        try:
            return int(owner_user_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid owner user ID") from exc

    def _normalize_folder_name(self, folder_name: Optional[str]) -> Optional[str]:
        """Normalize folder metadata used for snapshot grouping."""
        if folder_name is None:
            return None

        normalized = str(folder_name).replace('\\', '/').strip()
        if not normalized:
            return None

        parts = [part.strip() for part in normalized.split('/') if part.strip()]
        if not parts:
            return None

        for part in parts:
            if not FOLDER_SEGMENT_PATTERN.fullmatch(part):
                raise ValueError(
                    "Folder name may only contain letters, numbers, spaces, hyphens, underscores, periods, and '/'"
                )

        joined = '/'.join(parts)
        if len(joined) > 200:
            raise ValueError("Folder name is too long")

        return joined

    def _build_metadata(
        self,
        snapshot_name: str,
        folder_name: Optional[str],
        owner_user_id: Any,
        owner_username: Optional[str],
        access_scope: str,
        created_at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Build normalized snapshot metadata payload."""
        now = datetime.utcnow().isoformat()
        normalized_owner_id = self._normalize_owner_user_id(owner_user_id)

        return {
            'schema_version': 1,
            'snapshot_name': snapshot_name,
            'folder_name': self._normalize_folder_name(folder_name),
            'owner_user_id': normalized_owner_id,
            'owner_username': owner_username.strip() if owner_username else None,
            'access_scope': access_scope,
            'created_at': created_at or now,
            'updated_at': now,
        }

    def _write_metadata(self, snapshot_path: Path, metadata: dict[str, Any]) -> None:
        """Persist snapshot metadata sidecar."""
        metadata_path = self._metadata_path(snapshot_path)
        with open(metadata_path, 'w', encoding='utf-8') as metadata_file:
            json.dump(metadata, metadata_file, indent=2, ensure_ascii=False)

    def _load_metadata(self, snapshot_path: Path) -> dict[str, Any]:
        """Load snapshot metadata or synthesize deny-by-default legacy metadata."""
        metadata_path = self._metadata_path(snapshot_path)

        if metadata_path.exists():
            with open(metadata_path, 'r', encoding='utf-8') as metadata_file:
                metadata = json.load(metadata_file)
            metadata.setdefault('snapshot_name', snapshot_path.name)
            metadata.setdefault('folder_name', None)
            metadata['owner_user_id'] = self._normalize_owner_user_id(metadata.get('owner_user_id'))
            metadata.setdefault('owner_username', None)
            metadata.setdefault('access_scope', 'private' if metadata['owner_user_id'] is not None else 'open')
            metadata.setdefault('created_at', datetime.utcfromtimestamp(snapshot_path.stat().st_ctime).isoformat())
            metadata.setdefault('updated_at', datetime.utcfromtimestamp(snapshot_path.stat().st_mtime).isoformat())
            metadata['legacy_unowned'] = False
            return metadata

        stat = snapshot_path.stat()
        return {
            'schema_version': 0,
            'snapshot_name': snapshot_path.name,
            'folder_name': None,
            'owner_user_id': None,
            'owner_username': None,
            'access_scope': 'legacy',
            'created_at': datetime.utcfromtimestamp(stat.st_ctime).isoformat(),
            'updated_at': datetime.utcfromtimestamp(stat.st_mtime).isoformat(),
            'legacy_unowned': True,
        }

    def _is_accessible(
        self,
        metadata: dict[str, Any],
        auth_enabled: bool,
        requester_user_id: Any,
    ) -> bool:
        """Check whether the current request may access the snapshot."""
        if not auth_enabled:
            return True

        normalized_requester_id = self._normalize_owner_user_id(requester_user_id)
        if normalized_requester_id is None:
            return False

        owner_user_id = metadata.get('owner_user_id')
        return owner_user_id is not None and owner_user_id == normalized_requester_id

    def _validate_snapshot_name(self, name: str) -> str:
        """Validate a public snapshot name without silently rewriting it."""
        if name is None:
            raise ValueError("Snapshot name cannot be empty")

        raw_name = str(name).strip()
        if not raw_name:
            raise ValueError("Snapshot name cannot be empty")

        if '/' in raw_name or '\\' in raw_name:
            raise ValueError("Snapshot name must not contain path separators")

        if Path(raw_name).name != raw_name:
            raise ValueError("Snapshot name must not contain path components")

        safe_name = secure_filename(raw_name)
        if not safe_name or safe_name != raw_name:
            raise ValueError("Invalid snapshot name")

        return safe_name

    def _get_snapshot_directory(self, name: str) -> Path:
        """Resolve snapshot directory from public snapshot name."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        return snapshot_path

    def _authorize_snapshot(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> tuple[Path, dict[str, Any]]:
        """Resolve snapshot directory and enforce owner access when auth is enabled."""
        snapshot_path = self._get_snapshot_directory(name)
        metadata = self._load_metadata(snapshot_path)

        if not self._is_accessible(metadata, auth_enabled, requester_user_id):
            logger.warning(
                "Snapshot access denied: snapshot=%s requester_user_id=%s auth_enabled=%s",
                snapshot_path.name,
                requester_user_id,
                auth_enabled,
            )
            raise PermissionError(f"Access denied to snapshot '{snapshot_path.name}'")

        return snapshot_path, metadata

    def _count_snapshot_files(self, configs_dir: Path) -> int:
        """Count uploadable snapshot files using the configured allowlist."""
        return sum(
            1
            for file_path in configs_dir.iterdir()
            if file_path.is_file() and file_path.suffix.lower() in ALLOWED_EXTENSIONS
        )

    def _build_snapshot_response(self, snapshot_path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
        """Build API response payload for snapshot metadata."""
        configs_dir = snapshot_path / 'configs'
        file_count = self._count_snapshot_files(configs_dir) if configs_dir.exists() else 0

        return {
            'name': snapshot_path.name,
            'file_count': file_count,
            'created_at': metadata.get('created_at') or datetime.utcfromtimestamp(snapshot_path.stat().st_ctime).isoformat(),
            'size_bytes': self._get_directory_size(snapshot_path),
            'folder_name': metadata.get('folder_name'),
            'owner_username': metadata.get('owner_username'),
            'legacy_unowned': metadata.get('legacy_unowned', False),
        }

    def _validate_upload_content(self, file_storage: Any, filename: str) -> int:
        """Run shared upload validation and return the validated file size."""
        validation_result = validate_file_upload(file_storage)
        return int(validation_result['size'])

    def _validate_snapshot_file_name(self, filename: str) -> str:
        """Validate an uploaded snapshot file name without silently rewriting it."""
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be empty")

        if '/' in filename or '\\' in filename:
            raise ValueError("Filename must not contain path separators")

        if Path(filename).name != filename:
            raise ValueError("Filename must not contain path components")

        safe_filename = secure_filename(filename)
        if not safe_filename or safe_filename != filename:
            raise ValueError("Invalid filename")

        if Path(safe_filename).suffix.lower() not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File type not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

        return safe_filename

    def _get_snapshot_config_file(self, snapshot_path: Path, filename: str) -> Path:
        """Resolve an uploaded config/log file under the snapshot configs directory."""
        safe_filename = self._validate_snapshot_file_name(filename)
        configs_dir = snapshot_path / 'configs'

        if not configs_dir.exists():
            raise FileNotFoundError(f"Snapshot '{snapshot_path.name}' is missing configs directory")

        configs_dir_resolved = configs_dir.resolve(strict=True)
        file_path = configs_dir / safe_filename

        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"File '{safe_filename}' not found")

        file_path_resolved = file_path.resolve(strict=True)
        if file_path_resolved.parent != configs_dir_resolved:
            raise ValueError("Invalid file path")

        return file_path_resolved

    def _has_rancid_content_type_header(self, line: str) -> bool:
        """Return whether a line is a Batfish RANCID content type header."""
        normalized_line = line.strip()
        return normalized_line.startswith(RANCID_CONTENT_TYPE_HEADER)

    def _parse_rancid_content_type_header(self, line: str) -> str:
        """Return a RANCID content type value from a header line."""
        normalized_line = line.strip()
        return normalized_line[len(RANCID_CONTENT_TYPE_HEADER):].strip()

    def _read_rancid_format_override(self, file_path: Path) -> dict[str, Optional[str]]:
        """Read the first-line Batfish RANCID format override, if present."""
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError("Snapshot file must be UTF-8 text") from exc

        first_line = content.splitlines(keepends=True)[0] if content else ''
        if not self._has_rancid_content_type_header(first_line):
            return {
                'configuration_format_override': None,
                'unsupported_configuration_format_override': None,
            }

        header_value = self._parse_rancid_content_type_header(first_line)
        if header_value in SUPPORTED_RANCID_FORMATS:
            return {
                'configuration_format_override': header_value,
                'unsupported_configuration_format_override': None,
            }

        return {
            'configuration_format_override': None,
            'unsupported_configuration_format_override': header_value,
        }

    def _build_snapshot_file_response(self, file_path: Path) -> dict[str, Any]:
        """Build API response payload for one uploaded snapshot file."""
        stat = file_path.stat()
        format_override_error = None

        try:
            format_override = self._read_rancid_format_override(file_path)
            format_override_supported = file_path.suffix.lower() in CONFIG_FORMAT_EXTENSIONS
        except ValueError as exc:
            format_override = {
                'configuration_format_override': None,
                'unsupported_configuration_format_override': None,
            }
            format_override_supported = False
            format_override_error = str(exc)

        return {
            'name': file_path.name,
            'size_bytes': stat.st_size,
            'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'configuration_format_override': format_override['configuration_format_override'],
            'unsupported_configuration_format_override': format_override['unsupported_configuration_format_override'],
            'format_override_supported': format_override_supported,
            'format_override_error': format_override_error,
        }

    def _encode_artifact_id(self, relative_path: Path) -> str:
        """Create a URL-safe artifact identifier from a snapshot-relative path."""
        normalized = relative_path.as_posix()
        return base64.urlsafe_b64encode(normalized.encode('utf-8')).decode('ascii').rstrip('=')

    def _decode_artifact_id(self, artifact_id: str) -> Path:
        """Decode a URL-safe artifact identifier to a snapshot-relative path."""
        if not artifact_id or not isinstance(artifact_id, str):
            raise ValueError("Artifact ID cannot be empty")

        padding = '=' * (-len(artifact_id) % 4)
        try:
            decoded = base64.urlsafe_b64decode(f"{artifact_id}{padding}").decode('utf-8')
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid artifact ID") from exc

        relative_path = Path(decoded)
        if relative_path.is_absolute() or '..' in relative_path.parts or not relative_path.parts:
            raise ValueError("Invalid artifact path")

        return relative_path

    def _resolve_snapshot_relative_path(self, snapshot_path: Path, relative_path: Path) -> Path:
        """Resolve a snapshot-relative path and enforce snapshot-root containment."""
        snapshot_root = snapshot_path.resolve(strict=True)
        target_path = (snapshot_path / relative_path).resolve(strict=False)

        try:
            target_path.relative_to(snapshot_root)
        except ValueError as exc:
            raise ValueError("Artifact path escapes snapshot root") from exc

        return target_path

    def _normalize_artifact_type(self, artifact_type: Any) -> str:
        """Validate and normalize an artifact type identifier."""
        normalized = str(artifact_type or '').strip()
        if normalized not in ARTIFACT_TYPE_DEFINITIONS:
            raise ValueError("Unsupported artifact type")
        return normalized

    def _normalize_artifact_metadata(self, metadata: Any) -> dict[str, str]:
        """Normalize user-supplied artifact metadata."""
        if metadata is None or metadata == '':
            return {}
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError as exc:
                raise ValueError("Artifact metadata must be valid JSON") from exc
        if not isinstance(metadata, dict):
            raise ValueError("Artifact metadata must be a JSON object")

        normalized: dict[str, str] = {}
        for key, value in metadata.items():
            key_text = str(key).strip()
            if not key_text:
                continue
            if value is None:
                continue
            normalized[key_text] = str(value).strip()
        return normalized

    def _validate_artifact_segment(self, value: Any, field_name: str, required: bool = False) -> Optional[str]:
        """Validate one metadata segment used to build a Batfish artifact path."""
        if value is None or str(value).strip() == '':
            if required:
                raise ValueError(f"Missing required artifact metadata: {field_name}")
            return None

        segment = str(value).strip()
        if not ARTIFACT_SEGMENT_PATTERN.fullmatch(segment):
            raise ValueError(
                f"Invalid {field_name}. Use letters, numbers, dots, underscores, or hyphens only."
            )
        return segment

    def _validate_artifact_filename(
        self,
        filename: Any,
        artifact_type: str,
        definition: dict[str, Any],
    ) -> str:
        """Validate an artifact filename for a specific artifact type."""
        if not filename or not str(filename).strip():
            fixed_destination = definition.get('fixed_destination')
            if fixed_destination:
                return Path(fixed_destination).name
            raise ValueError("Artifact filename cannot be empty")

        raw_filename = str(filename).strip()
        if '/' in raw_filename or '\\' in raw_filename:
            raise ValueError("Artifact filename must not contain path separators")
        if Path(raw_filename).name != raw_filename:
            raise ValueError("Artifact filename must not contain path components")

        safe_filename = secure_filename(raw_filename)
        if not safe_filename or safe_filename != raw_filename:
            raise ValueError("Invalid artifact filename")

        if artifact_type == 'sonic_config':
            if not any(safe_filename.endswith(suffix) for suffix in ARTIFACT_ALLOWED_SONIC_SUFFIXES):
                raise ValueError(
                    "SONiC artifact filename must end with one of: "
                    f"{', '.join(ARTIFACT_ALLOWED_SONIC_SUFFIXES)}"
                )
            return safe_filename

        if artifact_type == 'checkpoint_management':
            allowed_files = CHECKPOINT_DOMAIN_FILES | CHECKPOINT_PACKAGE_FILES
            if safe_filename not in allowed_files:
                raise ValueError(
                    "Unsupported Check Point Management API file. "
                    f"Allowed filenames: {', '.join(sorted(allowed_files))}"
                )
            return safe_filename

        allowed_extensions = set(definition.get('allowed_extensions') or [])
        if allowed_extensions and Path(safe_filename).suffix.lower() not in allowed_extensions:
            raise ValueError(f"Artifact file type not allowed. Allowed: {', '.join(sorted(allowed_extensions))}")

        return safe_filename

    def _build_artifact_relative_path(
        self,
        artifact_type: str,
        filename: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Path:
        """Build a safe snapshot-relative path from artifact type and metadata."""
        definition = ARTIFACT_TYPE_DEFINITIONS[artifact_type]
        metadata = metadata or {}

        fixed_destination = definition.get('fixed_destination')
        if fixed_destination:
            return Path(fixed_destination)

        validated_filename = self._validate_artifact_filename(filename, artifact_type, definition)

        if artifact_type == 'network_config':
            return Path('configs') / validated_filename

        if artifact_type == 'aws_config':
            account = self._validate_artifact_segment(metadata.get('account'), 'account', required=False)
            region = self._validate_artifact_segment(metadata.get('region'), 'region', required=False)
            parts = ['aws_configs']
            if account:
                parts.append(account)
            if region:
                parts.append(region)
            parts.append(validated_filename)
            return Path(*parts)

        if artifact_type == 'azure_config':
            return Path('azure_configs') / validated_filename

        if artifact_type == 'checkpoint_management':
            manager = self._validate_artifact_segment(metadata.get('manager'), 'manager', required=True)
            domain = self._validate_artifact_segment(metadata.get('domain'), 'domain', required=True)
            package = self._validate_artifact_segment(metadata.get('package'), 'package', required=False)
            parts = ['checkpoint_management', manager, domain]
            if package:
                if validated_filename not in CHECKPOINT_PACKAGE_FILES:
                    raise ValueError("Package-level Check Point files must be rulebase or package files")
                parts.append(package)
            elif validated_filename in CHECKPOINT_PACKAGE_FILES - {'show-package.json'}:
                raise ValueError("Package rulebase files require package metadata")
            parts.append(validated_filename)
            return Path(*parts)

        if artifact_type == 'sonic_config':
            device = self._validate_artifact_segment(metadata.get('device'), 'device', required=True)
            return Path('sonic_configs') / device / validated_filename

        if artifact_type == 'host_model':
            return Path('hosts') / validated_filename

        if artifact_type == 'host_iptables':
            return Path('iptables') / validated_filename

        raise ValueError("Unsupported artifact type")

    def _validate_artifact_bytes(self, artifact_type: str, filename: str, content: bytes) -> int:
        """Validate artifact file content and return its size."""
        file_size = len(content)
        if file_size == 0:
            raise ValueError("Artifact file is empty")
        if file_size > MAX_FILE_SIZE:
            raise ValueError(
                f"Artifact file size ({file_size / 1024 / 1024:.2f}MB) exceeds "
                f"maximum allowed size ({MAX_FILE_SIZE / 1024 / 1024}MB)"
            )
        if b'\x00' in content:
            raise ValueError("Binary artifact files are not allowed")

        try:
            text = content.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError("Artifact file must be valid UTF-8 text") from exc

        self._validate_artifact_security_content(content)

        definition = ARTIFACT_TYPE_DEFINITIONS[artifact_type]
        content_kind = definition.get('content_kind')
        if content_kind == 'json' or filename.endswith('.json'):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Artifact file must be valid JSON: {exc}") from exc
            self._validate_artifact_json_payload(artifact_type, payload, filename)
        elif artifact_type == 'host_iptables':
            if '*filter' not in text and '-A ' not in text:
                raise ValueError("Host iptables artifact should look like iptables-save output")

        return file_size

    def _validate_artifact_json_payload(
        self,
        artifact_type: str,
        payload: Any,
        filename: Optional[str] = None,
    ) -> None:
        """Run lightweight schema checks for JSON artifacts."""
        if artifact_type == 'aws_config':
            if not isinstance(payload, dict) or not payload:
                raise ValueError("AWS config JSON must be a non-empty API response object")
            return

        if artifact_type == 'azure_config':
            if not isinstance(payload, dict):
                raise ValueError("Azure resource JSON must be an object")
            if any(key in payload for key in ('$schema', 'contentVersion', 'resources', 'parameters')):
                raise ValueError("Azure ARM templates are not supported; upload Azure resource JSON views")
            if not isinstance(payload.get('id'), str) or not isinstance(payload.get('type'), str):
                raise ValueError("Azure resource JSON view must include string 'id' and 'type' fields")
            return

        if artifact_type == 'checkpoint_management':
            if not isinstance(payload, dict):
                raise ValueError("Check Point management JSON must be an API response object")
            return

        if artifact_type == 'layer1_topology':
            if not isinstance(payload, dict) or not isinstance(payload.get('edges'), list):
                raise ValueError("Layer 1 topology JSON must contain an 'edges' array")
            for index, edge in enumerate(payload['edges']):
                if not isinstance(edge, dict):
                    raise ValueError(f"Layer 1 edge at index {index} must be an object")
                for endpoint_key in ('node1', 'node2'):
                    endpoint = edge.get(endpoint_key)
                    if not isinstance(endpoint, dict):
                        raise ValueError(f"Layer 1 edge at index {index} must contain {endpoint_key}")
                    if not endpoint.get('hostname') or not endpoint.get('interfaceName'):
                        raise ValueError(
                            f"Layer 1 edge at index {index} requires hostname and interfaceName"
                        )
            return

        if artifact_type == 'host_model':
            if not isinstance(payload, dict):
                raise ValueError("Host model JSON must be an object")
            if not payload.get('hostname'):
                raise ValueError("Host model JSON must include hostname")
            if not isinstance(payload.get('hostInterfaces'), dict):
                raise ValueError("Host model JSON must include hostInterfaces object")
            iptables_file = payload.get('iptablesFile')
            if iptables_file is not None:
                self._validate_host_iptables_reference(iptables_file)
            return

        if artifact_type == 'isp_config':
            if not isinstance(payload, dict):
                raise ValueError("ISP modeling artifact must be a JSON object")
            known_sections = {'borderInterfaces', 'bgpPeers', 'filter', 'ispNodeInfo', 'ispPeerings'}
            if not any(section in payload for section in known_sections):
                raise ValueError("ISP modeling artifact must include at least one supported ISP section")
            return

        if artifact_type == 'runtime_data':
            if not isinstance(payload, dict) or not isinstance(payload.get('runtimeData'), dict):
                raise ValueError("Runtime data artifact must contain a 'runtimeData' object")
            return

        if artifact_type == 'external_bgp_announcements':
            if not isinstance(payload, dict) or not isinstance(payload.get('Announcements'), list):
                raise ValueError("External BGP announcements must contain an 'Announcements' array")
            required_keys = {'type', 'network', 'nextHopIp', 'srcIp', 'dstNode', 'dstIp'}
            for index, announcement in enumerate(payload['Announcements']):
                if not isinstance(announcement, dict):
                    raise ValueError(f"Announcement at index {index} must be an object")
                missing_keys = sorted(key for key in required_keys if not announcement.get(key))
                if missing_keys:
                    raise ValueError(
                        f"Announcement at index {index} is missing required fields: {', '.join(missing_keys)}"
                    )
            return

    def _validate_snapshot_relative_reference(self, value: Any, field_name: str) -> Path:
        """Validate a snapshot-relative reference stored inside artifact content."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty snapshot-relative path")

        reference = value.strip()
        if len(reference) > 240:
            raise ValueError(f"{field_name} is too long")
        if '\0' in reference or '\\' in reference:
            raise ValueError(f"{field_name} must use a safe POSIX-style relative path")

        relative_path = Path(reference)
        if relative_path.is_absolute() or '..' in relative_path.parts or not relative_path.parts:
            raise ValueError(f"{field_name} must be a snapshot-relative path")

        for part in relative_path.parts:
            if part in {'', '.', '..'} or not ARTIFACT_SEGMENT_PATTERN.fullmatch(part):
                raise ValueError(
                    f"{field_name} contains an invalid path segment. "
                    "Use letters, numbers, dots, underscores, or hyphens only."
                )

        return relative_path

    def _validate_host_iptables_reference(self, value: Any) -> Path:
        """Validate the supported iptablesFile path used by host model JSON."""
        relative_path = self._validate_snapshot_relative_reference(value, 'iptablesFile')
        if len(relative_path.parts) != 2 or relative_path.parts[0] != 'iptables':
            raise ValueError("iptablesFile must point to iptables/<filename>")
        if relative_path.suffix.lower() not in ARTIFACT_TYPE_DEFINITIONS['host_iptables']['allowed_extensions']:
            raise ValueError("iptablesFile must reference a supported host iptables file extension")
        return relative_path

    def _validate_artifact_security_content(self, content: bytes) -> None:
        """Apply shared upload security checks to advanced artifact content."""
        for pattern in DANGEROUS_PATTERNS:
            if pattern.search(content):
                logger.warning("Dangerous pattern detected in snapshot artifact upload")
                raise ValueError("Artifact file contains potentially malicious content")

        mime = None
        try:
            mime = magic.from_buffer(content, mime=True)
        except Exception as exc:
            logger.error("Error checking artifact MIME type: %s", exc)

        if mime and not mime.startswith('text/') and mime not in ARTIFACT_ALLOWED_MIME_TYPES:
            logger.warning("Rejected artifact with MIME type: %s", mime)
            raise ValueError(f"Artifact file type not allowed: {mime}")

    def _preview_token_secret(self) -> bytes:
        """Return the process secret used for short-lived artifact preview tokens."""
        return config.SECRET_KEY.encode('utf-8')

    def _encode_preview_token_part(self, payload: bytes) -> str:
        return base64.urlsafe_b64encode(payload).decode('ascii').rstrip('=')

    def _decode_preview_token_part(self, payload: str) -> bytes:
        padded_payload = payload + ('=' * (-len(payload) % 4))
        return base64.urlsafe_b64decode(padded_payload.encode('ascii'))

    def _artifact_state_fingerprint(self, artifact_id: Any, artifact_path: Optional[Path]) -> Optional[dict[str, Any]]:
        """Return a stable fingerprint for the artifact state that was previewed."""
        if not artifact_id or artifact_path is None:
            return None

        try:
            stat = artifact_path.stat()
        except FileNotFoundError:
            return {
                'artifact_id': str(artifact_id),
                'exists': False,
            }

        digest = hashlib.sha256()
        with artifact_path.open('rb') as artifact_file:
            for chunk in iter(lambda: artifact_file.read(1024 * 1024), b''):
                digest.update(chunk)

        return {
            'artifact_id': str(artifact_id),
            'exists': True,
            'size_bytes': stat.st_size,
            'modified_at_ns': stat.st_mtime_ns,
            'sha256': digest.hexdigest(),
        }

    def _preview_claims(
        self,
        snapshot_name: str,
        operation: str,
        artifact_type: str,
        current_destination: Optional[str],
        next_destination: str,
        destination_exists: bool,
        artifact_state: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Build stable preview claims for a pending artifact mutation."""
        return {
            'snapshot_name': snapshot_name,
            'operation': operation,
            'artifact_type': artifact_type,
            'current_destination': current_destination,
            'next_destination': next_destination,
            'destination_exists': bool(destination_exists),
            'artifact_state': artifact_state,
        }

    def _sign_artifact_preview_token(self, claims: dict[str, Any]) -> str:
        """Create a short-lived signed token that proves a preview was requested."""
        payload = {
            'version': 1,
            'issued_at': int(time.time()),
            'claims': claims,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        signature = hmac.new(self._preview_token_secret(), payload_bytes, hashlib.sha256).digest()
        return f"{self._encode_preview_token_part(payload_bytes)}.{self._encode_preview_token_part(signature)}"

    def _validate_artifact_preview_token(self, token: Any, expected_claims: dict[str, Any]) -> None:
        """Validate that an artifact mutation matches a recent preview."""
        if not isinstance(token, str) or not token.strip():
            raise ValueError("Artifact preview token is required")

        parts = token.strip().split('.')
        if len(parts) != 2:
            raise ValueError("Invalid artifact preview token")

        try:
            payload_bytes = self._decode_preview_token_part(parts[0])
            signature = self._decode_preview_token_part(parts[1])
        except Exception as exc:
            raise ValueError("Invalid artifact preview token") from exc

        expected_signature = hmac.new(self._preview_token_secret(), payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid artifact preview token")

        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid artifact preview token") from exc

        issued_at = payload.get('issued_at')
        if not isinstance(issued_at, int) or int(time.time()) - issued_at > ARTIFACT_PREVIEW_TOKEN_TTL_SECONDS:
            raise ValueError("Artifact preview token has expired")

        if payload.get('claims') != expected_claims:
            raise ValueError("Artifact preview token does not match this request")

    def _write_artifact_bytes_atomic(self, destination: Path, content: bytes) -> None:
        """Write artifact content atomically in the destination directory."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Optional[Path] = None

        try:
            with tempfile.NamedTemporaryFile(
                mode='wb',
                dir=str(destination.parent),
                prefix=f".{destination.name}.",
                suffix='.tmp',
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(content)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.replace(temp_path, destination)
        except Exception:
            if temp_path and temp_path.exists():
                temp_path.unlink()
            raise

    def _read_file_storage_bytes(self, file_storage: Any) -> tuple[str, bytes]:
        """Read upload content and return sanitized original filename plus bytes."""
        if not file_storage or not file_storage.filename:
            raise ValueError("No artifact file provided")
        raw_filename = str(file_storage.filename).strip()
        filename = secure_filename(raw_filename)
        if not filename or filename != raw_filename:
            raise ValueError("Invalid artifact filename")
        content = file_storage.read(MAX_FILE_SIZE + 1)
        file_storage.seek(0)
        return filename, content

    def _infer_artifact_type(self, relative_path: Path) -> Optional[str]:
        """Infer a known artifact type from a snapshot-relative file path."""
        parts = relative_path.parts
        if not parts:
            return None

        if parts[0] == 'configs' and relative_path.suffix.lower() in ALLOWED_EXTENSIONS:
            return 'network_config'
        if parts[0] == 'aws_configs' and relative_path.suffix.lower() == '.json':
            return 'aws_config'
        if parts[0] == 'azure_configs' and relative_path.suffix.lower() == '.json':
            return 'azure_config'
        if parts[0] == 'checkpoint_management' and relative_path.suffix.lower() == '.json':
            return 'checkpoint_management'
        if parts[0] == 'sonic_configs' and any(relative_path.name.endswith(suffix) for suffix in ARTIFACT_ALLOWED_SONIC_SUFFIXES):
            return 'sonic_config'
        if parts[0] == 'hosts' and relative_path.suffix.lower() == '.json':
            return 'host_model'
        if parts[0] == 'iptables' and relative_path.suffix.lower() in {'.iptables', '.txt', '.conf'}:
            return 'host_iptables'
        if relative_path.as_posix() == 'batfish/layer1_topology.json':
            return 'layer1_topology'
        if relative_path.as_posix() == 'batfish/isp_config.json':
            return 'isp_config'
        if relative_path.as_posix() == 'batfish/runtime_data.json':
            return 'runtime_data'
        if relative_path.as_posix() == 'external_bgp_announcements.json':
            return 'external_bgp_announcements'

        return None

    def _infer_artifact_metadata(self, artifact_type: str, relative_path: Path) -> dict[str, Optional[str]]:
        """Infer display metadata from a known artifact path."""
        parts = relative_path.parts
        if artifact_type == 'aws_config':
            if len(parts) >= 4:
                return {'account': parts[1], 'region': parts[2]}
            if len(parts) == 3:
                return {'account': None, 'region': parts[1]}
            return {'account': None, 'region': None}
        if artifact_type == 'checkpoint_management':
            return {
                'manager': parts[1] if len(parts) > 1 else None,
                'domain': parts[2] if len(parts) > 2 else None,
                'package': parts[3] if len(parts) > 4 else None,
            }
        if artifact_type == 'sonic_config':
            return {'device': parts[1] if len(parts) > 1 else None}
        return {}

    def _build_artifact_record(self, snapshot_path: Path, file_path: Path) -> Optional[dict[str, Any]]:
        """Build a serializable artifact record for a known Batfish artifact file."""
        if not file_path.is_file() or file_path.is_symlink():
            return None

        snapshot_root = snapshot_path.resolve(strict=True)
        try:
            relative_path = file_path.resolve(strict=True).relative_to(snapshot_root)
        except ValueError:
            return None

        if relative_path.name == METADATA_FILENAME:
            return None

        artifact_type = self._infer_artifact_type(relative_path)
        if artifact_type is None:
            return None

        stat = file_path.stat()
        definition = ARTIFACT_TYPE_DEFINITIONS[artifact_type]

        return {
            'artifact_id': self._encode_artifact_id(relative_path),
            'artifact_type': artifact_type,
            'label': definition['label'],
            'category': definition['category'],
            'logical_name': file_path.name,
            'relative_path': relative_path.as_posix(),
            'size_bytes': stat.st_size,
            'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'metadata': self._infer_artifact_metadata(artifact_type, relative_path),
            'mutation_policy': definition['mutation_policy'],
            'warnings': [],
        }

    def _get_artifact_record_by_id(self, snapshot_path: Path, artifact_id: str) -> tuple[dict[str, Any], Path]:
        """Resolve an artifact ID and return its current record and file path."""
        relative_path = self._decode_artifact_id(artifact_id)
        file_path = self._resolve_snapshot_relative_path(snapshot_path, relative_path)
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError("Artifact not found")
        record = self._build_artifact_record(snapshot_path, file_path)
        if record is None:
            raise ValueError("Unsupported artifact")
        return record, file_path

    def _normalize_rancid_format_override(self, format_override: Any) -> Optional[str]:
        """Normalize a requested RANCID format override value."""
        if format_override is None:
            return None

        normalized = str(format_override).strip()
        if not normalized or normalized == 'auto':
            return None

        if normalized not in SUPPORTED_RANCID_FORMATS:
            raise ValueError(
                f"Unsupported configuration format override. Supported: {', '.join(sorted(SUPPORTED_RANCID_FORMATS))}"
            )

        return normalized

    def _write_rancid_format_override(self, file_path: Path, format_override: Optional[str]) -> dict[str, Any]:
        """Atomically add, replace, or remove the first-line Batfish RANCID header."""
        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError as exc:
            raise ValueError("Snapshot file must be UTF-8 text") from exc

        lines = content.splitlines(keepends=True)
        has_header = bool(lines and self._has_rancid_content_type_header(lines[0]))

        if format_override is None:
            updated_content = ''.join(lines[1:]) if has_header else content
        else:
            line_ending = '\r\n' if lines and lines[0].endswith('\r\n') else '\n'
            header_line = f"{RANCID_CONTENT_TYPE_HEADER} {format_override}{line_ending}"
            if has_header:
                lines[0] = header_line
                updated_content = ''.join(lines)
            else:
                updated_content = header_line + content

        file_stat = file_path.stat()
        temp_path: Optional[Path] = None

        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                dir=str(file_path.parent),
                prefix=f".{file_path.name}.",
                suffix='.tmp',
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(updated_content)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.chmod(temp_path, file_stat.st_mode)
            os.replace(temp_path, file_path)
        except Exception:
            if temp_path and temp_path.exists():
                temp_path.unlink()
            raise

        return self._build_snapshot_file_response(file_path)

    def list_snapshots(self, requester_user_id: Any = None, auth_enabled: bool = False) -> list[dict[str, Any]]:
        """
        List all available snapshots

        Returns:
            List of snapshot metadata
        """
        snapshots = []

        for snapshot_path in self.snapshots_dir.iterdir():
            if not snapshot_path.is_dir():
                continue

            configs_dir = snapshot_path / 'configs'
            if not configs_dir.exists():
                continue

            metadata = self._load_metadata(snapshot_path)
            if not self._is_accessible(metadata, auth_enabled, requester_user_id):
                continue

            snapshots.append(self._build_snapshot_response(snapshot_path, metadata))

        # Sort by creation time (newest first)
        snapshots.sort(key=lambda x: x['created_at'], reverse=True)

        return snapshots

    def create_snapshot(
        self,
        name: str,
        folder_name: Optional[str] = None,
        owner_user_id: Any = None,
        owner_username: Optional[str] = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Create a new empty snapshot

        Args:
            name: Snapshot name

        Returns:
            Created snapshot metadata

        Raises:
            ValueError: If snapshot name is invalid or already exists
        """
        safe_name = self._validate_snapshot_name(name)

        normalized_folder_name = self._normalize_folder_name(folder_name)
        normalized_owner_id = self._normalize_owner_user_id(owner_user_id)

        if auth_enabled and normalized_owner_id is None:
            raise PermissionError("Authenticated snapshot creation requires a valid user")

        snapshot_path = self.snapshots_dir / safe_name

        if snapshot_path.exists():
            raise ValueError(f"Snapshot '{safe_name}' already exists")

        # Create directory structure
        configs_dir = snapshot_path / 'configs'
        configs_dir.mkdir(parents=True, exist_ok=True)
        metadata = self._build_metadata(
            snapshot_name=safe_name,
            folder_name=normalized_folder_name,
            owner_user_id=normalized_owner_id,
            owner_username=owner_username,
            access_scope='private' if normalized_owner_id is not None else 'open',
        )
        self._write_metadata(snapshot_path, metadata)

        logger.info(
            "Created snapshot: name=%s folder=%s owner_user_id=%s access_scope=%s",
            safe_name,
            metadata.get('folder_name'),
            metadata.get('owner_user_id'),
            metadata.get('access_scope'),
        )

        return self._build_snapshot_response(snapshot_path, metadata)

    def update_snapshot_metadata(
        self,
        name: str,
        folder_name: Optional[str],
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Update editable snapshot metadata for an existing snapshot.

        Args:
            name: Snapshot name
            folder_name: Folder classification to store

        Returns:
            Updated snapshot metadata response
        """
        snapshot_path, metadata = self._authorize_snapshot(
            name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        metadata['folder_name'] = self._normalize_folder_name(folder_name)
        metadata['updated_at'] = datetime.utcnow().isoformat()
        self._write_metadata(snapshot_path, metadata)

        logger.info(
            "Updated snapshot metadata: name=%s folder=%s requester_user_id=%s",
            snapshot_path.name,
            metadata.get('folder_name'),
            requester_user_id,
        )

        return self._build_snapshot_response(snapshot_path, metadata)

    def delete_snapshot(self, name: str, requester_user_id: Any = None, auth_enabled: bool = False) -> None:
        """
        Delete a snapshot

        Args:
            name: Snapshot name

        Raises:
            ValueError: If snapshot is protected
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = self._validate_snapshot_name(name)

        # Check if snapshot is protected
        if safe_name in PROTECTED_SNAPSHOTS:
            raise ValueError(f"Cannot delete protected snapshot: '{safe_name}'")

        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        shutil.rmtree(snapshot_path)
        logger.info(f"Deleted snapshot: {safe_name}")

    def get_snapshot_files(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Get list of configuration files in a snapshot

        Args:
            name: Snapshot name

        Returns:
            List of file metadata

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        configs_dir = snapshot_path / 'configs'

        if not configs_dir.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' is missing configs directory")

        files = []
        for file_path in configs_dir.iterdir():
            if not file_path.is_file():
                continue

            if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
                continue

            files.append(self._build_snapshot_file_response(file_path))

        # Sort by name
        files.sort(key=lambda x: x['name'])

        return files

    def upload_file(
        self,
        name: str,
        file_storage: Any,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Upload a configuration file to a snapshot

        Args:
            name: Snapshot name
            file_storage: Werkzeug FileStorage object

        Returns:
            Uploaded file metadata

        Raises:
            FileNotFoundError: If snapshot does not exist
            ValueError: If file is invalid
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        configs_dir = snapshot_path / 'configs'

        if not configs_dir.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' is missing configs directory")

        # Validate file
        if not file_storage or not file_storage.filename:
            raise ValueError("No file provided")

        filename = secure_filename(file_storage.filename)
        if not filename:
            raise ValueError("Invalid filename")

        # Check extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

        file_size = self._validate_upload_content(file_storage, filename)

        # Save file
        file_path = configs_dir / filename
        file_storage.save(str(file_path))

        logger.info(f"Uploaded file '{filename}' to snapshot '{safe_name}'")

        uploaded_file_info = self._build_snapshot_file_response(file_path)
        uploaded_file_info['size_bytes'] = file_size
        uploaded_file_info['requires_reinitialize'] = True

        return uploaded_file_info

    def get_artifact_types(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> list[dict[str, Any]]:
        """Return artifact type definitions available for one accessible snapshot."""
        self._authorize_snapshot(
            name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        return json.loads(json.dumps(list(ARTIFACT_TYPE_DEFINITIONS.values())))

    def get_artifact_tree(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Return recognized Batfish artifacts in the snapshot."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        artifacts: list[dict[str, Any]] = []
        for file_path in snapshot_path.rglob('*'):
            record = self._build_artifact_record(snapshot_path, file_path)
            if record is not None:
                artifacts.append(record)

        artifacts.sort(key=lambda item: (item['category'], item['artifact_type'], item['relative_path']))
        summary: dict[str, int] = {}
        for artifact in artifacts:
            summary[artifact['artifact_type']] = summary.get(artifact['artifact_type'], 0) + 1

        return {
            'snapshot_name': safe_name,
            'artifacts': artifacts,
            'summary': summary,
        }

    def preview_artifact_change(
        self,
        name: str,
        payload: dict[str, Any],
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Preview destination and active snapshot impact for an artifact mutation."""
        if not isinstance(payload, dict):
            raise ValueError("Artifact preview payload must be a JSON object")

        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        artifact_id = payload.get('artifact_id')
        operation = str(payload.get('operation') or 'upload').strip()
        current_record: Optional[dict[str, Any]] = None
        current_destination: Optional[str] = None
        current_path: Optional[Path] = None
        artifact_type = payload.get('artifact_type')
        filename = payload.get('filename')
        metadata = self._normalize_artifact_metadata(payload.get('metadata'))

        if artifact_id:
            current_record, current_path = self._get_artifact_record_by_id(snapshot_path, str(artifact_id))
            artifact_type = current_record['artifact_type']
            current_destination = current_record['relative_path']
            filename = filename or current_record['logical_name']
            if 'metadata' not in payload:
                metadata = self._normalize_artifact_metadata(current_record.get('metadata'))

        normalized_type = self._normalize_artifact_type(artifact_type)
        if operation in {'delete', 'replace'}:
            if not current_record or not current_destination:
                raise ValueError("Artifact ID is required for this preview operation")
            next_destination = current_destination
            destination = self._resolve_snapshot_relative_path(snapshot_path, Path(next_destination))
        else:
            relative_path = self._build_artifact_relative_path(normalized_type, filename=filename, metadata=metadata)
            destination = self._resolve_snapshot_relative_path(snapshot_path, relative_path)
            next_destination = relative_path.as_posix()
        destination_exists = destination.exists()

        if current_destination and current_destination != next_destination:
            preview_operation = 'safe_relocate'
        elif operation == 'replace':
            preview_operation = 'content_replace'
        elif operation == 'delete':
            preview_operation = 'delete'
        else:
            preview_operation = operation

        warnings = []
        if destination_exists and current_destination != next_destination:
            warnings.append("Destination already exists")
        if normalized_type == 'azure_config':
            warnings.append("Azure ARM templates are not supported; upload Azure resource JSON views.")
        if normalized_type == 'network_config' and Path(next_destination).suffix.lower() == '.log':
            warnings.append("Log files must still contain parseable device configuration when used for Batfish analysis.")

        claims = self._preview_claims(
            safe_name,
            preview_operation,
            normalized_type,
            current_destination,
            next_destination,
            destination_exists,
            self._artifact_state_fingerprint(
                current_record.get('artifact_id') if current_record else artifact_id,
                current_path,
            ),
        )

        return {
            'artifact_type': normalized_type,
            'operation': preview_operation,
            'current_destination': current_destination,
            'next_destination': next_destination,
            'destination_exists': destination_exists,
            'requires_reinitialize': True,
            'warnings': warnings,
            'preview_token': self._sign_artifact_preview_token(claims),
        }

    def upload_artifact(
        self,
        name: str,
        artifact_type: Any,
        file_storage: Any,
        metadata: Any = None,
        preview_token: Any = None,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Upload a typed Batfish artifact into the snapshot layout."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        normalized_type = self._normalize_artifact_type(artifact_type)
        definition = ARTIFACT_TYPE_DEFINITIONS[normalized_type]
        normalized_metadata = self._normalize_artifact_metadata(metadata)
        uploaded_filename, content = self._read_file_storage_bytes(file_storage)
        artifact_filename = self._validate_artifact_filename(uploaded_filename, normalized_type, definition)
        relative_path = self._build_artifact_relative_path(
            normalized_type,
            filename=artifact_filename,
            metadata=normalized_metadata,
        )
        destination = self._resolve_snapshot_relative_path(snapshot_path, relative_path)

        if destination.exists():
            raise ValueError("Artifact already exists. Replace its content instead of uploading a duplicate.")

        preview_claims = self._preview_claims(
            safe_name,
            'upload',
            normalized_type,
            None,
            relative_path.as_posix(),
            False,
            None,
        )
        self._validate_artifact_preview_token(preview_token, preview_claims)

        file_size = self._validate_artifact_bytes(normalized_type, destination.name, content)
        self._write_artifact_bytes_atomic(destination, content)
        record = self._build_artifact_record(snapshot_path, destination)
        if record is None:
            raise ValueError("Uploaded artifact could not be indexed")

        record['size_bytes'] = file_size
        record['requires_reinitialize'] = True

        logger.info(
            "Uploaded snapshot artifact: snapshot=%s artifact_type=%s path=%s requester_user_id=%s",
            safe_name,
            normalized_type,
            relative_path.as_posix(),
            requester_user_id,
        )

        return record

    def update_artifact_metadata(
        self,
        name: str,
        artifact_id: str,
        payload: dict[str, Any],
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Apply a safe same-type metadata update that may relocate one artifact file."""
        if not isinstance(payload, dict):
            raise ValueError("Artifact update payload must be a JSON object")

        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        current_record, current_path = self._get_artifact_record_by_id(snapshot_path, artifact_id)
        artifact_type = current_record['artifact_type']
        requested_type = payload.get('artifact_type')
        if requested_type and self._normalize_artifact_type(requested_type) != artifact_type:
            raise ValueError("Artifact type changes require a new upload")

        metadata_source = payload.get('metadata') if 'metadata' in payload else current_record.get('metadata')
        metadata = self._normalize_artifact_metadata(metadata_source)
        filename = payload.get('filename') or current_record['logical_name']
        next_relative_path = self._build_artifact_relative_path(artifact_type, filename=filename, metadata=metadata)
        next_path = self._resolve_snapshot_relative_path(snapshot_path, next_relative_path)
        preview_operation = 'safe_relocate' if next_path != current_path else 'metadata_update'
        preview_claims = self._preview_claims(
            safe_name,
            preview_operation,
            artifact_type,
            current_record['relative_path'],
            next_relative_path.as_posix(),
            next_path.exists(),
            self._artifact_state_fingerprint(current_record.get('artifact_id'), current_path),
        )
        self._validate_artifact_preview_token(payload.get('preview_token'), preview_claims)

        if next_path == current_path:
            current_record['requires_reinitialize'] = False
            return current_record

        if next_path.exists():
            raise ValueError("Destination already exists")

        next_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(current_path, next_path)
        updated_record = self._build_artifact_record(snapshot_path, next_path)
        if updated_record is None:
            raise ValueError("Updated artifact could not be indexed")
        updated_record['requires_reinitialize'] = True

        logger.info(
            "Relocated snapshot artifact: snapshot=%s artifact_type=%s from=%s to=%s requester_user_id=%s",
            safe_name,
            artifact_type,
            current_record['relative_path'],
            next_relative_path.as_posix(),
            requester_user_id,
        )

        return updated_record

    def replace_artifact_content(
        self,
        name: str,
        artifact_id: str,
        file_storage: Any,
        preview_token: Any = None,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Replace one artifact file without changing its artifact type or destination."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        current_record, current_path = self._get_artifact_record_by_id(snapshot_path, artifact_id)
        artifact_type = current_record['artifact_type']
        preview_claims = self._preview_claims(
            safe_name,
            'content_replace',
            artifact_type,
            current_record['relative_path'],
            current_record['relative_path'],
            True,
            self._artifact_state_fingerprint(current_record.get('artifact_id'), current_path),
        )
        self._validate_artifact_preview_token(preview_token, preview_claims)
        _, content = self._read_file_storage_bytes(file_storage)
        file_size = self._validate_artifact_bytes(artifact_type, current_path.name, content)
        self._write_artifact_bytes_atomic(current_path, content)
        updated_record = self._build_artifact_record(snapshot_path, current_path)
        if updated_record is None:
            raise ValueError("Updated artifact could not be indexed")
        updated_record['size_bytes'] = file_size
        updated_record['requires_reinitialize'] = True

        logger.info(
            "Replaced snapshot artifact content: snapshot=%s artifact_type=%s path=%s requester_user_id=%s",
            safe_name,
            artifact_type,
            current_record['relative_path'],
            requester_user_id,
        )

        return updated_record

    def delete_artifact(
        self,
        name: str,
        artifact_id: str,
        preview_token: Any = None,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Delete one indexed artifact file."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        current_record, current_path = self._get_artifact_record_by_id(snapshot_path, artifact_id)
        preview_claims = self._preview_claims(
            safe_name,
            'delete',
            current_record['artifact_type'],
            current_record['relative_path'],
            current_record['relative_path'],
            True,
            self._artifact_state_fingerprint(current_record.get('artifact_id'), current_path),
        )
        self._validate_artifact_preview_token(preview_token, preview_claims)
        current_path.unlink()

        logger.info(
            "Deleted snapshot artifact: snapshot=%s artifact_type=%s path=%s requester_user_id=%s",
            safe_name,
            current_record['artifact_type'],
            current_record['relative_path'],
            requester_user_id,
        )

        return {
            'artifact_id': artifact_id,
            'artifact_type': current_record['artifact_type'],
            'relative_path': current_record['relative_path'],
            'requires_reinitialize': True,
        }

    def validate_snapshot_artifacts(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Run lightweight layout validation for typed snapshot artifacts."""
        tree = self.get_artifact_tree(
            name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        snapshot_path, _ = self._authorize_snapshot(
            name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        artifacts = tree['artifacts']
        errors: list[str] = []
        warnings: list[str] = []

        sonic_by_device: dict[str, set[str]] = {}
        for artifact in artifacts:
            artifact_path = self._resolve_snapshot_relative_path(snapshot_path, Path(artifact['relative_path']))
            try:
                content = artifact_path.read_bytes()
                self._validate_artifact_bytes(artifact['artifact_type'], artifact['logical_name'], content)
            except (OSError, ValueError) as exc:
                errors.append(f"Invalid artifact content: {artifact['relative_path']} ({exc})")
                continue

            if artifact['artifact_type'] == 'sonic_config':
                device = artifact.get('metadata', {}).get('device') or 'unknown'
                sonic_by_device.setdefault(device, set()).add(artifact['logical_name'])

            if artifact['artifact_type'] == 'host_model':
                try:
                    host_payload = json.loads(content.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    errors.append(f"Invalid host model JSON: {artifact['relative_path']} ({exc})")
                    continue
                iptables_file = host_payload.get('iptablesFile')
                if iptables_file:
                    try:
                        iptables_relative_path = self._validate_host_iptables_reference(iptables_file)
                        iptables_path = self._resolve_snapshot_relative_path(snapshot_path, iptables_relative_path)
                        if not iptables_path.exists():
                            warnings.append(
                                f"Host model references missing iptables file: {artifact['relative_path']} -> {iptables_file}"
                            )
                        else:
                            iptables_record = self._build_artifact_record(snapshot_path, iptables_path)
                            if not iptables_record or iptables_record['artifact_type'] != 'host_iptables':
                                errors.append(
                                    f"Host model iptablesFile is not a supported host iptables artifact: "
                                    f"{artifact['relative_path']} -> {iptables_file}"
                                )
                                continue
                            try:
                                iptables_content = iptables_path.read_bytes()
                                self._validate_artifact_bytes('host_iptables', iptables_path.name, iptables_content)
                            except (OSError, ValueError) as exc:
                                errors.append(
                                    f"Invalid host iptables artifact content: "
                                    f"{artifact['relative_path']} -> {iptables_file} ({exc})"
                                )
                    except ValueError as exc:
                        errors.append(f"Invalid host model iptablesFile: {artifact['relative_path']} ({exc})")

        for device, filenames in sonic_by_device.items():
            if not any(name.endswith('config_db.json') for name in filenames):
                errors.append(f"SONiC device '{device}' is missing config_db.json")
            if not any(name.endswith('frr.conf') for name in filenames):
                warnings.append(f"SONiC device '{device}' is missing frr.conf")

        status = 'passed' if not errors else 'failed'
        return {
            'status': status,
            'artifact_count': len(artifacts),
            'errors': errors,
            'warnings': warnings,
        }

    def update_snapshot_file_format(
        self,
        name: str,
        filename: str,
        configuration_format_override: Any,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Update a snapshot file's first-line Batfish RANCID format override."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        file_path = self._get_snapshot_config_file(snapshot_path, filename)
        normalized_format = self._normalize_rancid_format_override(configuration_format_override)
        file_info = self._write_rancid_format_override(file_path, normalized_format)
        file_info['requires_reinitialize'] = True

        logger.info(
            "Updated snapshot file format override: snapshot=%s file=%s format=%s requester_user_id=%s",
            safe_name,
            file_path.name,
            normalized_format or 'auto',
            requester_user_id,
        )

        return file_info

    def delete_snapshot_file(
        self,
        name: str,
        filename: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """Delete one uploaded snapshot file from the snapshot configs directory."""
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        file_path = self._get_snapshot_config_file(snapshot_path, filename)
        deleted_filename = file_path.name

        file_path.unlink()

        logger.info(
            "Deleted snapshot file: snapshot=%s file=%s requester_user_id=%s",
            safe_name,
            deleted_filename,
            requester_user_id,
        )

        return {
            'name': deleted_filename,
            'requires_reinitialize': True,
        }

    def get_snapshot_path(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> Path:
        """
        Get the full path to a snapshot directory

        Args:
            name: Snapshot name

        Returns:
            Path object

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        snapshot_path, _ = self._authorize_snapshot(
            name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )
        return snapshot_path

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes"""
        total = 0
        for entry in path.rglob('*'):
            if entry.is_file():
                total += entry.stat().st_size
        return total

    def get_layer1_topology(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Get Layer1 topology configuration for a snapshot

        Args:
            name: Snapshot name

        Returns:
            Layer1 topology data with edges array

        Raises:
            FileNotFoundError: If snapshot does not exist
            ValueError: If layer1_topology.json contains invalid JSON
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        layer1_file = snapshot_path / 'batfish' / 'layer1_topology.json'

        if not layer1_file.exists():
            return {"edges": []}

        try:
            with open(layer1_file, 'r', encoding='utf-8') as f:
                topology = json.load(f)
            logger.info(f"Loaded Layer1 topology for snapshot '{safe_name}'")
            return topology
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in layer1_topology.json for '{safe_name}': {e}")
            raise ValueError(f"Invalid Layer1 topology file: {e}")

    def save_layer1_topology(
        self,
        name: str,
        topology_data: dict[str, Any],
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Save Layer1 topology configuration with comprehensive validation

        Args:
            name: Snapshot name
            topology_data: Layer1 topology data with edges array

        Returns:
            Save result metadata

        Raises:
            FileNotFoundError: If snapshot does not exist
            ValueError: If topology data is invalid
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        # Validate topology data structure
        if not isinstance(topology_data, dict):
            raise ValueError("Topology data must be a JSON object")

        if 'edges' not in topology_data:
            raise ValueError("Topology data must contain 'edges' array")

        if not isinstance(topology_data['edges'], list):
            raise ValueError("'edges' must be an array")

        # Validate each edge
        for idx, edge in enumerate(topology_data['edges']):
            if not isinstance(edge, dict):
                raise ValueError(f"Edge at index {idx} must be an object")

            if 'node1' not in edge or 'node2' not in edge:
                raise ValueError(f"Edge at index {idx} must contain 'node1' and 'node2'")

            for node_key in ['node1', 'node2']:
                node = edge[node_key]
                if not isinstance(node, dict):
                    raise ValueError(f"Edge at index {idx}: '{node_key}' must be an object")

                if 'hostname' not in node or 'interfaceName' not in node:
                    raise ValueError(
                        f"Edge at index {idx}: '{node_key}' must contain 'hostname' and 'interfaceName'"
                    )

        # Save to batfish/ directory only (Batfish reads from this location)
        batfish_dir = snapshot_path / 'batfish'
        layer1_file = batfish_dir / 'layer1_topology.json'

        try:
            # Ensure batfish directory exists
            batfish_dir.mkdir(exist_ok=True)

            # Write to batfish/ directory
            with open(layer1_file, 'w', encoding='utf-8') as f:
                json.dump(topology_data, f, indent=2, ensure_ascii=False)

            file_size = layer1_file.stat().st_size
            edge_count = len(topology_data['edges'])

            logger.info(f"Saved Layer1 topology for snapshot '{safe_name}': {edge_count} edges, {file_size} bytes")

            return {
                'snapshot_name': safe_name,
                'edge_count': edge_count,
                'file_size_bytes': file_size
            }
        except Exception as e:
            logger.error(f"Failed to write layer1_topology.json for '{safe_name}': {e}")
            raise

    def delete_layer1_topology(
        self,
        name: str,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> None:
        """
        Delete Layer1 topology configuration

        Args:
            name: Snapshot name

        Raises:
            FileNotFoundError: If snapshot or Layer1 file does not exist
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        layer1_file = snapshot_path / 'batfish' / 'layer1_topology.json'

        if not layer1_file.exists():
            raise FileNotFoundError(f"Layer1 topology file not found for snapshot '{safe_name}'")

        layer1_file.unlink()
        logger.info(f"Deleted Layer1 topology for snapshot '{safe_name}'")

    def get_snapshot_interfaces(
        self,
        name: str,
        batfish_service,
        requester_user_id: Any = None,
        auth_enabled: bool = False,
    ) -> dict[str, Any]:
        """
        Get all interfaces for devices in a snapshot

        Args:
            name: Snapshot name
            batfish_service: Batfish service instance

        Returns:
            Dictionary mapping hostnames to interface lists

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = self._validate_snapshot_name(name)
        snapshot_path, _ = self._authorize_snapshot(
            safe_name,
            requester_user_id=requester_user_id,
            auth_enabled=auth_enabled,
        )

        # Check if snapshot is already initialized
        # Only initialize if different snapshot or not initialized
        if batfish_service.current_snapshot_name != safe_name:
            logger.info(f"Initializing snapshot '{safe_name}' for Layer1 editor")
            batfish_service.initialize_network(str(snapshot_path), snapshot_name=safe_name)

            # After initialization, call node_properties first to ensure Batfish parsing is complete
            # This gives Batfish time to fully analyze the snapshot before querying interfaces
            _ = batfish_service.get_node_properties()
        else:
            logger.debug(f"Using existing Batfish session for snapshot '{safe_name}'")

        # Get interface properties from Batfish
        interfaces_data = batfish_service.get_interface_properties()

        # Group interfaces by hostname
        result = {}

        for interface in interfaces_data:
            hostname = interface.get('hostname')
            interface_name = interface.get('interface')

            if not hostname or not interface_name:
                continue

            if hostname not in result:
                result[hostname] = {
                    'hostname': hostname,
                    'interfaces': []
                }

            result[hostname]['interfaces'].append({
                'name': interface_name,
                'active': interface.get('active', False),
                'description': interface.get('description', '')
            })

        # Sort interfaces by name for each device
        for device in result.values():
            device['interfaces'].sort(key=lambda x: x['name'])

        logger.info(f"Retrieved interfaces for snapshot '{safe_name}': {len(result)} devices")

        return result
