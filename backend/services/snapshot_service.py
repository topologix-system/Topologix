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
from pathlib import Path
from typing import Any, Optional
from datetime import datetime
from werkzeug.utils import secure_filename

from config import config
from security.validation import validate_file_upload

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.cfg', '.conf', '.txt', '.log'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
PROTECTED_SNAPSHOTS = set()  # No protected snapshots - all can be deleted
METADATA_FILENAME = '.topologix-snapshot.json'
FOLDER_SEGMENT_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$')


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

    def _get_snapshot_directory(self, name: str) -> Path:
        """Resolve snapshot directory from public snapshot name."""
        safe_name = secure_filename(name)
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
            'path': str(snapshot_path),
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
        # Validate name
        if not name or not name.strip():
            raise ValueError("Snapshot name cannot be empty")

        # Secure the filename
        safe_name = secure_filename(name)
        if not safe_name:
            raise ValueError("Invalid snapshot name")

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
        safe_name = secure_filename(name)

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
        safe_name = secure_filename(name)
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

            stat = file_path.stat()
            files.append({
                'name': file_path.name,
                'size_bytes': stat.st_size,
                'modified_at': datetime.fromtimestamp(stat.st_mtime).isoformat()
            })

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
        safe_name = secure_filename(name)
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

        return {
            'name': filename,
            'size_bytes': file_size,
            'modified_at': datetime.now().isoformat()
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
        safe_name = secure_filename(name)
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
        safe_name = secure_filename(name)
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
        safe_name = secure_filename(name)
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
        safe_name = secure_filename(name)
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
