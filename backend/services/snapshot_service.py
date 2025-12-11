"""
Network configuration snapshot management service
- Create, list, delete, and manage configuration snapshots
- Upload configuration files (.cfg, .conf, .txt) to snapshots
- File size validation (10MB limit per file)
- Secure filename handling with werkzeug.secure_filename
- Calculate snapshot directory sizes
- List files within snapshots with metadata
"""
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any
from datetime import datetime
from werkzeug.utils import secure_filename

from config import config

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'.cfg', '.conf', '.txt'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
PROTECTED_SNAPSHOTS = set()  # No protected snapshots - all can be deleted


class SnapshotService:
    """Service for managing network configuration snapshots"""

    def __init__(self):
        """Initialize snapshot service"""
        self.snapshots_dir = Path(config.SNAPSHOTS_DIR)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def list_snapshots(self) -> list[dict[str, Any]]:
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

            # Count config files using generators to avoid loading full lists into memory
            file_count = sum(1 for _ in configs_dir.glob('*.cfg')) + \
                        sum(1 for _ in configs_dir.glob('*.conf')) + \
                        sum(1 for _ in configs_dir.glob('*.txt'))

            # Get creation time
            stat = snapshot_path.stat()
            created_at = datetime.fromtimestamp(stat.st_ctime).isoformat()

            snapshots.append({
                'name': snapshot_path.name,
                'path': str(snapshot_path),
                'file_count': file_count,
                'created_at': created_at,
                'size_bytes': self._get_directory_size(snapshot_path)
            })

        # Sort by creation time (newest first)
        snapshots.sort(key=lambda x: x['created_at'], reverse=True)

        return snapshots

    def create_snapshot(self, name: str) -> dict[str, Any]:
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

        snapshot_path = self.snapshots_dir / safe_name

        if snapshot_path.exists():
            raise ValueError(f"Snapshot '{safe_name}' already exists")

        # Create directory structure
        configs_dir = snapshot_path / 'configs'
        configs_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Created snapshot: {safe_name}")

        return {
            'name': safe_name,
            'path': str(snapshot_path),
            'file_count': 0,
            'created_at': datetime.now().isoformat(),
            'size_bytes': 0
        }

    def delete_snapshot(self, name: str) -> None:
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

        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        shutil.rmtree(snapshot_path)
        logger.info(f"Deleted snapshot: {safe_name}")

    def get_snapshot_files(self, name: str) -> list[dict[str, Any]]:
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
        snapshot_path = self.snapshots_dir / safe_name
        configs_dir = snapshot_path / 'configs'

        if not configs_dir.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        files = []
        for file_path in configs_dir.iterdir():
            if not file_path.is_file():
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

    def upload_file(self, name: str, file_storage: Any) -> dict[str, Any]:
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
        snapshot_path = self.snapshots_dir / safe_name
        configs_dir = snapshot_path / 'configs'

        if not configs_dir.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

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

        # Check file size
        file_storage.seek(0, os.SEEK_END)
        file_size = file_storage.tell()
        file_storage.seek(0)

        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large. Maximum size: {MAX_FILE_SIZE / 1024 / 1024}MB")

        # Save file
        file_path = configs_dir / filename
        file_storage.save(str(file_path))

        logger.info(f"Uploaded file '{filename}' to snapshot '{safe_name}'")

        return {
            'name': filename,
            'size_bytes': file_size,
            'modified_at': datetime.now().isoformat()
        }

    def get_snapshot_path(self, name: str) -> Path:
        """
        Get the full path to a snapshot directory

        Args:
            name: Snapshot name

        Returns:
            Path object

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        return snapshot_path

    def get_layer1_topology(self, name: str) -> dict[str, Any] | None:
        """
        Get Layer1 topology JSON for a snapshot

        Args:
            name: Snapshot name

        Returns:
            Layer1 topology data wrapped in 'edges' key for frontend compatibility
            Returns None if file doesn't exist

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        layer1_file = snapshot_path / 'layer1_topology.json'

        if not layer1_file.exists():
            return None

        with open(layer1_file, 'r') as f:
            data = json.load(f)
            # Batfish expects top-level array, but frontend expects {"edges": [...]}
            # If data is already wrapped, return as-is; otherwise wrap it
            if isinstance(data, dict) and 'edges' in data:
                return data
            elif isinstance(data, list):
                return {'edges': data}
            else:
                logger.warning(f"Unexpected Layer1 topology format in '{safe_name}'")
                return {'edges': []}

    def save_layer1_topology(self, name: str, topology_data: dict[str, Any]) -> dict[str, Any]:
        """
        Save Layer1 topology JSON to snapshot directory in Batfish-compatible format

        Batfish expects layer1_topology.json in batfish/ subdirectory with structure:
        {"edges": [{"node1": {...}, "node2": {...}}, ...]}

        Args:
            name: Snapshot name
            topology_data: Layer1 topology data with 'edges' key

        Returns:
            Save result metadata

        Raises:
            FileNotFoundError: If snapshot does not exist
            ValueError: If topology data is invalid
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        if 'edges' not in topology_data:
            raise ValueError("Invalid topology format: missing 'edges' key")

        batfish_dir = snapshot_path / 'batfish'
        batfish_dir.mkdir(exist_ok=True)

        layer1_file = batfish_dir / 'layer1_topology.json'
        edges = topology_data.get('edges', [])

        with open(layer1_file, 'w') as f:
            json.dump({'edges': edges}, f, indent=2)

        logger.info(f"Saved Layer1 topology for snapshot '{safe_name}' with {len(edges)} edges to batfish/layer1_topology.json")

        return {
            'snapshot_name': safe_name,
            'edge_count': len(edges),
            'file_size_bytes': layer1_file.stat().st_size
        }

    def delete_layer1_topology(self, name: str) -> None:
        """
        Delete Layer1 topology file from snapshot

        Args:
            name: Snapshot name

        Raises:
            FileNotFoundError: If snapshot or topology file does not exist
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        layer1_file = snapshot_path / 'layer1_topology.json'

        if not layer1_file.exists():
            raise FileNotFoundError(f"Layer1 topology file not found for snapshot '{safe_name}'")

        layer1_file.unlink()
        logger.info(f"Deleted Layer1 topology for snapshot '{safe_name}'")

    def get_snapshot_interfaces(self, name: str, batfish_service) -> dict[str, Any]:
        """
        Get all interfaces in a snapshot grouped by hostname

        Args:
            name: Snapshot name
            batfish_service: BatfishService instance

        Returns:
            Dictionary mapping hostname to list of interfaces

        Raises:
            FileNotFoundError: If snapshot does not exist
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        interfaces_data = batfish_service.get_interface_properties()

        devices = {}
        for interface in interfaces_data:
            hostname = interface.get('hostname', '')
            interface_name = interface.get('interface', '')
            active = interface.get('active', False)
            description = interface.get('description', '')

            if hostname not in devices:
                devices[hostname] = {
                    'hostname': hostname,
                    'interfaces': []
                }

            devices[hostname]['interfaces'].append({
                'name': interface_name,
                'active': active,
                'description': description
            })

        for device in devices.values():
            device['interfaces'].sort(key=lambda x: x['name'])

        return devices

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes"""
        total = 0
        for entry in path.rglob('*'):
            if entry.is_file():
                total += entry.stat().st_size
        return total