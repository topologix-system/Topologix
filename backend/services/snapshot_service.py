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

            # Count config files
            file_count = len(list(configs_dir.glob('*.cfg'))) + \
                        len(list(configs_dir.glob('*.conf'))) + \
                        len(list(configs_dir.glob('*.txt')))

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

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of directory in bytes"""
        total = 0
        for entry in path.rglob('*'):
            if entry.is_file():
                total += entry.stat().st_size
        return total

    def get_layer1_topology(self, name: str) -> dict[str, Any]:
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
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

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

    def save_layer1_topology(self, name: str, topology_data: dict[str, Any]) -> dict[str, Any]:
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
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

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

    def delete_layer1_topology(self, name: str) -> None:
        """
        Delete Layer1 topology configuration

        Args:
            name: Snapshot name

        Raises:
            FileNotFoundError: If snapshot or Layer1 file does not exist
        """
        safe_name = secure_filename(name)
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

        layer1_file = snapshot_path / 'batfish' / 'layer1_topology.json'

        if not layer1_file.exists():
            raise FileNotFoundError(f"Layer1 topology file not found for snapshot '{safe_name}'")

        layer1_file.unlink()
        logger.info(f"Deleted Layer1 topology for snapshot '{safe_name}'")

    def get_snapshot_interfaces(self, name: str, batfish_service) -> dict[str, Any]:
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
        snapshot_path = self.snapshots_dir / safe_name

        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot '{safe_name}' not found")

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