"""
Network configuration snapshot management service
- Create, list, delete, and manage configuration snapshots
- Upload configuration files (.cfg, .conf, .txt) to snapshots
- File size validation (10MB limit per file)
- Secure filename handling with werkzeug.secure_filename
- Calculate snapshot directory sizes
- List files within snapshots with metadata
"""
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