"""Isolated snapshot versioning services backed by a temporary database and directories."""
import test_00_environment  # noqa: F401
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import func, select

from database.models import HistoryObject, SnapshotState as SnapshotStateRow, SnapshotVersion, SnapshotVersionFile
from database.session import DatabaseManager
from services.snapshot_history_service import SnapshotHistoryService
from services.snapshot_service import METADATA_FILENAME, SnapshotService
from services.snapshot_state_service import SnapshotStateService

CONFIG_R1 = "hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
CONFIG_R2 = "hostname r2\ninterface Loopback0\n ip address 192.0.2.2 255.255.255.255\n"


def default_settings(data_dir: Path, **overrides) -> SimpleNamespace:
    settings = SimpleNamespace(
        DATA_DIR=str(data_dir),
        DATA_DIR_FELL_BACK=False,
        RESULT_CACHE_DIR=str(data_dir / 'result_cache'),
        SNAPSHOT_HISTORY_DIR=str(data_dir / 'snapshot_history'),
        DEPLOYMENT_ID='',
        RESULT_CACHE_ENABLED=False,
        EXTERNAL_CHANGE_SETTLE_SECONDS=0,
        HISTORY_GC_GRACE_SECONDS=600,
        HISTORY_ACCEPT_STORE_LOSS='',
        SNAPSHOT_DIFF_MAX_BYTES=512 * 1024,
        SNAPSHOT_DIFF_MAX_LINES=2000,
    )
    for name, value in overrides.items():
        setattr(settings, name, value)
    return settings


class VersioningSandbox:
    """State and history services over a private database, data directory and snapshot store."""

    def __init__(self, snapshot_service: SnapshotService | None = None, with_database: bool = True,
                 snapshots_dir: Path | None = None, **settings_overrides):
        self._temp = tempfile.TemporaryDirectory(prefix='topologix-versioning-')
        self.root = Path(self._temp.name)
        self.data_dir = self.root / 'data'
        self.data_dir.mkdir()
        self.snapshots_dir = snapshots_dir or self.root / 'snapshots'
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.settings = default_settings(self.data_dir, **settings_overrides)
        self.database_url = f"sqlite:///{self.root / 'versioning.db'}"
        self.db = None
        if with_database:
            self.db = DatabaseManager(self.database_url)
            self.db.create_all()
        self.snapshot_service = snapshot_service or SnapshotService()
        self._original_snapshots_dir = self.snapshot_service.snapshots_dir
        self._original_state_service = getattr(self.snapshot_service, '_state_service', None)
        self.snapshot_service.snapshots_dir = self.snapshots_dir
        self.start()

    def start(self, attach: bool = True) -> SnapshotStateService:
        self.state = SnapshotStateService(self.db, self.snapshot_service, settings=self.settings)
        self.history = SnapshotHistoryService(
            self.db, self.state, self.settings.SNAPSHOT_HISTORY_DIR, settings=self.settings,
        )
        if attach:
            self.snapshot_service.attach_state_service(self.state)
        self.history.run_startup_tasks()
        return self.state

    def cleanup(self) -> None:
        self.snapshot_service.snapshots_dir = self._original_snapshots_dir
        self.snapshot_service.attach_state_service(self._original_state_service)
        if self.db is not None:
            self.db.engine.dispose()
        for directory, _, _ in os.walk(self.root):
            try:
                os.chmod(directory, 0o755)
            except OSError:
                pass
        self._temp.cleanup()

    def create_snapshot(self, name: str, files: dict[str, str | bytes] | None = None) -> Path:
        self.snapshot_service.create_snapshot(name)
        path = self.snapshots_dir / name
        for relative_path, content in (files if files is not None else {'configs/r1.cfg': CONFIG_R1}).items():
            write_file(path / relative_path, content)
        return path

    def poll(self, name: str):
        return self.state.get_state(name, {'requester_user_id': None, 'auth_enabled': False})

    def snapshot_id(self, name: str) -> str:
        return self.state.read_sidecar_id(self.snapshots_dir / name)

    def versions(self, snapshot_id: str) -> list:
        return self.history.list_versions(snapshot_id, limit=200)['items']

    def row(self, snapshot_id: str, namespace: str | None = None):
        with self.db.get_db_session() as session:
            return session.execute(
                select(SnapshotStateRow).where(
                    SnapshotStateRow.namespace == (namespace or self.state.namespace),
                    SnapshotStateRow.snapshot_id == snapshot_id,
                )
            ).scalar_one_or_none()

    def count(self, model) -> int:
        with self.db.get_db_session() as session:
            return session.execute(select(func.count()).select_from(model)).scalar_one()

    def version_count(self) -> int:
        return self.count(SnapshotVersion)

    def object_count(self) -> int:
        return self.count(HistoryObject)

    def file_row_count(self) -> int:
        return self.count(SnapshotVersionFile)


def write_file(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding='utf-8')


def set_times(path: Path, seconds_ago: float = 3600, now_ns: int | None = None) -> None:
    import time
    base = now_ns if now_ns is not None else time.time_ns()
    value = int(base - seconds_ago * 1_000_000_000)
    os.utime(path, ns=(value, value), follow_symlinks=False)


def sidecar_path(snapshot_dir: Path) -> Path:
    return snapshot_dir / METADATA_FILENAME
