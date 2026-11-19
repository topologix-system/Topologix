"""Snapshot change detection, identity and writer bookkeeping"""
import errno
import hashlib
import itertools
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from sqlalchemy import select

from config import config
from database.models import HistoryMeta, SnapshotState as SnapshotStateRow
from database.models import SnapshotVersion, SnapshotVersionFile
from services.snapshot_service import METADATA_FILENAME, METADATA_SCHEMA_VERSION

logger = logging.getLogger(__name__)

history_lock = threading.RLock()

NAMESPACE_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
INVALID_NAMESPACE_DIRNAME = '_invalid-namespace'
RESERVED_NAMESPACES = frozenset({'result_cache', 'snapshot_history', INVALID_NAMESPACE_DIRNAME})
STORE_MARKER_FILENAME = '.topologix-store.json'
UNAVAILABLE_REASON_ORDER = ('storage', 'database', 'namespace', 'sidecar', 'missing_objects')
MAX_EVALUATION_ROUNDS = 3
FUTURE_TIMESTAMP_TOLERANCE_NS = 5 * 1_000_000_000
HASH_CHUNK_SIZE = 1024 * 1024
BASELINE_MESSAGE = 'Initial state'
EXTERNAL_MESSAGE = 'External change detected'
ACTIVE_SNAPSHOT_FILENAME = 'active_snapshot.json'
EDITOR_TEMP_SUFFIXES = ('~', '.swp', '.swo')
HARD_LINK_UNSUPPORTED_ERRNOS = frozenset(
    code for code in (
        errno.EPERM,
        getattr(errno, 'EOPNOTSUPP', None),
        getattr(errno, 'ENOTSUP', None),
        errno.ENOSYS,
    ) if code is not None
)
_CANONICAL_UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
_KEEP = object()


class VersioningUnavailableError(Exception):
    """Versioning is unavailable globally or for one snapshot"""

    def __init__(self, reason: str):
        super().__init__(f"Snapshot versioning is unavailable: {reason}")
        self.reason = reason


class IdentityResolutionError(Exception):
    """A snapshot's identity kept changing, its sidecar changed while resolving, or another directory shares its row"""


class SnapshotEvaluationError(Exception):
    """A snapshot could not be evaluated after authorization succeeded"""


class StagingVanishedError(Exception):
    """The snapshot changed twice while it was staged, or its staging directory disappeared"""


class TreeMovedError(Exception):
    """The consumable file set changed while it was being read"""


class StateStoreError(Exception):
    """A snapshot state row or history_meta that an evaluation, restore or cache clear needs is missing or unstorable"""


class NameMismatchError(Exception):
    """The state row belongs to another directory than the one evaluated"""


class _NamespaceMarkerError(Exception):
    """The deployment namespace marker cannot be created, read or parsed, or holds no namespace"""


def _gevent_threading_patched() -> bool:
    try:
        from gevent import monkey
    except ImportError:
        return False
    return monkey.is_module_patched('threading')


def run_blocking(fn: Callable, *args, **kwargs):
    """Run file-only work on the gevent hub threadpool when gevent is active, else inline."""
    if _gevent_threading_patched():
        import gevent
        return gevent.get_hub().threadpool.apply(fn, args, kwargs)
    return fn(*args, **kwargs)


def is_canonical_uuid4(value: Any) -> bool:
    return isinstance(value, str) and _CANONICAL_UUID4.fullmatch(value) is not None


def paths_overlap(first: Path, second: Path) -> bool:
    """Return whether two resolved paths are equal or one contains the other."""
    return first == second or first in second.parents or second in first.parents


def make_private_dirs(path: Path | str) -> None:
    """Create a directory and every missing parent with mode 0700."""
    missing = []
    current = Path(path)
    while not current.exists() and current.parent != current:
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass


def assert_under_root(path: Path | str, root: Path | str) -> Path:
    """Return the resolved path, refusing any path that does not resolve strictly below root."""
    resolved_root = Path(root).resolve(strict=False)
    resolved = Path(path).resolve(strict=False)
    if resolved_root not in resolved.parents:
        raise ValueError(f"Path {path} escapes its root {root}")
    return resolved


def _utf8_sort_key(path: str) -> bytes:
    return path.encode('utf-8')


def canonical_manifest_text(entries) -> bytes:
    """Return the canonical manifest text for (path, sha256, size) entries."""
    files = [[path, sha256, size] for path, sha256, size in sorted(entries, key=lambda item: _utf8_sort_key(item[0]))]
    return json.dumps({'v': 1, 'files': files}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def content_hash(entries) -> str:
    return hashlib.sha256(canonical_manifest_text(entries)).hexdigest()


@dataclass(frozen=True)
class Manifest:
    """Consumable file set as sorted (path, sha256, size) entries"""
    files: tuple

    @classmethod
    def from_entries(cls, entries) -> 'Manifest':
        return cls(tuple(sorted(
            ((path, sha256, int(size)) for path, sha256, size in entries),
            key=lambda item: _utf8_sort_key(item[0]),
        )))

    @property
    def text(self) -> bytes:
        return canonical_manifest_text(self.files)

    @property
    def content_hash(self) -> str:
        return content_hash(self.files)

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(size for _, _, size in self.files)


@dataclass
class TreeScan:
    """Stat walk of the consumable file set"""
    fingerprint: str
    files: list
    timestamps: list


@dataclass
class SnapshotState:
    """Evaluated working-tree state of one snapshot"""
    snapshot_id: str
    snapshot_name: str
    content_hash: Optional[str]
    head: Optional[dict]
    head_content_hash: Optional[str]
    pending_external: bool
    external_settling: bool
    restored_from: Optional[dict]
    clear_seq: Optional[int]
    has_row: bool

    @property
    def uncommitted(self) -> bool:
        if self.content_hash is None:
            return False
        return self.head is None or self.content_hash != self.head_content_hash


@dataclass
class WriteScope:
    """Writer protocol bookkeeping for one mutating service call"""
    key: tuple
    snapshot_dir: Path


@dataclass
class UnrecordedWrite:
    """In-memory marker of an API write whose state could not be stored"""
    restored_from: Optional[dict]


@dataclass
class DecisionAction:
    """Outcome of the decision rules for one evaluation"""
    kind: str
    pending: Optional[bool] = None
    restored_from: Any = _KEEP

    @property
    def creates_version(self) -> bool:
        return self.kind in ('baseline', 'external')


@dataclass
class _RowValues:
    snapshot_name: str
    stat_fingerprint: Optional[str]
    content_hash: Optional[str]
    head_content_hash: Optional[str]
    pending_external: bool


class _InflightPoll:
    def __init__(self):
        self.event = threading.Event()
        self.result: Optional[SnapshotState] = None


def version_ref(version_id: Optional[str], seq: Optional[int]) -> Optional[dict]:
    if seq is None:
        return None
    return {'version_id': version_id, 'seq': seq}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_excluded_name(name: str) -> bool:
    if name.startswith('.'):
        return True
    if name.endswith(EDITOR_TEMP_SUFFIXES):
        return True
    return len(name) >= 2 and name.startswith('#') and name.endswith('#')


def _is_utf8_name(name: str) -> bool:
    try:
        os.fsencode(name).decode('utf-8')
    except UnicodeDecodeError:
        return False
    return True


def _open_below_root(path: Path, parts: list) -> int:
    """Open path = <root>/<parts...> through directory fds, following no symlink at any component below root."""
    root = Path(path)
    for _ in parts:
        root = root.parent
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def open_regular_file(path: Path, relative_path: Optional[str] = None) -> int:
    """Open a consumable file without following symlinks or blocking on special files.

    With relative_path (path below the snapshot root), no directory component below the root is followed either.
    """
    try:
        if relative_path is None:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        else:
            fd = _open_below_root(Path(path), relative_path.split('/'))
    except FileNotFoundError as exc:
        raise TreeMovedError(str(path)) from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENXIO):
            raise TreeMovedError(str(path)) from exc
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise TreeMovedError(str(path))
    return fd


def hash_files(files) -> Manifest:
    """Hash scanned files into a manifest (file-only work for run_blocking)."""
    entries = []
    for relative_path, absolute_path, _ in files:
        fd = open_regular_file(absolute_path, relative_path)
        hasher = hashlib.sha256()
        size = 0
        with os.fdopen(fd, 'rb') as source:
            while True:
                chunk = source.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
        entries.append((relative_path, hasher.hexdigest(), size))
    return Manifest.from_entries(entries)


def tree_contains_symlink(snapshot_dir: Path | str) -> bool:
    """Return whether an entry below snapshot_dir is a symlink, by an unpruned lstat walk that skips unlistable dirs."""
    for directory, dirnames, filenames in os.walk(snapshot_dir, followlinks=False):
        for name in itertools.chain(dirnames, filenames):
            try:
                if stat.S_ISLNK(os.lstat(os.path.join(directory, name)).st_mode):
                    return True
            except FileNotFoundError:
                continue
    return False


def _staging_parent(destination: Path, parts: list) -> Path:
    """Create the directories of a staged file below destination; raise when destination itself disappeared."""
    vanished = StagingVanishedError(f"Staging directory of snapshot {destination.name} disappeared")
    try:
        if not stat.S_ISDIR(os.lstat(destination).st_mode):
            raise vanished
    except FileNotFoundError as exc:
        raise vanished from exc
    current = destination
    for part in parts:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except FileNotFoundError as exc:
            raise vanished from exc
    return current


def copy_files(files, destination: Path) -> Manifest:
    """Copy scanned files below destination while hashing them (file-only work for run_blocking)."""
    entries = []
    for relative_path, absolute_path, _ in files:
        parts = relative_path.split('/')
        target = _staging_parent(destination, parts[:-1]) / parts[-1]
        fd = open_regular_file(absolute_path, relative_path)
        hasher = hashlib.sha256()
        size = 0
        with os.fdopen(fd, 'rb') as source:
            try:
                target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            except FileNotFoundError as exc:
                raise StagingVanishedError(f"Staging directory of snapshot {destination.name} disappeared") from exc
            os.fchmod(target_fd, 0o600)
            with os.fdopen(target_fd, 'wb') as copy:
                while True:
                    chunk = source.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    copy.write(chunk)
                    size += len(chunk)
        entries.append((relative_path, hasher.hexdigest(), size))
    _staging_parent(destination, [])
    return Manifest.from_entries(entries)


class SnapshotStateService:
    """Change detection and identity for snapshot directories"""

    def __init__(self, db_manager, snapshot_service, settings=None, clock_ns: Callable[[], int] = time.time_ns):
        self._db = db_manager
        self._snapshot_service = snapshot_service
        self.settings = settings if settings is not None else config
        self._clock_ns = clock_ns
        self._history = None
        self._registry_lock = threading.Lock()
        self._global_reasons: set[str] = set()
        self._marks: dict[tuple, str] = {}
        self._in_progress: dict[tuple, int] = {}
        self._markers: dict[tuple, UnrecordedWrite] = {}
        self._evaluation_locks: dict[tuple, threading.Lock] = {}
        self._inflight_polls: dict[tuple, _InflightPoll] = {}
        self._warned: set[tuple] = set()
        self._system_temp_staging_root: Optional[Path] = None
        self._reparse_requested: dict[tuple, Optional[int]] = {}
        self._active_snapshot_loaded = False

        self.data_dir = Path(self.settings.DATA_DIR)
        self.snapshots_root = Path(snapshot_service.snapshots_dir)
        self.result_cache_dir = Path(self.settings.RESULT_CACHE_DIR)
        self.history_dir = Path(self.settings.SNAPSHOT_HISTORY_DIR)
        self.invalid_namespace_root = self.data_dir / INVALID_NAMESPACE_DIRNAME
        self.data_dir_fell_back = bool(getattr(self.settings, 'DATA_DIR_FELL_BACK', False))
        self.marker_created = False
        self.storage_overlap = False
        self.data_dir_in_store = False
        self.invalid_namespace_root_overlaps = False
        self.result_cache_forced_off = self.data_dir_fell_back

        if db_manager is None:
            self._global_reasons.add('database')
        if self.data_dir_fell_back:
            self._global_reasons.add('storage')
        self._check_storage_overlap()
        self.namespace, self.namespace_valid = self._resolve_namespace()

    def attach_history_service(self, history_service) -> None:
        self._history = history_service

    @property
    def history(self):
        return self._history

    @property
    def db_manager(self):
        return self._db

    @property
    def result_cache_enabled(self) -> bool:
        return bool(self.settings.RESULT_CACHE_ENABLED) and not self.result_cache_forced_off

    def id_key(self, snapshot_id: str) -> tuple:
        return ('id', self.namespace, snapshot_id)

    def name_key(self, snapshot_name: str) -> tuple:
        return ('name', self.namespace, snapshot_name)

    def dir_key(self, snapshot_dir: Path | str) -> tuple:
        return ('dir', self.namespace, str(Path(snapshot_dir).absolute()))

    def mark_globally_unavailable(self, reason: str) -> None:
        with self._registry_lock:
            self._global_reasons.add(reason)

    def global_unavailable_reason(self) -> Optional[str]:
        with self._registry_lock:
            reasons = set(self._global_reasons)
        return next((reason for reason in UNAVAILABLE_REASON_ORDER if reason in reasons), None)

    def mark_versioning_unavailable(self, key: tuple, reason: str) -> bool:
        """Mark one snapshot unavailable; return whether the mark is new."""
        with self._registry_lock:
            previous = self._marks.get(key)
            self._marks[key] = reason
        return previous != reason

    def clear_versioning_unavailable(self, key: tuple) -> None:
        with self._registry_lock:
            self._marks.pop(key, None)

    def drop_name_marks(self, snapshot_name: str) -> None:
        self.clear_versioning_unavailable(self.name_key(snapshot_name))

    def marked_snapshot_count(self, reason: str) -> int:
        with self._registry_lock:
            return sum(1 for value in self._marks.values() if value == reason)

    def unavailable_reason(self, snapshot_id: Optional[str] = None, snapshot_name: Optional[str] = None) -> Optional[str]:
        with self._registry_lock:
            reasons = set(self._global_reasons)
            if snapshot_name is not None and self.name_key(snapshot_name) in self._marks:
                reasons.add(self._marks[self.name_key(snapshot_name)])
            if snapshot_id is not None and self.id_key(snapshot_id) in self._marks:
                reasons.add(self._marks[self.id_key(snapshot_id)])
        return next((reason for reason in UNAVAILABLE_REASON_ORDER if reason in reasons), None)

    def _warn_once(self, key: tuple, message: str, *args) -> None:
        with self._registry_lock:
            if key in self._warned:
                return
            self._warned.add(key)
        logger.warning(message, *args)

    def _check_storage_overlap(self) -> None:
        directories = {
            'SNAPSHOTS_DIR': self.snapshots_root.resolve(strict=False),
            'RESULT_CACHE_DIR': self.result_cache_dir.resolve(strict=False),
            'SNAPSHOT_HISTORY_DIR': self.history_dir.resolve(strict=False),
            INVALID_NAMESPACE_DIRNAME: self.invalid_namespace_root.resolve(strict=False),
        }
        violations = []
        for (first_label, first), (second_label, second) in itertools.combinations(directories.items(), 2):
            if paths_overlap(first, second):
                violations.append(f"{first_label} and {second_label}")
                if INVALID_NAMESPACE_DIRNAME in (first_label, second_label):
                    self.invalid_namespace_root_overlaps = True

        store = directories['SNAPSHOTS_DIR']
        data_dir = self.data_dir.resolve(strict=False)
        if data_dir == store or store in data_dir.parents:
            violations.append("DATA_DIR inside SNAPSHOTS_DIR")
            self.data_dir_in_store = True

        if violations:
            logger.error(
                "Storage directories overlap (%s); snapshot versioning is unavailable and the result cache is "
                "disabled. Configure SNAPSHOTS_DIR, DATA_DIR, RESULT_CACHE_DIR and SNAPSHOT_HISTORY_DIR as "
                "separate directories.",
                '; '.join(violations),
            )
            self.storage_overlap = True
            self.result_cache_forced_off = True
            self._global_reasons.add('storage')
            try:
                self.settings.RESULT_CACHE_ENABLED = False
            except AttributeError:
                pass

    def namespace_problem(self, namespace: str) -> Optional[str]:
        """Return why a namespace is invalid for this deployment, or None when it is valid."""
        if not isinstance(namespace, str) or not NAMESPACE_PATTERN.fullmatch(namespace):
            return "it does not match ^[A-Za-z0-9_-]{1,64}$"
        if namespace in RESERVED_NAMESPACES:
            return "it is a reserved name"
        namespace_dir = (self.data_dir / namespace).resolve(strict=False)
        for label, directory in (
            ('SNAPSHOTS_DIR', self.snapshots_root),
            ('RESULT_CACHE_DIR', self.result_cache_dir),
            ('SNAPSHOT_HISTORY_DIR', self.history_dir),
            (INVALID_NAMESPACE_DIRNAME, self.invalid_namespace_root),
        ):
            if paths_overlap(namespace_dir, directory.resolve(strict=False)):
                return f"its directory overlaps {label}"
        return None

    def _resolve_namespace(self) -> tuple[str, bool]:
        deployment_id = (getattr(self.settings, 'DEPLOYMENT_ID', '') or '').strip()
        if deployment_id:
            candidate, source = deployment_id, 'DEPLOYMENT_ID'
        else:
            source = f"store marker {self.snapshots_root / STORE_MARKER_FILENAME}"
            try:
                candidate = self._read_or_create_store_marker()
            except _NamespaceMarkerError as exc:
                logger.error(
                    "Deployment namespace is unavailable: %s; snapshot versioning is unavailable", exc,
                )
                self._global_reasons.add('namespace')
                return INVALID_NAMESPACE_DIRNAME, False

        problem = self.namespace_problem(candidate)
        if problem:
            logger.error(
                "Deployment namespace from %s is invalid because %s; snapshot versioning is unavailable",
                source,
                problem,
            )
            self._global_reasons.add('namespace')
            return INVALID_NAMESPACE_DIRNAME, False
        return candidate, True

    def _read_store_marker(self, marker_path: Path) -> str:
        try:
            with open(marker_path, 'r', encoding='utf-8') as marker_file:
                payload = json.load(marker_file)
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as exc:
            raise _NamespaceMarkerError(f"{marker_path} cannot be read or parsed ({type(exc).__name__})") from exc
        namespace = payload.get('namespace') if isinstance(payload, dict) else None
        if not isinstance(namespace, str):
            raise _NamespaceMarkerError(f"{marker_path} does not contain a namespace")
        return namespace

    def _read_or_create_store_marker(self) -> str:
        marker_path = self.snapshots_root / STORE_MARKER_FILENAME
        try:
            return self._read_store_marker(marker_path)
        except FileNotFoundError:
            pass

        temp_path = self.snapshots_root / f"{STORE_MARKER_FILENAME}.{uuid.uuid4().hex}.tmp"
        payload = json.dumps({'namespace': str(uuid.uuid4())}).encode('utf-8')
        created = False
        try:
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temp_path, marker_path)
                created = True
            except FileExistsError:
                created = False
            except OSError as exc:
                if exc.errno in HARD_LINK_UNSUPPORTED_ERRNOS:
                    raise _NamespaceMarkerError(
                        f"the snapshot store filesystem does not support hard links "
                        f"({errno.errorcode.get(exc.errno, exc.errno)}) needed to publish {marker_path}; "
                        f"set DEPLOYMENT_ID to choose the namespace explicitly"
                    ) from exc
                raise
        except _NamespaceMarkerError:
            raise
        except OSError as exc:
            raise _NamespaceMarkerError(
                f"{marker_path} cannot be created ({errno.errorcode.get(exc.errno, exc.errno)})"
            ) from exc
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        if created:
            self.marker_created = True
            try:
                self._fsync_directory(self.snapshots_root)
            except OSError:
                pass
        try:
            return self._read_store_marker(marker_path)
        except FileNotFoundError as exc:
            raise _NamespaceMarkerError(f"{marker_path} disappeared after creation") from exc

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def scan_tree(self, snapshot_dir: Path | str) -> TreeScan:
        """Stat-walk the consumable file set."""
        snapshot_dir = Path(snapshot_dir)
        root_stat = os.lstat(snapshot_dir)
        if stat.S_ISLNK(root_stat.st_mode):
            root_stat = os.stat(snapshot_dir)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir.name}")

        snapshot_name = snapshot_dir.name
        records = []
        files = []
        timestamps = []
        pending = [('', snapshot_dir, root_stat)]
        while pending:
            relative_dir, directory, directory_stat = pending.pop()
            records.append(('d', relative_dir, directory_stat.st_mtime_ns, directory_stat.st_ctime_ns))
            timestamps.extend((directory_stat.st_mtime_ns, directory_stat.st_ctime_ns))
            try:
                iterator = os.scandir(directory)
            except (FileNotFoundError, NotADirectoryError) as exc:
                if not relative_dir:
                    raise FileNotFoundError(f"Snapshot directory not found: {snapshot_name}") from exc
                raise TreeMovedError(relative_dir) from exc
            with iterator:
                for entry in iterator:
                    name = entry.name
                    if _is_excluded_name(name):
                        continue
                    if not _is_utf8_name(name):
                        self._warn_once(
                            ('non_utf8', snapshot_name),
                            "Snapshot %s contains a path that is not valid UTF-8; it is excluded from versioning "
                            "and from the staged Batfish copy",
                            snapshot_name,
                        )
                        continue
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except FileNotFoundError as exc:
                        raise TreeMovedError(name) from exc
                    relative_path = f"{relative_dir}/{name}" if relative_dir else name
                    if stat.S_ISLNK(entry_stat.st_mode):
                        self._warn_once(
                            ('symlink', snapshot_name),
                            "Snapshot %s contains symlinks; they are excluded from versioning and Batfish uploads",
                            snapshot_name,
                        )
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        pending.append((relative_path, Path(entry.path), entry_stat))
                    elif stat.S_ISREG(entry_stat.st_mode):
                        files.append((relative_path, Path(entry.path), entry_stat.st_size))
                        records.append((
                            'f', relative_path, entry_stat.st_size, entry_stat.st_mtime_ns,
                            entry_stat.st_ctime_ns, entry_stat.st_ino,
                        ))
                        timestamps.extend((entry_stat.st_mtime_ns, entry_stat.st_ctime_ns))

        records.sort(key=lambda record: (_utf8_sort_key(record[1]), record[0]))
        files.sort(key=lambda item: _utf8_sort_key(item[0]))
        fingerprint = hashlib.sha256(
            json.dumps(records, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        ).hexdigest()
        return TreeScan(fingerprint=fingerprint, files=files, timestamps=timestamps)

    def scan_tree_or_none(self, snapshot_dir: Path | str) -> Optional[TreeScan]:
        try:
            return self.scan_tree(snapshot_dir)
        except TreeMovedError:
            return None

    def iter_consumable_files(self, snapshot_dir: Path | str) -> Iterator[tuple[str, Path]]:
        """Yield (relative POSIX path, absolute path) for every consumable file."""
        for relative_path, absolute_path, _ in self.scan_tree(snapshot_dir).files:
            yield relative_path, absolute_path

    def compute_stat_fingerprint(self, snapshot_dir: Path | str) -> str:
        return self.scan_tree(snapshot_dir).fingerprint

    def compute_manifest(self, snapshot_dir: Path | str) -> Manifest:
        for _ in range(MAX_EVALUATION_ROUNDS):
            scan = self.scan_tree_or_none(snapshot_dir)
            if scan is None:
                continue
            try:
                return run_blocking(hash_files, scan.files)
            except TreeMovedError:
                continue
        raise TreeMovedError(Path(snapshot_dir).name)

    def _settle_window_open(self, scan: TreeScan, snapshot_name: str) -> bool:
        now = self._clock_ns()
        limit = now + FUTURE_TIMESTAMP_TOLERANCE_NS
        valid = [value for value in scan.timestamps if value <= limit]
        if len(valid) != len(scan.timestamps):
            self._warn_once(
                ('future_timestamp', snapshot_name),
                "Snapshot %s contains file or directory timestamps in the future; they are ignored for the "
                "external change settle window",
                snapshot_name,
            )
        if not valid:
            return False
        settle_ns = float(self.settings.EXTERNAL_CHANGE_SETTLE_SECONDS) * 1_000_000_000
        return (now - max(valid)) < settle_ns

    def _read_sidecar(self, snapshot_dir: Path) -> tuple[Optional[dict], Any]:
        metadata_path = snapshot_dir / METADATA_FILENAME
        try:
            with open(metadata_path, 'r', encoding='utf-8') as metadata_file:
                metadata = json.load(metadata_file)
        except FileNotFoundError:
            return None, None
        if not isinstance(metadata, dict):
            raise ValueError(f"Snapshot metadata of {snapshot_dir.name} must be a JSON object")
        return metadata, metadata.get('snapshot_id')

    def read_sidecar_id(self, snapshot_dir: Path | str) -> Optional[str]:
        """Return the canonical sidecar snapshot_id without locking, or None."""
        try:
            _, value = self._read_sidecar(Path(snapshot_dir))
        except (OSError, ValueError):
            return None
        return value if is_canonical_uuid4(value) else None

    def _set_sidecar_mark(self, snapshot_name: str, error: Exception) -> None:
        if self.mark_versioning_unavailable(self.name_key(snapshot_name), 'sidecar'):
            logger.warning(
                "Snapshot %s cannot store its snapshot_id in the metadata sidecar (%s); snapshot versioning is "
                "unavailable for it until the directory is writable",
                snapshot_name,
                type(error).__name__,
            )

    def _clear_sidecar_mark(self, snapshot_name: str) -> None:
        key = self.name_key(snapshot_name)
        with self._registry_lock:
            if self._marks.get(key) == 'sidecar':
                del self._marks[key]

    def _write_sidecar(self, snapshot_dir: Path, metadata: dict) -> None:
        try:
            self._snapshot_service._write_metadata(snapshot_dir, metadata)
        except OSError as exc:
            self._set_sidecar_mark(snapshot_dir.name, exc)
            raise VersioningUnavailableError('sidecar') from exc

    @contextmanager
    def _sidecar_file_lock(self, snapshot_dir: Path):
        try:
            lock_context = self._snapshot_service._snapshot_metadata_file_lock(snapshot_dir)
            lock_context.__enter__()
        except OSError as exc:
            self._set_sidecar_mark(snapshot_dir.name, exc)
            raise VersioningUnavailableError('sidecar') from exc
        try:
            yield
        finally:
            lock_context.__exit__(None, None, None)

    def ensure_snapshot_id(self, snapshot_dir: Path | str) -> str:
        """Read the sidecar snapshot_id, or assign one under both metadata locks preserving every other field."""
        snapshot_dir = Path(snapshot_dir)
        snapshot_service = self._snapshot_service
        with snapshot_service._metadata_lock:
            _, current = self._read_sidecar(snapshot_dir)
            if is_canonical_uuid4(current):
                return current

            with self._sidecar_file_lock(snapshot_dir):
                metadata, current = self._read_sidecar(snapshot_dir)
                if is_canonical_uuid4(current):
                    self._clear_sidecar_mark(snapshot_dir.name)
                    return current

                new_id = str(uuid.uuid4())
                if metadata is None:
                    legacy = snapshot_service._load_metadata(snapshot_dir)
                    metadata = snapshot_service._build_metadata(
                        snapshot_name=snapshot_dir.name,
                        folder_name=None,
                        owner_user_id=None,
                        owner_username=None,
                        access_scope='legacy',
                        created_at=legacy.get('created_at'),
                        snapshot_id=new_id,
                        legacy_unowned=True,
                    )
                else:
                    metadata = dict(metadata)
                    metadata['snapshot_id'] = new_id
                    metadata['schema_version'] = METADATA_SCHEMA_VERSION
                self._write_sidecar(snapshot_dir, metadata)

        if current is not None:
            logger.warning(
                "Snapshot %s had a non-canonical snapshot_id in its metadata sidecar; assigned a new one",
                snapshot_dir.name,
            )
        self._clear_sidecar_mark(snapshot_dir.name)
        return new_id

    def _compare_and_set_fresh_id(self, snapshot_dir: Path, expected_id: str) -> tuple[str, bool]:
        """Give a copied directory a fresh id; return (id, adopted) where adopted means another resolver won."""
        snapshot_service = self._snapshot_service
        with snapshot_service._metadata_lock:
            with self._sidecar_file_lock(snapshot_dir):
                metadata, current = self._read_sidecar(snapshot_dir)
                if current != expected_id:
                    if is_canonical_uuid4(current):
                        return current, True
                    raise IdentityResolutionError(
                        f"Snapshot {snapshot_dir.name} changed its metadata sidecar during identity resolution"
                    )
                new_id = str(uuid.uuid4())
                metadata = dict(metadata or {})
                metadata['snapshot_id'] = new_id
                metadata['schema_version'] = METADATA_SCHEMA_VERSION
                self._write_sidecar(snapshot_dir, metadata)
        logger.info("Assigned a fresh snapshot_id to snapshot %s, a copy of another snapshot", snapshot_dir.name)
        return new_id, False

    def check_sidecar_identity(self, snapshot_dir: Path, snapshot_id: str) -> None:
        """Raise FileNotFoundError when the directory no longer carries snapshot_id in its sidecar."""
        try:
            _, current = self._read_sidecar(snapshot_dir)
        except (OSError, ValueError) as exc:
            raise FileNotFoundError(f"Snapshot {snapshot_dir.name} no longer carries its snapshot_id") from exc
        if current != snapshot_id:
            raise FileNotFoundError(f"Snapshot {snapshot_dir.name} no longer carries its snapshot_id")

    def _directory_holds_id(self, directory: Path, snapshot_id: str) -> bool:
        try:
            directory_stat = os.lstat(directory)
        except FileNotFoundError:
            return False
        if not stat.S_ISDIR(directory_stat.st_mode):
            return False
        try:
            _, current = self._read_sidecar(directory)
        except (OSError, ValueError):
            logger.warning(
                "Metadata sidecar of snapshot %s cannot be read or parsed; it is treated as still holding its "
                "snapshot_id",
                directory.name,
            )
            return True
        return current == snapshot_id

    def _stored_name_directory(self, stored_name: str) -> Optional[Path]:
        try:
            safe_name = self._snapshot_service._validate_snapshot_name(stored_name)
        except ValueError:
            return None
        return Path(self._snapshot_service.snapshots_dir) / safe_name

    def _resolve_rows(self, snapshot_id: str, snapshot_dir: Path) -> str:
        """Run the DB part of identity resolution; return 'done', 'restart' or 'copy'."""
        with history_lock:
            with self._db.get_db_session() as session:
                stored_name = session.execute(
                    select(SnapshotStateRow.snapshot_name).where(
                        SnapshotStateRow.namespace == self.namespace,
                        SnapshotStateRow.snapshot_id == snapshot_id,
                    )
                ).scalar_one_or_none()
        if stored_name is None or stored_name == snapshot_dir.name:
            return 'done'

        stored_dir = self._stored_name_directory(stored_name)
        same_id = stored_dir is not None and self._directory_holds_id(stored_dir, snapshot_id)

        renamed = False
        with history_lock:
            with self._db.get_db_session() as session:
                row = session.execute(
                    select(SnapshotStateRow).where(
                        SnapshotStateRow.namespace == self.namespace,
                        SnapshotStateRow.snapshot_id == snapshot_id,
                    )
                ).scalar_one_or_none()
                if row is None or row.snapshot_name != stored_name:
                    outcome = 'restart'
                elif same_id:
                    outcome = 'copy'
                else:
                    row.snapshot_name = snapshot_dir.name
                    row.updated_at = _utcnow()
                    renamed = True
                    outcome = 'done'
        if renamed:
            logger.info(
                "Snapshot %s was moved outside the API from %s; its history follows the new name",
                snapshot_dir.name,
                stored_name,
            )
        return outcome

    def resolve_snapshot_identity(self, snapshot_dir: Path | str) -> str:
        """Return the snapshot_id of a directory, detecting out-of-band moves and copies."""
        snapshot_dir = Path(snapshot_dir)
        snapshot_id = self.ensure_snapshot_id(snapshot_dir)
        if self._db is None:
            raise VersioningUnavailableError('database')
        restarts = 0
        while True:
            outcome = self._resolve_rows(snapshot_id, snapshot_dir)
            if outcome == 'done':
                self._clear_sidecar_mark(snapshot_dir.name)
                self._rekey_marker(self.dir_key(snapshot_dir), self.id_key(snapshot_id))
                return snapshot_id
            if outcome == 'restart':
                restarts += 1
                if restarts > 1:
                    raise IdentityResolutionError(f"Identity of snapshot {snapshot_dir.name} kept changing")
                continue
            snapshot_id, adopted = self._compare_and_set_fresh_id(snapshot_dir, snapshot_id)
            if adopted:
                restarts += 1
                if restarts > 1:
                    raise IdentityResolutionError(f"Identity of snapshot {snapshot_dir.name} kept changing")

    def resolve_available_snapshot(self, snapshot_dir: Path | str, allowed_reason: Optional[str] = None) -> str:
        """Resolve the snapshot_id and raise VersioningUnavailableError for any unavailability except allowed_reason."""
        snapshot_dir = Path(snapshot_dir)
        reason = self.global_unavailable_reason()
        if reason:
            raise VersioningUnavailableError(reason)
        snapshot_id = self.resolve_snapshot_identity(snapshot_dir)
        reason = self.unavailable_reason(snapshot_id, snapshot_dir.name)
        if reason and reason != allowed_reason:
            raise VersioningUnavailableError(reason)
        return snapshot_id

    def begin_api_write(self, key: tuple) -> None:
        with self._registry_lock:
            self._in_progress[key] = self._in_progress.get(key, 0) + 1

    def _finish_api_write(self, key: tuple) -> None:
        with self._registry_lock:
            count = self._in_progress.get(key, 0) - 1
            if count > 0:
                self._in_progress[key] = count
            else:
                self._in_progress.pop(key, None)

    def write_in_progress(self, *keys: tuple) -> bool:
        with self._registry_lock:
            return any(self._in_progress.get(key) for key in keys)

    def get_marker(self, key: tuple) -> Optional[UnrecordedWrite]:
        with self._registry_lock:
            return self._markers.get(key)

    def set_marker(self, key: tuple, restored_from: Optional[dict] = None) -> None:
        with self._registry_lock:
            existing = self._markers.get(key)
            if restored_from is None and existing is not None:
                restored_from = existing.restored_from
            self._markers[key] = UnrecordedWrite(restored_from=restored_from)

    def drop_marker(self, key: tuple) -> None:
        with self._registry_lock:
            self._markers.pop(key, None)

    def _rekey_marker(self, source: tuple, target: tuple) -> None:
        with self._registry_lock:
            marker = self._markers.pop(source, None)
            if marker is None:
                return
            existing = self._markers.get(target)
            if marker.restored_from is None and existing is not None:
                marker = existing
            self._markers[target] = marker

    def settle_external_changes(self, snapshot_id: str, snapshot_dir: Path | str) -> str:
        """Force-settle external changes before an API write; return the snapshot_id to use."""
        snapshot_id, _ = self._evaluate(snapshot_id, Path(snapshot_dir), 'settle')
        return snapshot_id

    def begin_restore_write(self, key: tuple, snapshot_dir: Path | str, version_id: str,
                            expected_working_hash: Optional[str]) -> tuple[Manifest, list, dict, bool]:
        """Check a restore against the settled state and set its in-progress flag.

        Returns (manifest, consumable_paths, version_ref, noop); noop means the working tree already holds the
        version, so no flag is set and restored_from is recorded only when the version is not the head's content.
        """
        from services.snapshot_history_service import VersionConflictError, VersionNotFoundError

        snapshot_dir = Path(snapshot_dir)
        snapshot_id = key[2]
        self.check_sidecar_identity(snapshot_dir, snapshot_id)
        with history_lock:
            rescan = self.scan_tree_or_none(snapshot_dir)
            busy = self.write_in_progress(key, self.dir_key(snapshot_dir))
            with self._db.get_db_session() as session:
                outcome = self._restore_hold(
                    session, snapshot_id, snapshot_dir, version_id, expected_working_hash, rescan, busy,
                )
            if outcome[0] == 'write':
                self.begin_api_write(key)
        tag = outcome[0]
        if tag == 'mismatch':
            raise NameMismatchError(snapshot_dir.name)
        if tag == 'not_found':
            raise VersionNotFoundError("Version not found for this snapshot")
        if tag == 'no_row':
            raise StateStoreError(f"Snapshot {snapshot_dir.name} has no stored state")
        if tag == 'busy':
            raise VersionConflictError("An API write is in progress for this snapshot")
        if tag == 'hash_conflict':
            raise VersionConflictError("The working tree changed since its files were listed")
        if tag == 'moved':
            raise VersionConflictError("The working tree changed while the restore was prepared")
        _, manifest, consumable_paths, ref = outcome
        return manifest, consumable_paths, ref, tag == 'noop'

    def _restore_hold(self, session, snapshot_id: str, snapshot_dir: Path, version_id: str,
                      expected_working_hash: Optional[str], rescan: Optional[TreeScan], busy: bool) -> tuple:
        row = session.execute(
            select(SnapshotStateRow).where(
                SnapshotStateRow.namespace == self.namespace,
                SnapshotStateRow.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if row is not None and row.snapshot_name != snapshot_dir.name:
            return ('mismatch',)
        version = session.execute(
            select(SnapshotVersion).where(
                SnapshotVersion.version_id == version_id,
                SnapshotVersion.namespace == self.namespace,
                SnapshotVersion.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if version is None:
            return ('not_found',)
        if row is None:
            return ('no_row',)
        if busy:
            return ('busy',)
        if expected_working_hash is not None and expected_working_hash != row.content_hash:
            return ('hash_conflict',)
        if rescan is None or rescan.fingerprint != row.stat_fingerprint:
            return ('moved',)

        ref = version_ref(version.version_id, version.seq)
        manifest = Manifest.from_entries(session.execute(
            select(SnapshotVersionFile.path, SnapshotVersionFile.sha256, SnapshotVersionFile.size)
            .where(SnapshotVersionFile.version_id == version.version_id)
        ).all())
        consumable_paths = [relative_path for relative_path, _, _ in rescan.files]
        if version.content_hash != row.content_hash:
            return ('write', manifest, consumable_paths, ref)
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        if head is None or head.content_hash != version.content_hash:
            row.restored_from_version_id = version.version_id
            row.restored_from_seq = version.seq
            row.updated_at = _utcnow()
        return ('noop', manifest, consumable_paths, ref)

    def end_api_write(self, key: tuple, snapshot_dir: Path | str, restored_from: Optional[dict] = None) -> None:
        """Store the state left by an API write; never raises."""
        snapshot_dir = Path(snapshot_dir)
        marker_key = key
        try:
            if key[0] == 'dir':
                try:
                    snapshot_id = self.resolve_snapshot_identity(snapshot_dir)
                except Exception as exc:
                    logger.warning(
                        "Snapshot %s: API write could not be recorded because its identity could not be resolved "
                        "(%s); it will be recorded by the next evaluation",
                        snapshot_dir.name,
                        type(exc).__name__,
                    )
                    self.set_marker(key, restored_from)
                    return
                marker_key = self.id_key(snapshot_id)
                if self.unavailable_reason(snapshot_id, snapshot_dir.name):
                    self.set_marker(marker_key, restored_from)
                    return
            else:
                snapshot_id = key[2]
            self._evaluate(snapshot_id, snapshot_dir, 'end_write', restored_from=restored_from)
        except Exception as exc:
            logger.warning(
                "Snapshot %s: API write could not be recorded (%s); it will be recorded by the next evaluation",
                snapshot_dir.name,
                type(exc).__name__,
            )
            self.set_marker(marker_key, restored_from)
        finally:
            self._finish_api_write(key)

    def open_write_scope(self, snapshot_dir: Path | str) -> Optional[WriteScope]:
        """Run settle and begin_api_write for a mutating service call and return its write scope or None; never
        raises."""
        snapshot_dir = Path(snapshot_dir)
        try:
            if self.global_unavailable_reason():
                return None
            try:
                snapshot_id = self.resolve_snapshot_identity(snapshot_dir)
            except VersioningUnavailableError:
                return None
            except Exception as exc:
                logger.warning(
                    "Snapshot %s: identity resolution failed before an API write (%s); the write proceeds and is "
                    "recorded later",
                    snapshot_dir.name,
                    type(exc).__name__,
                )
                key = self.dir_key(snapshot_dir)
                self.begin_api_write(key)
                self.set_marker(key)
                return WriteScope(key=key, snapshot_dir=snapshot_dir)

            if self.unavailable_reason(snapshot_id, snapshot_dir.name):
                return None
            try:
                key = self.id_key(self.settle_external_changes(snapshot_id, snapshot_dir))
            except VersioningUnavailableError:
                return None
            except Exception as exc:
                logger.warning(
                    "Snapshot %s: settling external changes failed before an API write (%s); the write proceeds "
                    "and is recorded later",
                    snapshot_dir.name,
                    type(exc).__name__,
                )
                key = self.dir_key(snapshot_dir)
                self.set_marker(key)
            self.begin_api_write(key)
            return WriteScope(key=key, snapshot_dir=snapshot_dir)
        except Exception as exc:
            logger.warning(
                "Snapshot %s: versioning bookkeeping failed before an API write (%s)",
                snapshot_dir.name,
                type(exc).__name__,
            )
            return None

    def close_write_scope(self, scope: WriteScope) -> None:
        self.end_api_write(scope.key, scope.snapshot_dir)

    @contextmanager
    def evaluation_lock(self, snapshot_id: str, snapshot_dir: Path):
        key = (self.namespace, snapshot_id, snapshot_dir.name)
        with self._registry_lock:
            lock = self._evaluation_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._evaluation_locks[key] = lock
        with lock:
            yield

    def row_values(self, session, snapshot_id: str) -> tuple[Optional[SnapshotStateRow], Optional[_RowValues]]:
        row = session.execute(
            select(SnapshotStateRow).where(
                SnapshotStateRow.namespace == self.namespace,
                SnapshotStateRow.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if row is None:
            return None, None
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        return row, _RowValues(
            snapshot_name=row.snapshot_name,
            stat_fingerprint=row.stat_fingerprint,
            content_hash=row.content_hash,
            head_content_hash=head.content_hash if head else None,
            pending_external=bool(row.pending_external),
        )

    def _state_view(self, session, row: Optional[SnapshotStateRow], snapshot_id: str, snapshot_dir: Path,
                    settling: bool = False) -> SnapshotState:
        if row is None:
            return SnapshotState(
                snapshot_id=snapshot_id,
                snapshot_name=snapshot_dir.name,
                content_hash=None,
                head=None,
                head_content_hash=None,
                pending_external=False,
                external_settling=settling,
                restored_from=None,
                clear_seq=None,
                has_row=False,
            )
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        return SnapshotState(
            snapshot_id=snapshot_id,
            snapshot_name=snapshot_dir.name,
            content_hash=row.content_hash,
            head=self._history.serialize_version(head) if head is not None else None,
            head_content_hash=head.content_hash if head is not None else None,
            pending_external=bool(row.pending_external),
            external_settling=settling,
            restored_from=version_ref(row.restored_from_version_id, row.restored_from_seq),
            clear_seq=row.clear_seq,
            has_row=True,
        )

    def _read_view(self, snapshot_id: str, snapshot_dir: Path, settling: bool = False) -> SnapshotState:
        with self._db.get_db_session() as session:
            row, _ = self.row_values(session, snapshot_id)
            return self._state_view(session, row, snapshot_id, snapshot_dir, settling)

    def decide(self, mode: str, row: Optional[_RowValues], new_hash: str, scan: TreeScan,
               marker: Optional[UnrecordedWrite], restored_from: Optional[dict], never_settled: bool,
               snapshot_name: str) -> DecisionAction:
        """Apply the decision rules to a hashed manifest."""
        if row is None:
            return DecisionAction('baseline')
        if mode == 'end_write' and restored_from is not None:
            recorded = restored_from
        else:
            recorded = marker.restored_from if marker else None
        recorded_value = recorded if recorded is not None else _KEEP
        if new_hash == row.content_hash:
            return DecisionAction('store', restored_from=recorded_value)
        if mode == 'end_write' or marker is not None:
            if new_hash == row.head_content_hash:
                return DecisionAction('store')
            return DecisionAction('store', pending=True if never_settled else None, restored_from=recorded_value)
        if mode == 'poll' and self._settle_window_open(scan, snapshot_name):
            return DecisionAction('settling')
        if new_hash == row.head_content_hash:
            return DecisionAction('store')
        if row.content_hash != row.head_content_hash or row.pending_external or never_settled:
            return DecisionAction('store', pending=True)
        return DecisionAction('external')

    def _objects_may_be_needed(self, mode: str, row: Optional[_RowValues], scan: TreeScan,
                               marker: Optional[UnrecordedWrite], snapshot_name: str) -> bool:
        if row is None:
            return True
        if mode == 'end_write' or marker is not None:
            return False
        if row.content_hash != row.head_content_hash or row.pending_external:
            return False
        if mode == 'poll' and self._settle_window_open(scan, snapshot_name):
            return False
        return True

    def store_state(self, session, row: SnapshotStateRow, new_hash: str, fingerprint: str,
                    pending: Optional[bool] = None, restored_from: Any = _KEEP) -> None:
        """Store a working hash; clear pending_external and restored_from when it equals head's."""
        now = _utcnow()
        row.content_hash = new_hash
        row.stat_fingerprint = fingerprint
        if pending is not None:
            row.pending_external = pending
        if restored_from is not _KEEP:
            version_id = restored_from.get('version_id') if restored_from else None
            seq = restored_from.get('seq') if restored_from else None
            if version_id is not None and session.get(SnapshotVersion, version_id) is None:
                version_id = None
            row.restored_from_version_id = version_id
            row.restored_from_seq = seq
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        if head is not None and head.content_hash == new_hash:
            row.pending_external = False
            row.restored_from_version_id = None
            row.restored_from_seq = None
        row.evaluated_at = now
        row.updated_at = now

    def apply_action(self, session, action: DecisionAction, snapshot_id: str, snapshot_dir: Path,
                     manifest: Manifest, fingerprint: str) -> tuple[SnapshotStateRow, Optional[SnapshotVersion]]:
        """Apply a decision inside an open transaction; return the row and any automatic version."""
        row = session.execute(
            select(SnapshotStateRow).where(
                SnapshotStateRow.namespace == self.namespace,
                SnapshotStateRow.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        version = None
        if action.kind == 'baseline':
            row = SnapshotStateRow(
                namespace=self.namespace,
                snapshot_id=snapshot_id,
                snapshot_name=snapshot_dir.name,
                next_seq=1,
                pending_external=False,
            )
            session.add(row)
            session.flush()
            version = self._history.insert_version(session, row, manifest, 'baseline', BASELINE_MESSAGE)
        elif action.kind == 'external':
            version = self._history.insert_version(session, row, manifest, 'external', EXTERNAL_MESSAGE)
        else:
            self.store_state(
                session, row, manifest.content_hash, fingerprint,
                pending=action.pending, restored_from=action.restored_from,
            )
        row.stat_fingerprint = fingerprint
        row.evaluated_at = _utcnow()
        return row, version

    def log_automatic_version(self, snapshot_dir: Path, version: Optional[SnapshotVersion]) -> None:
        if version is not None and version.kind == 'external':
            logger.info(
                "External change versioned: snapshot=%s seq=%s files=%s",
                snapshot_dir.name,
                version.seq,
                version.file_count,
            )

    def _evaluate(self, snapshot_id: str, snapshot_dir: Path, mode: str,
                  restored_from: Optional[dict] = None) -> tuple[str, SnapshotState]:
        reresolved = False
        while True:
            try:
                if mode == 'poll':
                    return snapshot_id, self._evaluate_poll(snapshot_id, snapshot_dir)
                return snapshot_id, self._evaluate_locked(snapshot_id, snapshot_dir, mode, restored_from)
            except NameMismatchError:
                if reresolved:
                    raise IdentityResolutionError(
                        f"Snapshot {snapshot_dir.name} shares its state row with another directory"
                    )
                reresolved = True
                snapshot_id = self.resolve_snapshot_identity(snapshot_dir)

    def _step_one(self, snapshot_id: str, snapshot_dir: Path, mode: str,
                  restored_from: Optional[dict]) -> tuple[Optional[SnapshotState], Optional[TreeScan], Any]:
        """Stat-walk under history_lock; return (stored state or None when hashing is needed, scan, row values)."""
        key = self.id_key(snapshot_id)
        mismatch = False
        stored = None
        with history_lock:
            scan = self.scan_tree_or_none(snapshot_dir)
            with self._db.get_db_session() as session:
                row, values = self.row_values(session, snapshot_id)
                if values is not None and values.snapshot_name != snapshot_dir.name:
                    mismatch = True
                elif mode == 'poll' and self.write_in_progress(key, self.dir_key(snapshot_dir)):
                    stored = self._state_view(session, row, snapshot_id, snapshot_dir)
                elif (
                    scan is not None and values is not None and values.stat_fingerprint == scan.fingerprint
                    and not (mode == 'end_write' and restored_from is not None)
                ):
                    self.drop_marker(key)
                    stored = self._state_view(session, row, snapshot_id, snapshot_dir)
        if mismatch:
            raise NameMismatchError(snapshot_dir.name)
        return stored, scan, values

    def _evaluate_poll(self, snapshot_id: str, snapshot_dir: Path) -> SnapshotState:
        stored, _, _ = self._step_one(snapshot_id, snapshot_dir, 'poll', None)
        if stored is not None:
            return stored

        poll_key = (self.namespace, snapshot_id, snapshot_dir.name)
        with self._registry_lock:
            inflight = self._inflight_polls.get(poll_key)
            owner = inflight is None
            if owner:
                inflight = _InflightPoll()
                self._inflight_polls[poll_key] = inflight
        if not owner:
            inflight.event.wait()
            if inflight.result is not None:
                return inflight.result
            return self._evaluate_locked(snapshot_id, snapshot_dir, 'poll', None)
        try:
            result = self._evaluate_locked(snapshot_id, snapshot_dir, 'poll', None)
            inflight.result = result
            return result
        finally:
            with self._registry_lock:
                self._inflight_polls.pop(poll_key, None)
            inflight.event.set()

    def _evaluate_locked(self, snapshot_id: str, snapshot_dir: Path, mode: str,
                         restored_from: Optional[dict]) -> SnapshotState:
        key = self.id_key(snapshot_id)
        with self.evaluation_lock(snapshot_id, snapshot_dir):
            stored, scan, values = self._step_one(snapshot_id, snapshot_dir, mode, restored_from)
            if stored is not None:
                return stored

            force_objects = False
            last = None
            for round_number in range(1, MAX_EVALUATION_ROUNDS + 1):
                if scan is None:
                    with history_lock:
                        scan = self.scan_tree_or_none(snapshot_dir)
                    if scan is None:
                        continue
                with_objects = force_objects or self._objects_may_be_needed(
                    mode, values, scan, self.get_marker(key), snapshot_dir.name,
                )
                try:
                    manifest = self._hash_scan(scan, with_objects)
                except TreeMovedError:
                    scan = None
                    continue
                last = (scan, manifest, with_objects)
                outcome = self._settle_round(
                    snapshot_id, snapshot_dir, mode, restored_from, scan, manifest, with_objects,
                    final=round_number == MAX_EVALUATION_ROUNDS,
                )
                if isinstance(outcome, SnapshotState):
                    return outcome
                scan, force_objects, values = outcome

            if mode == 'poll':
                with history_lock:
                    return self._read_view(snapshot_id, snapshot_dir, settling=True)
            if last is None:
                raise StateStoreError(f"Snapshot {snapshot_dir.name} never settled long enough to be hashed")
            outcome = self._settle_round(
                snapshot_id, snapshot_dir, mode, restored_from, *last, final=True,
            )
            if isinstance(outcome, SnapshotState):
                return outcome
            raise StateStoreError(f"Snapshot {snapshot_dir.name} state could not be stored")

    def _hash_scan(self, scan: TreeScan, with_objects: bool) -> Manifest:
        if not with_objects:
            return run_blocking(hash_files, scan.files)
        manifest = run_blocking(self._history.put_files, scan.files)
        run_blocking(self._history.fsync_store_directories)
        return manifest

    def _settle_round(self, snapshot_id: str, snapshot_dir: Path, mode: str, restored_from: Optional[dict],
                      scan: TreeScan, manifest: Manifest, with_objects: bool, final: bool):
        """Run step 3 of one evaluation round; return a SnapshotState or (next_scan, force_objects, values)."""
        self.check_sidecar_identity(snapshot_dir, snapshot_id)
        with history_lock:
            rescan = self.scan_tree_or_none(snapshot_dir)
            with self._db.get_db_session() as session:
                outcome = self._round_outcome(
                    session, snapshot_id, snapshot_dir, mode, restored_from,
                    scan, rescan, manifest, with_objects, final,
                )
            if outcome[0] == 'stored':
                self.drop_marker(self.id_key(snapshot_id))
        tag = outcome[0]
        if tag == 'mismatch':
            raise NameMismatchError(snapshot_dir.name)
        if tag == 'store_failed':
            raise StateStoreError(f"Snapshot {snapshot_dir.name} objects are missing from the store")
        if tag == 'objects_unreadable':
            raise outcome[1]
        if tag == 'stored':
            self.log_automatic_version(snapshot_dir, outcome[2])
        return outcome[1]

    def _round_outcome(self, session, snapshot_id: str, snapshot_dir: Path, mode: str,
                       restored_from: Optional[dict], scan: TreeScan, rescan: Optional[TreeScan],
                       manifest: Manifest, with_objects: bool, final: bool) -> tuple:
        row, values = self.row_values(session, snapshot_id)
        if values is not None and values.snapshot_name != snapshot_dir.name:
            return ('mismatch',)
        settled = rescan is not None and rescan.fingerprint == scan.fingerprint
        if not settled and not final:
            return ('next', (rescan, False, values))
        if mode == 'poll':
            if self.write_in_progress(self.id_key(snapshot_id), self.dir_key(snapshot_dir)):
                return ('state', self._state_view(session, row, snapshot_id, snapshot_dir))
            if not settled:
                return ('state', self._state_view(session, row, snapshot_id, snapshot_dir, settling=True))
        action = self.decide(
            mode, values, manifest.content_hash, scan, self.get_marker(self.id_key(snapshot_id)), restored_from,
            never_settled=not settled, snapshot_name=snapshot_dir.name,
        )
        if action.kind == 'settling':
            return ('state', self._state_view(session, row, snapshot_id, snapshot_dir, settling=True))
        try:
            objects_missing = action.creates_version and (
                not with_objects or not self._history.objects_present(manifest)
            )
        except OSError as exc:
            return ('objects_unreadable', exc)
        if objects_missing:
            if not final:
                return ('next', (rescan, True, values))
            if mode == 'poll':
                return ('state', self._state_view(session, row, snapshot_id, snapshot_dir, settling=True))
            return ('store_failed',)
        row, version = self.apply_action(session, action, snapshot_id, snapshot_dir, manifest, scan.fingerprint)
        session.flush()
        return ('stored', self._state_view(session, row, snapshot_id, snapshot_dir), version)

    def evaluate_snapshot(self, snapshot_dir: Path | str) -> SnapshotState:
        """Resolve and evaluate an authorized snapshot directory for a poll."""
        snapshot_dir = Path(snapshot_dir)
        try:
            snapshot_id = self.resolve_available_snapshot(snapshot_dir)
            _, state = self._evaluate(snapshot_id, snapshot_dir, 'poll')
            return state
        except OSError as exc:
            raise SnapshotEvaluationError(f"Snapshot {snapshot_dir.name} could not be evaluated") from exc

    def get_state(self, snapshot_name: str, context: dict) -> SnapshotState:
        """Authorize a snapshot for the request context and return its evaluated state."""
        snapshot_dir = self._snapshot_service.get_snapshot_path(snapshot_name, **context)
        return self.evaluate_snapshot(snapshot_dir)

    def read_clear_counter(self) -> Optional[int]:
        """Return the history_meta clear counter, or None when it is unavailable; never raises."""
        reason = self.global_unavailable_reason()
        if reason or self._db is None:
            self._warn_once(
                ('clear_counter_unavailable', reason or 'database'),
                "Result cache clear counter is unavailable because snapshot versioning is unavailable (%s)",
                reason or 'database',
            )
            return None
        try:
            with history_lock:
                with self._db.get_db_session() as session:
                    meta = session.get(HistoryMeta, 1)
                    return int(meta.clear_counter) if meta is not None else None
        except Exception as exc:
            logger.warning("Result cache clear counter could not be read (%s)", type(exc).__name__)
            return None

    def record_cache_clear(self, snapshot_id: str) -> Optional[int]:
        """In one hold, store an incremented clear counter as the snapshot's clear_seq if it has a state row, and
        request its re-parse."""
        key = self.id_key(snapshot_id)
        with history_lock:
            with self._db.get_db_session() as session:
                row = session.execute(
                    select(SnapshotStateRow).where(
                        SnapshotStateRow.namespace == self.namespace,
                        SnapshotStateRow.snapshot_id == snapshot_id,
                    )
                ).scalar_one_or_none()
                clear_seq = None
                meta_missing = False
                if row is not None:
                    meta = session.get(HistoryMeta, 1)
                    meta_missing = meta is None
                    if not meta_missing:
                        meta.clear_counter = int(meta.clear_counter or 0) + 1
                        clear_seq = meta.clear_counter
                        row.clear_seq = clear_seq
                        row.updated_at = _utcnow()
            if meta_missing:
                raise StateStoreError("history_meta is missing")
            with self._registry_lock:
                self._reparse_requested[key] = clear_seq
        return clear_seq

    def request_reparse(self, snapshot_id: str) -> None:
        with history_lock:
            with self._registry_lock:
                self._reparse_requested[self.id_key(snapshot_id)] = None

    def reparse_requested(self, snapshot_id: Optional[str]) -> bool:
        if not snapshot_id:
            return False
        with self._registry_lock:
            return self.id_key(snapshot_id) in self._reparse_requested

    def consume_reparse(self, snapshot_id: Optional[str], parse_counter: Optional[int]) -> bool:
        """Clear the re-parse request when a parse read a counter at least the requested clear_seq."""
        if not snapshot_id or parse_counter is None:
            return False
        key = self.id_key(snapshot_id)
        with self._registry_lock:
            if key not in self._reparse_requested:
                return False
            requested = self._reparse_requested[key]
            if requested is not None and parse_counter < requested:
                return False
            del self._reparse_requested[key]
        return True

    def _active_snapshot_path(self) -> Optional[Path]:
        if not self.namespace_valid:
            return None
        path = self.data_dir / self.namespace / ACTIVE_SNAPSHOT_FILENAME
        assert_under_root(path, self.data_dir)
        return path

    def persist_active_snapshot(self, snapshot_name: str) -> None:
        """Atomically record the AUTH OFF active snapshot name under a valid namespace; never raises."""
        try:
            path = self._active_snapshot_path()
            if path is None:
                return
            make_private_dirs(path.parent)
            fd, temp_name = tempfile.mkstemp(prefix=f'.{ACTIVE_SNAPSHOT_FILENAME}.', suffix='.tmp', dir=path.parent)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                    json.dump({'snapshot_name': snapshot_name}, handle)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, path)
            except BaseException:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise
        except Exception as exc:
            logger.warning(
                "The active snapshot name could not be stored for the next start (%s)", type(exc).__name__,
            )

    def _read_active_snapshot_name(self, path: Path) -> Any:
        with open(path, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        return payload.get('snapshot_name') if isinstance(payload, dict) else None

    def clear_active_snapshot_file(self, snapshot_name: Optional[str] = None) -> None:
        """Delete the active snapshot file (with snapshot_name, only if it names that snapshot); never raises."""
        try:
            path = self._active_snapshot_path()
            if path is None or not os.path.lexists(path):
                return
            if snapshot_name is not None:
                try:
                    stored = self._read_active_snapshot_name(path)
                except (OSError, ValueError):
                    stored = None
                if stored != snapshot_name:
                    return
            path.unlink()
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("The stored active snapshot name could not be removed (%s)", type(exc).__name__)

    def load_active_snapshot_once(self) -> Optional[str]:
        """Return the stored AUTH OFF active snapshot name on the first call, or None."""
        with self._registry_lock:
            if self._active_snapshot_loaded:
                return None
            self._active_snapshot_loaded = True
        try:
            path = self._active_snapshot_path()
            if path is None:
                return None
            try:
                name = self._read_active_snapshot_name(path)
            except FileNotFoundError:
                logger.warning("No stored active snapshot name; no snapshot is selected at start")
                return None
            if not isinstance(name, str):
                raise ValueError("The stored active snapshot name is not a string")
            safe_name = self._snapshot_service._validate_snapshot_name(name)
            if not (Path(self._snapshot_service.snapshots_dir) / safe_name).is_dir():
                logger.warning(
                    "The stored active snapshot %s no longer exists; no snapshot is selected at start", safe_name,
                )
                return None
            return safe_name
        except Exception as exc:
            logger.warning(
                "The stored active snapshot name cannot be used (%s); no snapshot is selected at start",
                type(exc).__name__,
            )
            return None

    def staging_root(self) -> Path:
        if self.data_dir_in_store or (not self.namespace_valid and self.invalid_namespace_root_overlaps):
            if self._system_temp_staging_root is None:
                self._system_temp_staging_root = Path(tempfile.mkdtemp(prefix='topologix-staging-'))
            return self._system_temp_staging_root
        if self.namespace_valid:
            return self.data_dir / self.namespace / 'staging'
        return self.invalid_namespace_root / 'staging'

    def stage_for_upload(self, snapshot_dir: Path | str) -> tuple[Path, str]:
        """Copy the consumable file set into a staging directory; return (staged_dir, content_hash)."""
        snapshot_dir = Path(snapshot_dir)
        root = self.staging_root()
        make_private_dirs(root)
        snapshot_id = self.read_sidecar_id(snapshot_dir)
        if snapshot_id:
            container = root / snapshot_id
            assert_under_root(container, root)
            if container.exists():
                shutil.rmtree(container)
            container.mkdir(mode=0o700)
        else:
            container = Path(tempfile.mkdtemp(dir=root))
            assert_under_root(container, root)
        staged_dir = container / snapshot_dir.name
        try:
            assert_under_root(staged_dir, root)
            for attempt in (1, 2):
                try:
                    scan = self.scan_tree(snapshot_dir)
                    make_private_dirs(staged_dir)
                    manifest = run_blocking(copy_files, scan.files, staged_dir)
                    if self.scan_tree(snapshot_dir).fingerprint != scan.fingerprint:
                        raise TreeMovedError(snapshot_dir.name)
                    return staged_dir, manifest.content_hash
                except TreeMovedError:
                    if staged_dir.exists():
                        shutil.rmtree(staged_dir)
                    if attempt == 2:
                        raise StagingVanishedError(f"Snapshot {snapshot_dir.name} changed while it was staged")
        except BaseException:
            shutil.rmtree(container, ignore_errors=True)
            raise
        raise StagingVanishedError(f"Snapshot {snapshot_dir.name} changed while it was staged")

    def cleanup_staging(self, staged_dir: Path | str) -> None:
        container = Path(staged_dir).parent
        assert_under_root(container, self.staging_root())
        shutil.rmtree(container, ignore_errors=True)

    def _empty_directory(self, directory: Path, root: Path) -> None:
        try:
            directory_stat = os.lstat(directory)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(directory_stat.st_mode):
            return
        assert_under_root(directory, root)
        for entry in os.scandir(directory):
            entry_path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry_path, ignore_errors=True)
            else:
                try:
                    entry_path.unlink()
                except FileNotFoundError:
                    pass

    def cleanup_all_staging(self, db_id: Optional[str] = None) -> None:
        """Empty the leftover staging and temporary directories that are safe to empty at startup."""
        if self.namespace_valid:
            self._empty_directory(self.data_dir / self.namespace / 'staging', self.data_dir)
        if not self.data_dir_in_store and not self.invalid_namespace_root_overlaps:
            self._empty_directory(self.invalid_namespace_root / 'staging', self.data_dir)
        if not self.storage_overlap:
            if db_id and is_canonical_uuid4(db_id):
                self._empty_directory(self.history_dir / db_id / 'tmp', self.history_dir)
            self._empty_directory(self.result_cache_dir / 'tmp', self.result_cache_dir)
