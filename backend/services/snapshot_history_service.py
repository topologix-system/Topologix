"""Snapshot version history service"""
import difflib
import errno
import hashlib
import itertools
import logging
import os
import re
import shutil
import stat
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from database.models import HistoryMeta, HistoryNamespace, HistoryObject, SnapshotState as SnapshotStateRow
from database.models import SnapshotVersion, SnapshotVersionFile
from services.result_cache import owner_scope_for
from services.snapshot_state_service import (
    HASH_CHUNK_SIZE,
    MAX_EVALUATION_ROUNDS,
    IdentityResolutionError,
    Manifest,
    NameMismatchError,
    TreeMovedError,
    VersioningUnavailableError,
    _gevent_threading_patched,
    assert_under_root,
    history_lock,
    is_canonical_uuid4,
    make_private_dirs,
    open_regular_file,
    run_blocking,
    version_ref,
)

logger = logging.getLogger(__name__)

MAX_COMMIT_ATTEMPTS = 3
SQL_IN_CHUNK = 500
_SHA256_PATTERN = re.compile(r'^[0-9a-f]{64}$')
EXPECTED_HEAD_UNSET = object()
SYSTEM_VERSION_KINDS = frozenset({'baseline', 'external'})
DELETION_MODES = frozenset({'single', 'all', 'oldest', 'newest'})
PERIODIC_MAINTENANCE_INTERVAL_SECONDS = 3600
DIFF_WORKING_SIDE = 'working'
DIFF_CONTEXT_LINES = 3
ABSENT_WORKING_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ENXIO})
# Most line comparisons one file diff may spend on matching before it is answered as too_large
DIFF_MATCH_BUDGET = 30_000_000
# Most file diffs that build their hunks at the same time
DIFF_JOB_SLOTS = threading.BoundedSemaphore(2)
_DIFF_TOO_LARGE = object()


class VersionUnchangedError(Exception):
    """The working tree equals the head version"""


class VersionConflictError(Exception):
    """A versioning write conflicts with an API write in progress, a changed tree or a stale expectation"""


class VersionNotFoundError(Exception):
    """The version does not belong to the authorized snapshot"""


class NamespaceNotFoundError(Exception):
    """The database holds no snapshot history for the named namespace"""


class CurrentNamespaceError(Exception):
    """The requested namespace is, or the database matches it to, the current deployment namespace"""


class RestoreFailedError(Exception):
    """A restore could not settle external changes, found a missing or changed object, or could not rewrite the tree"""


class PathClashError(VersionConflictError):
    """A version path is unsafe or clashes with a working tree entry that a restore never replaces"""

    def __init__(self, path: str):
        super().__init__("A version path clashes with an entry of the working tree")
        self.path = path


class InvalidDiffPathError(ValueError):
    """The requested path is a file of neither side of a diff"""


class _DiffObjectMissingError(Exception):
    """A history object read for a diff is absent from the object store"""

    def __init__(self, version_id: str, error: OSError):
        super().__init__("A history object of the diffed version is absent from the object store")
        self.version_id = version_id
        self.error = error


class _DiffBudgetExceededError(Exception):
    """Matching the lines of a file diff would exceed its comparison budget"""

    def __init__(self, work: int):
        super().__init__("Matching the lines of a file diff would exceed its comparison budget")
        self.work = work


@dataclass(frozen=True)
class StoreView:
    """Sidecar identities and directory set of the snapshot store root, read once"""
    holders: dict
    unreadable: frozenset
    directories: frozenset


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def is_in_memory_sqlite(database_url: str) -> bool:
    try:
        url = make_url(database_url)
    except Exception:
        return False
    if url.get_backend_name() != 'sqlite':
        return False
    database = url.database or ''
    return database in ('', ':memory:') or database.startswith('file::memory:') or url.query.get('mode') == 'memory'


def is_database_error(error: BaseException, db_manager: Any = None) -> bool:
    """Return whether error is a SQLAlchemy error or an exception of db_manager's DBAPI driver."""
    if isinstance(error, SQLAlchemyError):
        return True
    dialect = getattr(getattr(db_manager, 'engine', None), 'dialect', None)
    driver_error = getattr(getattr(dialect, 'loaded_dbapi', None), 'Error', None)
    return isinstance(driver_error, type) and isinstance(error, driver_error)


def _chunks(values: list, size: int = SQL_IN_CHUNK) -> Iterable[list]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _manifest_entries(manifest: Manifest) -> dict[str, tuple[str, int]]:
    return {path: (sha256, size) for path, sha256, size in manifest.files}


def diff_file_list(manifest: Manifest, against_manifest: Manifest) -> list[dict[str, Any]]:
    """Return {path, status, size, against_size} for every path of either manifest, ordered by UTF-8 bytes."""
    old_entries = _manifest_entries(manifest)
    new_entries = _manifest_entries(against_manifest)
    files = []
    for path in sorted(old_entries.keys() | new_entries.keys(), key=lambda item: item.encode('utf-8')):
        old_entry = old_entries.get(path)
        new_entry = new_entries.get(path)
        if old_entry is None:
            status = 'added'
        elif new_entry is None:
            status = 'removed'
        elif old_entry[0] != new_entry[0]:
            status = 'modified'
        else:
            status = 'unchanged'
        files.append({
            'path': path,
            'status': status,
            'size': old_entry[1] if old_entry is not None else None,
            'against_size': new_entry[1] if new_entry is not None else None,
        })
    return files


def split_diff_lines(text: str) -> list[str]:
    """Split text at newlines, each line keeping its newline, so a missing final newline is a difference."""
    parts = text.split('\n')
    lines = [part + '\n' for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def decode_diff_text(data: Optional[bytes]) -> Optional[list[str]]:
    """Return the lines of one diff side ([] when absent), or None when it holds a NUL byte or is not UTF-8."""
    if data is None:
        return []
    if b'\0' in data:
        return None
    try:
        return split_diff_lines(data.decode('utf-8'))
    except UnicodeDecodeError:
        return None


def _diff_hunk(old_index: int, new_index: int, lines: list) -> dict[str, Any]:
    old_lines = sum(1 for kind, _ in lines if kind != '+')
    new_lines = sum(1 for kind, _ in lines if kind != '-')
    return {
        'old_start': old_index + 1 if old_lines else old_index,
        'old_lines': old_lines,
        'new_start': new_index + 1 if new_lines else new_index,
        'new_lines': new_lines,
        'lines': [{'type': kind, 'text': line[:-1] if line.endswith('\n') else line} for kind, line in lines],
    }


class _BudgetedMatcher(difflib.SequenceMatcher):
    """SequenceMatcher that charges every find_longest_match call the line comparisons it may make and raises
    _DiffBudgetExceededError instead of exceeding its budget; with strip it takes the common prefix and suffix
    as its first matches."""

    def __init__(self, a: list[str], b: list[str], budget: int, strip: bool):
        super().__init__(None, a, b)
        prefix = suffix = 0
        if strip:
            shorter = min(len(a), len(b))
            while prefix < shorter and a[prefix] == b[prefix]:
                prefix += 1
            while suffix < shorter - prefix and a[-1 - suffix] == b[-1 - suffix]:
                suffix += 1
        self.prefix = prefix
        self.suffix = suffix
        self.budget = budget
        self.work = 0
        self._costs = list(itertools.accumulate(
            (1 + len(self.b2j.get(line, ())) for line in a), initial=0,
        ))
        if self._costs[len(a) - suffix] - self._costs[prefix] > budget:
            raise _DiffBudgetExceededError(0)

    def find_longest_match(self, alo=0, ahi=None, blo=0, bhi=None):
        ahi = len(self.a) if ahi is None else ahi
        bhi = len(self.b) if bhi is None else bhi
        whole = ahi == len(self.a) and bhi == len(self.b)
        if whole and alo == blo == 0 and self.prefix:
            return difflib.Match(0, 0, self.prefix)
        if whole and alo == blo == self.prefix and self.suffix:
            return difflib.Match(len(self.a) - self.suffix, len(self.b) - self.suffix, self.suffix)
        cost = self._costs[ahi] - self._costs[alo]
        if self.work + cost > self.budget:
            raise _DiffBudgetExceededError(self.work)
        self.work += cost
        return super().find_longest_match(alo, ahi, blo, bhi)


def _grouped_opcodes(old_lines: list[str], new_lines: list[str]) -> list:
    """Group the opcodes exactly as difflib does when its matching fits half of DIFF_MATCH_BUDGET; otherwise match
    the lines between the common prefix and suffix within the rest of the budget."""
    try:
        exact = _BudgetedMatcher(old_lines, new_lines, DIFF_MATCH_BUDGET // 2, strip=False)
        return list(exact.get_grouped_opcodes(DIFF_CONTEXT_LINES))
    except _DiffBudgetExceededError as exc:
        spent = exc.work
    stripped = _BudgetedMatcher(old_lines, new_lines, DIFF_MATCH_BUDGET - spent, strip=True)
    return list(stripped.get_grouped_opcodes(DIFF_CONTEXT_LINES))


def build_diff_hunks(old_lines: list[str], new_lines: list[str], max_lines: int) -> tuple[list, bool]:
    """Return the unified hunks from old_lines to new_lines, cut after max_lines lines, and whether they were cut.

    Raises _DiffBudgetExceededError when matching the lines would exceed DIFF_MATCH_BUDGET comparisons.
    """
    hunks = []
    emitted = 0
    for group in _grouped_opcodes(old_lines, new_lines):
        lines = []
        for tag, old_from, old_to, new_from, new_to in group:
            if tag == 'equal':
                lines.extend((' ', line) for line in old_lines[old_from:old_to])
                continue
            if tag in ('replace', 'delete'):
                lines.extend(('-', line) for line in old_lines[old_from:old_to])
            if tag in ('replace', 'insert'):
                lines.extend(('+', line) for line in new_lines[new_from:new_to])
        truncated = emitted + len(lines) > max_lines
        if truncated:
            lines = lines[:max(max_lines - emitted, 0)]
        if lines:
            hunks.append(_diff_hunk(group[0][1], group[0][3], lines))
            emitted += len(lines)
        if truncated:
            return hunks, True
    return hunks, False


class SnapshotHistoryService:
    """Object store and version rows for snapshot history"""

    def __init__(self, db_manager, state_service, history_dir, settings=None):
        self._db = db_manager
        self._state = state_service
        self.history_dir = Path(history_dir)
        self.settings = settings if settings is not None else state_service.settings
        self.db_id: Optional[str] = None
        self._periodic_lock = threading.Lock()
        self._periodic_running = False
        self._last_periodic_run = time.monotonic()
        self.periodic_worker = None
        self.result_cache = None
        state_service.attach_history_service(self)

    def attach_result_cache(self, result_cache) -> None:
        self.result_cache = result_cache

    @property
    def store_dir(self) -> Path:
        if not self.db_id:
            raise VersioningUnavailableError('database')
        return self.history_dir / self.db_id

    @property
    def objects_dir(self) -> Path:
        return self.store_dir / 'objects'

    @property
    def tmp_dir(self) -> Path:
        return self.store_dir / 'tmp'

    @property
    def trash_dir(self) -> Path:
        return self.store_dir / 'trash'

    def object_path(self, sha256: str) -> Path:
        if not isinstance(sha256, str) or not _SHA256_PATTERN.fullmatch(sha256):
            raise ValueError("Invalid object hash")
        return self.objects_dir / sha256[:2] / sha256

    @staticmethod
    def fsync_directory(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _put_object(self, source_path: Path, relative_path: Optional[str] = None) -> tuple[str, int]:
        tmp_dir = self.tmp_dir
        make_private_dirs(tmp_dir)
        source_fd = open_regular_file(source_path, relative_path)
        temp_name: Optional[str] = None
        try:
            try:
                temp_fd, temp_name = tempfile.mkstemp(dir=tmp_dir, prefix='object-')
            except BaseException:
                os.close(source_fd)
                raise
            hasher = hashlib.sha256()
            size = 0
            with os.fdopen(source_fd, 'rb') as source, os.fdopen(temp_fd, 'wb') as copy:
                while True:
                    chunk = source.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    copy.write(chunk)
                    size += len(chunk)
                copy.flush()
                os.fsync(copy.fileno())
            sha256 = hasher.hexdigest()

            object_dir = self.objects_dir / sha256[:2]
            make_private_dirs(object_dir)
            object_path = object_dir / sha256
            try:
                os.utime(object_path)
                install = os.stat(object_path).st_size != size
            except FileNotFoundError:
                install = True
            if install:
                os.replace(temp_name, object_path)
                temp_name = None
            self.fsync_directory(object_dir)
            return sha256, size
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    def put_object(self, source_path: Path | str) -> str:
        """Copy a file into the object store while hashing it; return its sha256."""
        return self._put_object(Path(source_path))[0]

    def put_files(self, files) -> Manifest:
        """Store every scanned file and return the manifest built from the stored hashes."""
        entries = []
        for relative_path, absolute_path, _ in files:
            sha256, size = self._put_object(absolute_path, relative_path)
            entries.append((relative_path, sha256, size))
        return Manifest.from_entries(entries)

    def fsync_store_directories(self) -> None:
        for directory in (self.objects_dir, self.store_dir, self.history_dir):
            if directory.is_dir():
                self.fsync_directory(directory)

    def objects_present(self, manifest: Manifest) -> bool:
        for _, sha256, size in manifest.files:
            try:
                object_stat = os.stat(self.object_path(sha256))
            except FileNotFoundError:
                return False
            if not stat.S_ISREG(object_stat.st_mode) or object_stat.st_size != size:
                return False
        return True

    def open_object(self, sha256: str):
        return open(self.object_path(sha256), 'rb')

    def verify_object(self, sha256: str) -> bool:
        hasher = hashlib.sha256()
        try:
            with self.open_object(sha256) as object_file:
                while True:
                    chunk = object_file.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
        except FileNotFoundError:
            return False
        return hasher.hexdigest() == sha256

    def _upsert_objects(self, session, manifest: Manifest) -> None:
        sizes: dict[str, int] = {}
        for _, sha256, size in manifest.files:
            sizes.setdefault(sha256, size)
        existing: set[str] = set()
        for chunk in _chunks(list(sizes)):
            existing.update(session.execute(
                select(HistoryObject.sha256).where(HistoryObject.sha256.in_(chunk))
            ).scalars())
        now = _utcnow()
        for sha256, size in sizes.items():
            if sha256 not in existing:
                session.add(HistoryObject(sha256=sha256, size=size, created_at=now))

    def insert_version(self, session, row: SnapshotStateRow, manifest: Manifest, kind: str, message: str,
                       author_user_id: Optional[int] = None, author_username: Optional[str] = None) -> SnapshotVersion:
        """Insert a version for the state row, advance head and clear restored_from and pending_external."""
        now = _utcnow()
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        restored_from_id = restored_from_seq = None
        if kind in ('manual', 'restore'):
            restored_from_id, restored_from_seq = row.restored_from_version_id, row.restored_from_seq
            if restored_from_id is not None and session.get(SnapshotVersion, restored_from_id) is None:
                restored_from_id = None
        if kind in SYSTEM_VERSION_KINDS:
            author_user_id = author_username = None

        version = SnapshotVersion(
            version_id=str(uuid.uuid4()),
            snapshot_id=row.snapshot_id,
            namespace=row.namespace,
            seq=row.next_seq,
            content_hash=manifest.content_hash,
            parent_version_id=head.version_id if head is not None else None,
            parent_seq=head.seq if head is not None else None,
            kind=kind,
            message=message,
            author_user_id=author_user_id,
            author_username=author_username,
            restored_from_version_id=restored_from_id,
            restored_from_seq=restored_from_seq,
            created_at=now,
            file_count=manifest.file_count,
            total_bytes=manifest.total_bytes,
        )
        session.add(version)
        self._upsert_objects(session, manifest)
        session.flush()
        if manifest.files:
            session.execute(insert(SnapshotVersionFile), [
                {'version_id': version.version_id, 'path': path, 'sha256': sha256, 'size': size}
                for path, sha256, size in manifest.files
            ])

        row.next_seq = version.seq + 1
        row.head_version_id = version.version_id
        row.content_hash = manifest.content_hash
        row.pending_external = False
        row.restored_from_version_id = None
        row.restored_from_seq = None
        row.updated_at = now
        return version

    def serialize_version(self, version: SnapshotVersion) -> dict[str, Any]:
        return {
            'version_id': version.version_id,
            'seq': version.seq,
            'message': version.message,
            'kind': version.kind,
            'created_at': _isoformat(version.created_at),
            'author': None if version.kind in SYSTEM_VERSION_KINDS else version.author_username,
            'file_count': version.file_count,
            'total_bytes': version.total_bytes,
            'parent': version_ref(version.parent_version_id, version.parent_seq),
            'restored_from': version_ref(version.restored_from_version_id, version.restored_from_seq),
        }

    def commit(self, snapshot_id: str, snapshot_dir: Path | str, message: str, author: Optional[dict] = None,
               expected_head: Any = EXPECTED_HEAD_UNSET) -> dict[str, Any]:
        """Create a manual or restore version of the working tree; return the version object."""
        snapshot_dir = Path(snapshot_dir)
        reresolved = False
        for _ in range(MAX_COMMIT_ATTEMPTS):
            prepared = self._commit_phase1(snapshot_dir)
            if prepared is None:
                continue
            scan, manifest = prepared
            outcome = self._commit_phase2(snapshot_id, snapshot_dir, scan, manifest, message, author, expected_head)
            tag = outcome[0]
            if tag == 'restart':
                continue
            if tag == 'mismatch':
                if reresolved:
                    raise IdentityResolutionError(
                        f"Snapshot {snapshot_dir.name} shares its state row with another directory"
                    )
                reresolved = True
                snapshot_id = self._state.resolve_snapshot_identity(snapshot_dir)
                continue
            if tag == 'in_progress':
                raise VersionConflictError("An API write is in progress for this snapshot")
            if tag == 'unchanged':
                raise VersionUnchangedError("The working tree has no changes against the head version")
            if tag == 'head_conflict':
                raise VersionConflictError("The head version changed since it was displayed")
            return outcome[1]
        raise VersionConflictError("The snapshot kept changing while it was committed")

    def _commit_phase1(self, snapshot_dir: Path):
        scan = self._state.scan_tree_or_none(snapshot_dir)
        if scan is None:
            return None
        try:
            manifest = run_blocking(self.put_files, scan.files)
        except TreeMovedError:
            return None
        run_blocking(self.fsync_store_directories)
        return scan, manifest

    def _commit_phase2(self, snapshot_id: str, snapshot_dir: Path, scan, manifest: Manifest, message: str,
                       author: Optional[dict], expected_head: Any) -> tuple:
        state = self._state
        key = state.id_key(snapshot_id)
        with state.evaluation_lock(snapshot_id, snapshot_dir):
            state.check_sidecar_identity(snapshot_dir, snapshot_id)
            with history_lock:
                if state.write_in_progress(key, state.dir_key(snapshot_dir)):
                    return ('in_progress',)
                rescan = state.scan_tree_or_none(snapshot_dir)
                if rescan is None or rescan.fingerprint != scan.fingerprint:
                    return ('restart',)
                if not self.objects_present(manifest):
                    return ('restart',)
                with self._db.get_db_session() as session:
                    outcome = self._commit_transaction(
                        session, snapshot_id, snapshot_dir, scan, manifest, message, author, expected_head,
                        state.get_marker(key),
                    )
                if outcome[0] != 'mismatch':
                    state.drop_marker(key)
        if outcome[0] != 'mismatch':
            state.log_automatic_version(snapshot_dir, outcome[2])
        return outcome

    def _commit_transaction(self, session, snapshot_id: str, snapshot_dir: Path, scan, manifest: Manifest,
                            message: str, author: Optional[dict], expected_head: Any, marker) -> tuple:
        state = self._state
        _, values = state.row_values(session, snapshot_id)
        if values is not None and values.snapshot_name != snapshot_dir.name:
            return ('mismatch',)
        action = state.decide(
            'commit', values, manifest.content_hash, scan, marker, None,
            never_settled=False, snapshot_name=snapshot_dir.name,
        )
        row, automatic = state.apply_action(session, action, snapshot_id, snapshot_dir, manifest, scan.fingerprint)
        session.flush()
        head = session.get(SnapshotVersion, row.head_version_id) if row.head_version_id else None
        if head is not None and head.content_hash == manifest.content_hash:
            return ('unchanged', None, automatic)
        if expected_head is not EXPECTED_HEAD_UNSET and expected_head != (head.version_id if head else None):
            return ('head_conflict', None, automatic)

        kind = 'restore' if row.restored_from_seq is not None else 'manual'
        version = self.insert_version(
            session, row, manifest, kind, message,
            author_user_id=(author or {}).get('user_id'),
            author_username=(author or {}).get('username'),
        )
        row.stat_fingerprint = scan.fingerprint
        row.evaluated_at = _utcnow()
        session.flush()
        return ('created', self.serialize_version(version), automatic)

    def list_versions(self, snapshot_id: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Return {items, total} with items ordered by seq descending."""
        namespace = self._state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                total = session.execute(
                    select(func.count()).select_from(SnapshotVersion).where(
                        SnapshotVersion.namespace == namespace,
                        SnapshotVersion.snapshot_id == snapshot_id,
                    )
                ).scalar_one()
                versions = session.execute(
                    select(SnapshotVersion).where(
                        SnapshotVersion.namespace == namespace,
                        SnapshotVersion.snapshot_id == snapshot_id,
                    ).order_by(SnapshotVersion.seq.desc()).limit(limit).offset(offset)
                ).scalars().all()
                items = [self.serialize_version(version) for version in versions]
        return {'items': items, 'total': total}

    def get_version(self, snapshot_id: str, version_id: str) -> dict[str, Any]:
        """Return the version object plus its files; raise VersionNotFoundError outside the snapshot."""
        namespace = self._state.namespace
        result = None
        with history_lock:
            with self._db.get_db_session() as session:
                version = session.execute(
                    select(SnapshotVersion).where(
                        SnapshotVersion.version_id == version_id,
                        SnapshotVersion.namespace == namespace,
                        SnapshotVersion.snapshot_id == snapshot_id,
                    )
                ).scalar_one_or_none()
                if version is not None:
                    files = session.execute(
                        select(SnapshotVersionFile.path, SnapshotVersionFile.sha256, SnapshotVersionFile.size)
                        .where(SnapshotVersionFile.version_id == version.version_id)
                    ).all()
                    result = self.serialize_version(version)
                    result['files'] = [
                        {'path': path, 'sha256': sha256, 'size': size}
                        for path, sha256, size in sorted(files, key=lambda item: item[0].encode('utf-8'))
                    ]
        if result is None:
            raise VersionNotFoundError("Version not found for this snapshot")
        return result

    @staticmethod
    def _version_manifest(session, namespace: str, snapshot_id: str, version_id: str) -> Optional[Manifest]:
        found = session.execute(
            select(SnapshotVersion.version_id).where(
                SnapshotVersion.version_id == version_id,
                SnapshotVersion.namespace == namespace,
                SnapshotVersion.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if found is None:
            return None
        return Manifest.from_entries(session.execute(
            select(SnapshotVersionFile.path, SnapshotVersionFile.sha256, SnapshotVersionFile.size)
            .where(SnapshotVersionFile.version_id == found)
        ).all())

    def _read_diff_manifests(self, snapshot_id: str, version_id: str,
                             against: str) -> tuple[Manifest, Optional[Manifest]]:
        """Read the version's manifest and, unless against is the working tree, the other version's manifest."""
        namespace = self._state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                manifest = self._version_manifest(session, namespace, snapshot_id, version_id)
                against_manifest = None
                if manifest is not None and against != DIFF_WORKING_SIDE:
                    against_manifest = self._version_manifest(session, namespace, snapshot_id, against)
        if manifest is None or (against != DIFF_WORKING_SIDE and against_manifest is None):
            raise VersionNotFoundError("Version not found for this snapshot")
        return manifest, against_manifest

    def _version_exists(self, snapshot_id: str, version_id: str) -> bool:
        namespace = self._state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                found = session.execute(
                    select(SnapshotVersion.version_id).where(
                        SnapshotVersion.version_id == version_id,
                        SnapshotVersion.namespace == namespace,
                        SnapshotVersion.snapshot_id == snapshot_id,
                    )
                ).scalar_one_or_none()
        return found is not None

    def diff_summary(self, snapshot_id: str, snapshot_dir: Path | str, version_id: str,
                     against: str) -> dict[str, Any]:
        """Return the files changed from the version to against, a version id of the snapshot or 'working'."""
        manifest, against_manifest = self._read_diff_manifests(snapshot_id, version_id, against)
        result: dict[str, Any] = {'from': version_id, 'against': against}
        if against == DIFF_WORKING_SIDE:
            against_manifest = self._state.compute_manifest(Path(snapshot_dir))
            result['working_content_hash'] = against_manifest.content_hash
        result['files'] = diff_file_list(manifest, against_manifest)
        return result

    def _working_paths(self, snapshot_dir: Path) -> set[str]:
        for _ in range(MAX_EVALUATION_ROUNDS):
            try:
                return {relative_path for relative_path, _ in self._state.iter_consumable_files(snapshot_dir)}
            except TreeMovedError:
                continue
        raise TreeMovedError(snapshot_dir.name)

    def diff_file(self, snapshot_id: str, snapshot_dir: Path | str, version_id: str, against: str,
                  path: str) -> dict[str, Any]:
        """Return one file's unified hunks from the version to against, a version id of the snapshot or 'working'."""
        snapshot_dir = Path(snapshot_dir)
        manifest, against_manifest = self._read_diff_manifests(snapshot_id, version_id, against)
        old_entry = _manifest_entries(manifest).get(path)
        new_entry = None
        if against == DIFF_WORKING_SIDE:
            member = old_entry is not None or path in self._working_paths(snapshot_dir)
        else:
            new_entry = _manifest_entries(against_manifest).get(path)
            member = old_entry is not None or new_entry is not None
        if not member:
            raise InvalidDiffPathError("'path' is not a file of either side of the diff")

        try:
            with DIFF_JOB_SLOTS:
                return run_blocking(
                    self._build_file_diff, snapshot_dir, version_id, against, path, old_entry, new_entry,
                )
        except _DiffObjectMissingError as exc:
            if self._version_exists(snapshot_id, exc.version_id):
                raise exc.error from None
            raise VersionNotFoundError("Version not found for this snapshot") from exc

    def _build_file_diff(self, snapshot_dir: Path, version_id: str, against: str, path: str,
                         old_entry: Optional[tuple], new_entry: Optional[tuple]) -> dict[str, Any]:
        """Read both sides of one file within the size limit and build its hunks (file-only work)."""
        max_bytes = int(self.settings.SNAPSHOT_DIFF_MAX_BYTES)
        result: dict[str, Any] = {'path': path, 'binary': False, 'too_large': False, 'truncated': False, 'hunks': []}
        old = self._read_object_side(version_id, old_entry, max_bytes)
        if against == DIFF_WORKING_SIDE:
            new = self._read_working_side(snapshot_dir, path, max_bytes)
        else:
            new = self._read_object_side(against, new_entry, max_bytes)
        if old is _DIFF_TOO_LARGE or new is _DIFF_TOO_LARGE:
            result['too_large'] = True
            return result
        old_lines = decode_diff_text(old)
        new_lines = decode_diff_text(new)
        if old_lines is None or new_lines is None:
            result['binary'] = True
            return result
        try:
            result['hunks'], result['truncated'] = build_diff_hunks(
                old_lines, new_lines, int(self.settings.SNAPSHOT_DIFF_MAX_LINES),
            )
        except _DiffBudgetExceededError:
            result['too_large'] = True
        return result

    def _read_object_side(self, version_id: str, entry: Optional[tuple], max_bytes: int):
        """Return a version's file content, None when the version lacks the file, or _DIFF_TOO_LARGE."""
        if entry is None:
            return None
        sha256, size = entry
        if size > max_bytes:
            return _DIFF_TOO_LARGE
        try:
            object_file = self.open_object(sha256)
        except FileNotFoundError as exc:
            raise _DiffObjectMissingError(version_id, exc) from exc
        with object_file:
            data = object_file.read(max_bytes + 1)
        return _DIFF_TOO_LARGE if len(data) > max_bytes else data

    def _read_working_side(self, snapshot_dir: Path, path: str, max_bytes: int):
        """Return a working file's content, None when it is absent on the working side, or _DIFF_TOO_LARGE."""
        fd = self._open_working_file(snapshot_dir, path)
        if fd is None:
            return None
        with os.fdopen(fd, 'rb') as working_file:
            if os.fstat(working_file.fileno()).st_size > max_bytes:
                return _DIFF_TOO_LARGE
            data = working_file.read(max_bytes + 1)
        return _DIFF_TOO_LARGE if len(data) > max_bytes else data

    def _open_working_file(self, snapshot_dir: Path, path: str) -> Optional[int]:
        """Open a working regular file through real directories without blocking; None when it is absent."""
        parts = path.split('/')
        if any(part in ('', '.', '..') for part in parts):
            return None
        current = snapshot_dir
        for index, part in enumerate(parts):
            current = current / part
            try:
                mode = os.lstat(current).st_mode
            except OSError as exc:
                if exc.errno in ABSENT_WORKING_ERRNOS:
                    return None
                raise
            expected_type = stat.S_ISREG if index == len(parts) - 1 else stat.S_ISDIR
            if not expected_type(mode):
                return None
        try:
            self._state._snapshot_service._resolve_snapshot_relative_path(snapshot_dir, Path(*parts))
        except (ValueError, FileNotFoundError):
            return None

        try:
            root_fd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                parent_fd = self._open_working_directory(root_fd, parts[:-1], create=False)
            finally:
                os.close(root_fd)
            try:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            if exc.errno in ABSENT_WORKING_ERRNOS:
                return None
            raise
        try:
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
        except BaseException:
            os.close(fd)
            raise
        if not regular:
            os.close(fd)
            return None
        return fd

    def restore(self, snapshot_id: str, snapshot_dir: Path | str, version_id: str,
                expected_working_hash: Optional[str] = None) -> dict[str, Any]:
        """Write a version's files into the working tree and leave it uncommitted; return the restore result."""
        snapshot_dir = Path(snapshot_dir)
        state = self._state
        reresolved = False
        while True:
            try:
                snapshot_id = state.settle_external_changes(snapshot_id, snapshot_dir)
            except VersioningUnavailableError as exc:
                if exc.reason == 'sidecar':
                    raise
                raise RestoreFailedError("External changes could not be settled before the restore") from exc
            except Exception as exc:
                raise RestoreFailedError("External changes could not be settled before the restore") from exc
            key = state.id_key(snapshot_id)
            try:
                manifest, consumable_paths, restored_from, noop = state.begin_restore_write(
                    key, snapshot_dir, version_id, expected_working_hash,
                )
            except NameMismatchError:
                if reresolved:
                    raise IdentityResolutionError(
                        f"Snapshot {snapshot_dir.name} shares its state row with another directory"
                    )
                reresolved = True
                snapshot_id = state.resolve_snapshot_identity(snapshot_dir)
                continue
            break

        if not noop:
            completed = False
            try:
                run_blocking(self._write_version_tree, snapshot_dir, manifest, consumable_paths)
                completed = True
            except (PathClashError, RestoreFailedError):
                raise
            except Exception as exc:
                raise RestoreFailedError("The working tree could not be rewritten") from exc
            finally:
                state.end_api_write(key, snapshot_dir, restored_from=restored_from if completed else None)
        return {'requires_reinitialize': True, 'restored_from': restored_from}

    def _write_version_tree(self, snapshot_dir: Path, manifest: Manifest, consumable_paths: list) -> None:
        """Verify objects and paths, then remove, prune and write the working tree (file-only work)."""
        for sha256 in sorted({sha256 for _, sha256, _ in manifest.files}):
            if not self.verify_object(sha256):
                raise RestoreFailedError(f"History object {sha256} is missing or corrupt")
        manifest_paths = {path for path, _, _ in manifest.files}
        removals = [path for path in consumable_paths if path not in manifest_paths]
        removal_set = set(removals)
        prune = [path for path, _, _ in manifest.files if self._check_restore_path(snapshot_dir, path, removal_set)]

        root_fd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for path in removals:
                self._remove_working_file(root_fd, path)
            for path in prune:
                self._prune_working_directory(root_fd, path)
            for path, sha256, _ in manifest.files:
                self._write_working_file(root_fd, path, sha256)
        finally:
            os.close(root_fd)

    def _check_restore_path(self, snapshot_dir: Path, path: str, removal_set: set) -> bool:
        """Raise PathClashError unless restore may write path; return whether a directory there must be pruned."""
        parts = path.split('/')
        if any(part in ('', '.', '..') for part in parts):
            raise PathClashError(path)
        prune = False
        current = snapshot_dir
        for index, part in enumerate(parts):
            current = current / part
            relative = '/'.join(parts[:index + 1])
            last = index == len(parts) - 1
            try:
                mode = os.lstat(current).st_mode
            except FileNotFoundError:
                break
            if stat.S_ISLNK(mode):
                raise PathClashError(relative)
            if stat.S_ISDIR(mode):
                if last:
                    if self._holds_entries_outside(current, relative, removal_set):
                        raise PathClashError(relative)
                    prune = True
                continue
            if last:
                if not stat.S_ISREG(mode):
                    raise PathClashError(relative)
            elif relative not in removal_set:
                raise PathClashError(relative)
            break
        try:
            self._state._snapshot_service._resolve_snapshot_relative_path(snapshot_dir, Path(*parts))
        except ValueError as exc:
            raise PathClashError(path) from exc
        return prune

    def _holds_entries_outside(self, directory: Path, relative: str, removal_set: set) -> bool:
        """Return whether a directory holds, recursively by lstat, a non-directory entry outside removal_set."""
        with os.scandir(directory) as iterator:
            entries = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in iterator]
        for name, is_directory in entries:
            entry_relative = f"{relative}/{name}"
            if is_directory:
                if self._holds_entries_outside(directory / name, entry_relative, removal_set):
                    return True
            elif entry_relative not in removal_set:
                return True
        return False

    @staticmethod
    def _open_working_directory(root_fd: int, parts: list, create: bool) -> int:
        """Open a directory below root_fd component by component without following symlinks."""
        fd = os.dup(root_fd)
        try:
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _remove_working_file(self, root_fd: int, path: str) -> None:
        """Unlink a listed consumable file when it is still a regular file reached through real directories."""
        parts = path.split('/')
        try:
            parent_fd = self._open_working_directory(root_fd, parts[:-1], create=False)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                return
            raise
        try:
            if stat.S_ISREG(os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False).st_mode):
                os.unlink(parts[-1], dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)

    def _prune_working_directory(self, root_fd: int, path: str) -> None:
        parts = path.split('/')
        parent_fd = self._open_working_directory(root_fd, parts[:-1], create=False)
        try:
            self._remove_directory_tree(parent_fd, parts[-1])
        finally:
            os.close(parent_fd)

    def _remove_directory_tree(self, parent_fd: int, name: str) -> None:
        """Remove a tree of directories bottom-up with rmdir, so a non-directory entry makes it fail."""
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            with os.scandir(fd) as iterator:
                children = [entry.name for entry in iterator if entry.is_dir(follow_symlinks=False)]
            for child in children:
                self._remove_directory_tree(fd, child)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=parent_fd)

    def _write_working_file(self, root_fd: int, path: str, sha256: str) -> None:
        """Copy an object to path through a temporary file and os.replace, keeping an existing file's mode."""
        parts = path.split('/')
        name = parts[-1]
        parent_fd = self._open_working_directory(root_fd, parts[:-1], create=True)
        temp_name: Optional[str] = f".restore-{uuid.uuid4().hex}.tmp"
        try:
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False).st_mode
                existing_mode = stat.S_IMODE(existing) if stat.S_ISREG(existing) else None
            except FileNotFoundError:
                existing_mode = None
            temp_fd = os.open(
                temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666, dir_fd=parent_fd,
            )
            hasher = hashlib.sha256()
            with os.fdopen(temp_fd, 'wb') as target, self.open_object(sha256) as source:
                while True:
                    chunk = source.read(HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    target.write(chunk)
                target.flush()
                if existing_mode is not None:
                    os.fchmod(target.fileno(), existing_mode)
                os.fsync(target.fileno())
            if hasher.hexdigest() != sha256:
                raise RestoreFailedError(f"History object {sha256} changed while it was restored")
            os.replace(temp_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            temp_name = None
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)

    def _delete_version_rows(self, session, version_ids: list) -> set[str]:
        """Delete version rows with their manifest rows; return the object hashes they referenced."""
        candidates: set[str] = set()
        for chunk in _chunks(version_ids):
            candidates.update(session.execute(
                select(SnapshotVersionFile.sha256).where(SnapshotVersionFile.version_id.in_(chunk)).distinct()
            ).scalars())
        for chunk in _chunks(version_ids):
            session.execute(delete(SnapshotVersionFile).where(SnapshotVersionFile.version_id.in_(chunk)))
        for chunk in _chunks(version_ids):
            session.execute(delete(SnapshotVersion).where(SnapshotVersion.version_id.in_(chunk)))
        return candidates

    def _collect_candidates(self, candidates: set[str], skip_grace: bool, context: str) -> None:
        if not candidates:
            return
        try:
            self.gc_unreferenced(candidates, skip_grace=skip_grace)
        except Exception as exc:
            logger.warning(
                "Snapshot history garbage collection after %s failed (%s); the leftovers are collected by the "
                "next run",
                context,
                type(exc).__name__,
            )

    def delete_versions(self, snapshot_id: str, snapshot_dir: Path | str, mode: str, count: Optional[int] = None,
                        version_id: Optional[str] = None, expected_head: Any = EXPECTED_HEAD_UNSET,
                        expected_total: Optional[int] = None,
                        expected_unavailable: Optional[str] = None,
                        owner_scope: Optional[str] = None) -> dict[str, Any]:
        """Delete versions in one transaction, move head and collect unreferenced objects; return {deleted, head}."""
        if mode not in DELETION_MODES:
            raise ValueError(f"Unknown deletion mode: {mode}")
        if mode in ('oldest', 'newest') and (isinstance(count, bool) or not isinstance(count, int) or count < 1):
            raise ValueError("count must be a positive integer")
        snapshot_dir = Path(snapshot_dir)
        state = self._state
        reresolved = False
        while True:
            state.check_sidecar_identity(snapshot_dir, snapshot_id)
            with history_lock:
                if state.write_in_progress(state.id_key(snapshot_id), state.dir_key(snapshot_dir)):
                    outcome = ('in_progress',)
                else:
                    if not snapshot_dir.is_dir():
                        raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir.name}")
                    with self._db.get_db_session() as session:
                        outcome = self._deletion_transaction(
                            session, snapshot_id, snapshot_dir, mode, count, version_id,
                            expected_head, expected_total, expected_unavailable,
                        )
                    if outcome[0] == 'deleted' and mode == 'all':
                        state.clear_versioning_unavailable(state.id_key(snapshot_id))
            if outcome[0] != 'mismatch':
                break
            if reresolved:
                raise IdentityResolutionError(f"Snapshot {snapshot_dir.name} shares its state row with another directory")
            reresolved = True
            snapshot_id = state.resolve_snapshot_identity(snapshot_dir)

        tag = outcome[0]
        if tag == 'in_progress':
            raise VersionConflictError("An API write is in progress for this snapshot")
        if tag == 'head_conflict':
            raise VersionConflictError("The head version changed since it was displayed")
        if tag == 'total_conflict':
            raise VersionConflictError("The version count changed since it was displayed")
        if tag == 'unavailable_conflict':
            raise VersionConflictError("The snapshot is not marked unavailable for the expected reason")
        if tag == 'not_found':
            raise VersionNotFoundError("Version not found for this snapshot")
        _, deleted, head, candidates = outcome
        self._collect_candidates(candidates, skip_grace=False, context='a version deletion')
        self._evict_unreferenced(owner_scope, context='a version deletion')
        return {'deleted': deleted, 'head': head}

    def _deletion_transaction(self, session, snapshot_id: str, snapshot_dir: Path, mode: str,
                              count: Optional[int], version_id: Optional[str], expected_head: Any,
                              expected_total: Optional[int], expected_unavailable: Optional[str]) -> tuple:
        state = self._state
        namespace = state.namespace
        row = session.execute(
            select(SnapshotStateRow).where(
                SnapshotStateRow.namespace == namespace,
                SnapshotStateRow.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if row is not None and row.snapshot_name != snapshot_dir.name:
            return ('mismatch',)
        if expected_head is not EXPECTED_HEAD_UNSET and expected_head != (row.head_version_id if row else None):
            return ('head_conflict',)
        if (
            expected_unavailable is not None
            and state.unavailable_reason(snapshot_id, snapshot_dir.name) != expected_unavailable
        ):
            return ('unavailable_conflict',)

        versions = session.execute(
            select(SnapshotVersion.version_id, SnapshotVersion.seq, SnapshotVersion.content_hash).where(
                SnapshotVersion.namespace == namespace,
                SnapshotVersion.snapshot_id == snapshot_id,
            ).order_by(SnapshotVersion.seq)
        ).all()
        if mode in ('oldest', 'newest') and expected_total is not None and expected_total != len(versions):
            return ('total_conflict',)
        if mode == 'single':
            victims = [version for version in versions if version.version_id == version_id]
            if not victims:
                return ('not_found',)
        elif mode == 'all':
            victims = list(versions)
        elif mode == 'oldest':
            victims = list(versions[:count])
        else:
            victims = list(versions[max(len(versions) - count, 0):])

        victim_ids = {version.version_id for version in victims}
        remaining = [version for version in versions if version.version_id not in victim_ids]
        head = remaining[-1] if remaining else None
        if row is not None:
            row.head_version_id = head.version_id if head is not None else None
            if row.restored_from_version_id in victim_ids:
                row.restored_from_version_id = None
            if head is not None and head.content_hash == row.content_hash:
                row.pending_external = False
                row.restored_from_version_id = None
                row.restored_from_seq = None
            row.updated_at = _utcnow()
            session.flush()
        candidates = self._delete_version_rows(session, sorted(victim_ids))
        head_ref = version_ref(head.version_id, head.seq) if head is not None else None
        return ('deleted', len(victim_ids), head_ref, candidates)

    def _remove_staging_copy(self, snapshot_id: str, snapshot_name: str) -> None:
        state = self._state
        if not state.namespace_valid:
            return
        try:
            root = state.staging_root()
            container = root / snapshot_id
            assert_under_root(container, root)
            if os.path.lexists(container):
                shutil.rmtree(container)
        except Exception as exc:
            logger.warning(
                "Snapshot %s: its staging copy could not be removed after the deletion (%s)",
                snapshot_name,
                type(exc).__name__,
            )

    def remove_staging_copy(self, snapshot_id: str, snapshot_name: str) -> None:
        """Remove a deleted snapshot's staging container; the caller holds the Batfish request lock. Never raises."""
        self._remove_staging_copy(snapshot_id, snapshot_name)

    def delete_all_for_snapshot(self, snapshot_id: str, deleted_name: str, owner_scope: Optional[str] = None,
                                remove_staging: bool = True) -> bool:
        """Purge the history of a snapshot deleted through the API; return whether it was purged. Never raises."""
        try:
            with history_lock:
                with self._db.get_db_session() as session:
                    outcome = self._purge_deleted_snapshot_rows(session, snapshot_id, deleted_name)
        except Exception as exc:
            logger.warning(
                "Snapshot %s: its history could not be purged after the deletion (%s); the rows are left to the "
                "orphan scan and the admin purge",
                deleted_name,
                type(exc).__name__,
            )
            return False
        if outcome[0] == 'kept':
            logger.warning(
                "Snapshot %s: its history was not purged because it now belongs to snapshot %s",
                deleted_name,
                outcome[1],
            )
            return False
        if remove_staging:
            self._remove_staging_copy(snapshot_id, deleted_name)
        self._collect_candidates(outcome[1], skip_grace=True, context='a snapshot deletion')
        self._evict_unreferenced(owner_scope, context='a snapshot deletion')
        return True

    def _purge_deleted_snapshot_rows(self, session, snapshot_id: str, deleted_name: str) -> tuple:
        namespace = self._state.namespace
        row = session.execute(
            select(SnapshotStateRow).where(
                SnapshotStateRow.namespace == namespace,
                SnapshotStateRow.snapshot_id == snapshot_id,
            )
        ).scalar_one_or_none()
        if row is not None and row.snapshot_name != deleted_name:
            stored_dir = self._state._stored_name_directory(row.snapshot_name)
            if stored_dir is not None and os.path.lexists(stored_dir):
                return ('kept', row.snapshot_name)
        version_ids = list(session.execute(
            select(SnapshotVersion.version_id).where(
                SnapshotVersion.namespace == namespace,
                SnapshotVersion.snapshot_id == snapshot_id,
            )
        ).scalars())
        session.execute(delete(SnapshotStateRow).where(
            SnapshotStateRow.namespace == namespace,
            SnapshotStateRow.snapshot_id == snapshot_id,
        ))
        return ('purged', self._delete_version_rows(session, version_ids))

    def purge_orphans(self, older_than_days: int) -> dict[str, Any]:
        """Purge the current namespace's rows orphaned for at least older_than_days; return {purged, last_seen_at}."""
        namespace = self._state.namespace
        result = {'purged': 0, 'last_seen_at': None}
        try:
            cutoff = _utcnow() - timedelta(days=older_than_days)
        except OverflowError:
            return result
        with history_lock:
            with self._db.get_db_session() as session:
                rows = session.execute(
                    select(SnapshotStateRow.snapshot_id, SnapshotStateRow.snapshot_name, SnapshotStateRow.missing_since)
                    .where(SnapshotStateRow.namespace == namespace, SnapshotStateRow.missing_since.is_not(None))
                ).all()
        expired = [tuple(row) for row in rows if _as_utc(row.missing_since) <= cutoff]
        if not expired:
            return result

        view = run_blocking(self.read_store_view)
        self._warn_unreadable_sidecars(view)
        orphans = [
            (snapshot_id, snapshot_name, missing_since)
            for snapshot_id, snapshot_name, missing_since in expired
            if snapshot_id not in view.holders and snapshot_name not in view.unreadable
        ]
        if not orphans:
            return result

        purged = 0
        skipped: list[str] = []
        candidates: set[str] = set()
        store_changed = False
        with history_lock:
            if self.store_directory_set() != view.directories:
                store_changed = True
            else:
                with self._db.get_db_session() as session:
                    for snapshot_id, snapshot_name, missing_since in orphans:
                        deleted = session.execute(delete(SnapshotStateRow).where(
                            SnapshotStateRow.namespace == namespace,
                            SnapshotStateRow.snapshot_id == snapshot_id,
                            SnapshotStateRow.snapshot_name == snapshot_name,
                            SnapshotStateRow.missing_since == missing_since,
                        )).rowcount
                        if deleted != 1:
                            skipped.append(snapshot_name)
                            continue
                        version_ids = list(session.execute(
                            select(SnapshotVersion.version_id).where(
                                SnapshotVersion.namespace == namespace,
                                SnapshotVersion.snapshot_id == snapshot_id,
                            )
                        ).scalars())
                        candidates |= self._delete_version_rows(session, version_ids)
                        purged += 1
        if store_changed:
            logger.warning(
                "Snapshot history orphan purge removed nothing because the snapshot store changed while it was "
                "checked; repeat the purge",
            )
            return result
        for snapshot_name in skipped:
            logger.warning(
                "Snapshot history orphan purge skipped the history of snapshot %s because it changed during the purge",
                snapshot_name,
            )
        self._collect_candidates(candidates, skip_grace=True, context='an orphan purge')
        self._sweep_result_cache(context='an orphan purge')
        if purged:
            logger.info("Purged the snapshot history of %d orphaned snapshots in namespace %s", purged, namespace)
        result['purged'] = purged
        return result

    def purge_namespace(self, namespace: str) -> tuple[int, Optional[str]]:
        """Purge every row of a non-current namespace and its staging folder; return (purged, last_seen_at)."""
        if namespace == self._state.namespace:
            raise CurrentNamespaceError("The current namespace cannot be purged")
        with history_lock:
            with self._db.get_db_session() as session:
                outcome = self._purge_namespace_rows(session, namespace)
        if outcome[0] == 'current':
            raise CurrentNamespaceError("The current namespace cannot be purged")
        if outcome[0] == 'not_found':
            raise NamespaceNotFoundError(f"Namespace {namespace} has no snapshot history")
        _, purged, last_seen_at, candidates = outcome
        self._remove_namespace_staging(namespace)
        self._collect_candidates(candidates, skip_grace=True, context='a namespace purge')
        self._sweep_result_cache(context='a namespace purge')
        logger.info("Purged the snapshot history of namespace %s: %d snapshots", namespace, purged)
        return purged, last_seen_at

    @staticmethod
    def _matched_namespaces(session, namespace: str) -> set[str]:
        """Return the stored namespace values of every row the database matches for the requested namespace."""
        matched = set(session.execute(
            select(HistoryNamespace.namespace).where(HistoryNamespace.namespace == namespace)
        ).scalars())
        for model in (SnapshotStateRow, SnapshotVersion):
            matched.update(session.execute(
                select(model.namespace).where(model.namespace == namespace).distinct()
            ).scalars())
        return matched

    def _purge_namespace_rows(self, session, namespace: str) -> tuple:
        if self._state.namespace in self._matched_namespaces(session, namespace):
            return ('current',)
        meta = session.get(HistoryNamespace, namespace)
        version_ids = list(session.execute(
            select(SnapshotVersion.version_id).where(SnapshotVersion.namespace == namespace)
        ).scalars())
        purged = session.execute(delete(SnapshotStateRow).where(SnapshotStateRow.namespace == namespace)).rowcount
        if meta is None and not version_ids and not purged:
            return ('not_found',)
        last_seen_at = _isoformat(meta.last_seen_at) if meta is not None else None
        candidates = self._delete_version_rows(session, version_ids)
        if meta is not None:
            session.delete(meta)
        return ('purged', purged, last_seen_at, candidates)

    def _remove_namespace_staging(self, namespace: str) -> None:
        state = self._state
        problem = state.namespace_problem(namespace)
        if problem:
            logger.warning("Staging directory of namespace %s is not removed because %s", namespace, problem)
            return
        try:
            staging = state.data_dir / namespace / 'staging'
            assert_under_root(staging, state.data_dir)
            if os.path.lexists(staging):
                shutil.rmtree(staging)
        except Exception as exc:
            logger.warning(
                "Staging directory of namespace %s could not be removed (%s)", namespace, type(exc).__name__,
            )

    @property
    def auth_enabled(self) -> bool:
        return bool(getattr(self.settings, 'AUTH_ENABLED', False))

    def _read_owner_scopes(self, rows: list) -> dict:
        """Map (snapshot_id, snapshot_name) to the owner scope read from the named directory's sidecar (file-only work)."""
        state = self._state
        scopes = {}
        for snapshot_id, snapshot_name in rows:
            directory = state._stored_name_directory(snapshot_name)
            if directory is None:
                continue
            try:
                metadata, sidecar_id = state._read_sidecar(directory)
                if metadata is None or sidecar_id != snapshot_id:
                    continue
                owner = state._snapshot_service._normalize_owner_user_id(metadata.get('owner_user_id'))
            except (OSError, ValueError):
                continue
            scopes[(snapshot_id, snapshot_name)] = owner_scope_for(True, self.db_id, owner)
        return scopes

    def referenced_hashes_by_scope(self, db=None) -> dict[str, set[str]]:
        """Return the content hashes referenced per owner scope: every state and version row of the database under ''
        under AUTH OFF; under AUTH ON the current namespace's rows whose directory's sidecar carries their id, under
        the owner scope read from that sidecar."""
        db = db or self._db
        with history_lock:
            with db.get_db_session() as session:
                state_rows = session.execute(
                    select(
                        SnapshotStateRow.namespace, SnapshotStateRow.snapshot_id,
                        SnapshotStateRow.snapshot_name, SnapshotStateRow.content_hash,
                    )
                ).all()
                version_rows = session.execute(
                    select(SnapshotVersion.namespace, SnapshotVersion.snapshot_id, SnapshotVersion.content_hash)
                    .distinct()
                ).all()
        if not self.auth_enabled:
            hashes = {row.content_hash for row in state_rows if row.content_hash}
            hashes.update(row.content_hash for row in version_rows if row.content_hash)
            return {'': hashes}

        namespace = self._state.namespace
        names = {
            row.snapshot_id: row.snapshot_name for row in state_rows if row.namespace == namespace
        }
        scopes = run_blocking(self._read_owner_scopes, sorted(names.items()))
        by_id = {snapshot_id: scopes.get((snapshot_id, name)) for snapshot_id, name in names.items()}
        referenced: dict[str, set[str]] = {}
        for row in list(state_rows) + list(version_rows):
            scope = by_id.get(row.snapshot_id) if row.namespace == namespace else None
            if scope and row.content_hash:
                referenced.setdefault(scope, set()).add(row.content_hash)
        return referenced

    def working_hash_shared(self, snapshot_id: str, content_hash: str, owner_scope: str) -> bool:
        """Return whether another snapshot has content_hash as its working hash: any state row of the database under
        AUTH OFF, a current namespace row whose sidecar carries the same owner scope under AUTH ON."""
        with history_lock:
            with self._db.get_db_session() as session:
                rows = session.execute(
                    select(SnapshotStateRow.namespace, SnapshotStateRow.snapshot_id, SnapshotStateRow.snapshot_name)
                    .where(SnapshotStateRow.content_hash == content_hash)
                ).all()
        others = [row for row in rows if not (row.namespace == self._state.namespace and row.snapshot_id == snapshot_id)]
        if not self.auth_enabled:
            return bool(others)
        current = [
            (row.snapshot_id, row.snapshot_name) for row in others if row.namespace == self._state.namespace
        ]
        if not current:
            return False
        scopes = run_blocking(self._read_owner_scopes, current)
        return any(scope == owner_scope for scope in scopes.values())

    def _evict_unreferenced(self, owner_scope: Optional[str], context: str) -> None:
        cache = self.result_cache
        if cache is None or owner_scope is None or cache.forced_off:
            return
        try:
            referenced = self.referenced_hashes_by_scope().get(owner_scope, set())
            cache.evict_unreferenced(owner_scope, referenced)
        except Exception as exc:
            logger.warning(
                "Result cache eviction after %s failed (%s); the entries are swept by the next maintenance run",
                context,
                type(exc).__name__,
            )

    def _sweep_result_cache(self, db=None, context: str = 'maintenance') -> None:
        cache = self.result_cache
        if cache is None or not self.db_id or cache.forced_off:
            return
        try:
            cache.sweep_unreferenced(self.db_id, self.referenced_hashes_by_scope(db))
        except Exception as exc:
            logger.warning("Result cache sweep during %s failed (%s)", context, type(exc).__name__)

    def _list_store_objects(self) -> list[str]:
        objects_dir = self.objects_dir
        found = []
        if not objects_dir.is_dir():
            return found
        for prefix_entry in os.scandir(objects_dir):
            if not prefix_entry.is_dir(follow_symlinks=False):
                continue
            for object_entry in os.scandir(prefix_entry.path):
                if _SHA256_PATTERN.fullmatch(object_entry.name) and object_entry.name[:2] == prefix_entry.name:
                    found.append(object_entry.name)
        return found

    def _empty_trash(self) -> list[str]:
        failures = []
        trash_dir = self.trash_dir
        if not trash_dir.is_dir():
            return failures
        for entry in os.scandir(trash_dir):
            try:
                if entry.is_dir(follow_symlinks=False):
                    shutil.rmtree(entry.path)
                else:
                    os.unlink(entry.path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                failures.append(type(exc).__name__)
        return failures

    def gc_unreferenced(self, candidates: Optional[Iterable[str]] = None, skip_grace: bool = False, db=None) -> int:
        """Move unreferenced objects to trash under history_lock, then empty the trash outside it; return how many
        objects were collected."""
        if not self.db_id:
            return 0
        db = db or self._db
        if candidates is None:
            stored = run_blocking(self._list_store_objects)
            with history_lock:
                with db.get_db_session() as session:
                    orphan_rows = session.execute(
                        select(HistoryObject.sha256).where(
                            ~select(SnapshotVersionFile.id)
                            .where(SnapshotVersionFile.sha256 == HistoryObject.sha256)
                            .exists()
                        )
                    ).scalars().all()
            candidates = set(stored) | set(orphan_rows)
        candidate_list = sorted({sha for sha in candidates if isinstance(sha, str) and _SHA256_PATTERN.fullmatch(sha)})

        grace_seconds = float(self.settings.HISTORY_GC_GRACE_SECONDS)
        collected: list[str] = []
        move_failures: list[str] = []
        db_failure: Optional[Exception] = None
        if candidate_list:
            trash_dir = self.trash_dir
            make_private_dirs(trash_dir)
            with history_lock:
                referenced: set[str] = set()
                with db.get_db_session() as session:
                    for chunk in _chunks(candidate_list):
                        referenced.update(session.execute(
                            select(SnapshotVersionFile.sha256).where(SnapshotVersionFile.sha256.in_(chunk))
                        ).scalars())
                now = time.time()
                for sha256 in candidate_list:
                    if sha256 in referenced:
                        continue
                    object_path = self.object_path(sha256)
                    try:
                        object_stat = os.lstat(object_path)
                    except FileNotFoundError:
                        collected.append(sha256)
                        continue
                    if not skip_grace and now - object_stat.st_mtime < grace_seconds:
                        continue
                    try:
                        os.rename(object_path, trash_dir / f"{sha256}.{uuid.uuid4().hex}")
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        move_failures.append(type(exc).__name__)
                        continue
                    collected.append(sha256)
                if collected:
                    try:
                        with db.get_db_session() as session:
                            for chunk in _chunks(collected):
                                session.execute(delete(HistoryObject).where(HistoryObject.sha256.in_(chunk)))
                    except Exception as exc:
                        db_failure = exc

        trash_failures = run_blocking(self._empty_trash)
        if move_failures:
            logger.warning(
                "Snapshot history garbage collection could not move %d objects to trash (%s); they are retried "
                "by the next run",
                len(move_failures),
                ', '.join(sorted(set(move_failures))),
            )
        if trash_failures:
            logger.warning(
                "Snapshot history garbage collection could not remove %d trash entries (%s); they are retried by "
                "the next run",
                len(trash_failures),
                ', '.join(sorted(set(trash_failures))),
            )
        if db_failure is not None:
            raise db_failure
        if collected:
            logger.info(
                "Snapshot history garbage collection collected %d unreferenced objects; their files were moved to "
                "trash or were already absent",
                len(collected),
            )
        return len(collected)

    def store_directory_set(self) -> frozenset:
        """Return (name, inode) of every directory in the snapshot store root, by scandir and lstat."""
        directories = set()
        with os.scandir(self._state.snapshots_root) as iterator:
            for entry in iterator:
                try:
                    if entry.is_dir():
                        directories.add((entry.name, os.lstat(entry.path).st_ino))
                except FileNotFoundError:
                    continue
        return frozenset(directories)

    def read_store_view(self) -> StoreView:
        """Read the sidecar of every directory in the snapshot store root once (file-only work)."""
        state = self._state
        directories = self.store_directory_set()
        holders: dict[str, list[str]] = {}
        unreadable = set()
        for name, _ in sorted(directories):
            try:
                _, snapshot_id = state._read_sidecar(state.snapshots_root / name)
            except (OSError, ValueError):
                unreadable.add(name)
                continue
            if is_canonical_uuid4(snapshot_id):
                holders.setdefault(snapshot_id, []).append(name)
        return StoreView(holders=holders, unreadable=frozenset(unreadable), directories=directories)

    @staticmethod
    def _warn_unreadable_sidecars(view: StoreView) -> None:
        for name in sorted(view.unreadable):
            logger.warning(
                "Metadata sidecar of snapshot %s cannot be read or parsed; its snapshot history is treated as present",
                name,
            )

    def touch_namespace(self, db=None) -> bool:
        """Upsert the current namespace's history_namespaces row; return whether the row was created."""
        state = self._state
        if state.global_unavailable_reason():
            return False
        db = db or self._db
        now = _utcnow()
        with history_lock:
            with db.get_db_session() as session:
                row = session.get(HistoryNamespace, state.namespace)
                created = row is None
                if created:
                    session.add(HistoryNamespace(namespace=state.namespace, first_seen_at=now, last_seen_at=now))
                else:
                    row.last_seen_at = now
        return created

    def warn_namespace_change(self) -> None:
        """Log one WARNING when a snapshot of the current store has history rows under another namespace."""
        state = self._state
        if state.global_unavailable_reason():
            return
        snapshot_ids = sorted(run_blocking(self.read_store_view).holders)
        if not snapshot_ids:
            return
        details = []
        with history_lock:
            with self._db.get_db_session() as session:
                namespaces: set[str] = set()
                for chunk in _chunks(snapshot_ids):
                    namespaces.update(session.execute(
                        select(SnapshotStateRow.namespace).where(
                            SnapshotStateRow.snapshot_id.in_(chunk),
                            SnapshotStateRow.namespace != state.namespace,
                        ).distinct()
                    ).scalars())
                for namespace in sorted(namespaces):
                    rows = session.execute(
                        select(func.count()).select_from(SnapshotStateRow).where(SnapshotStateRow.namespace == namespace)
                    ).scalar_one()
                    meta = session.get(HistoryNamespace, namespace)
                    last_seen_at = _isoformat(meta.last_seen_at) if meta is not None else None
                    details.append(f"namespace={namespace} last_seen_at={last_seen_at} rows={rows}")
        if details:
            logger.warning(
                "Snapshots of the current store have history under other namespaces (%s). If this deployment "
                "changed its namespace, set DEPLOYMENT_ID to the previous namespace to restore that history, or "
                "purge the detached namespace through DELETE /api/admin/snapshot-history/orphans; if the snapshot "
                "folders were copied from another stack sharing the database, no action is needed.",
                '; '.join(details),
            )

    def list_namespaces(self) -> dict[str, Any]:
        """Return {items: [{namespace, current, first_seen_at, last_seen_at, rows}]} for every namespace."""
        current = self._state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                seen = {
                    row.namespace: (row.first_seen_at, row.last_seen_at)
                    for row in session.execute(select(HistoryNamespace)).scalars()
                }
                counts = dict(session.execute(
                    select(SnapshotStateRow.namespace, func.count()).group_by(SnapshotStateRow.namespace)
                ).all())
                versioned = set(session.execute(select(SnapshotVersion.namespace).distinct()).scalars())
        items = []
        for namespace in sorted(set(seen) | set(counts) | versioned):
            first_seen_at, last_seen_at = seen.get(namespace, (None, None))
            items.append({
                'namespace': namespace,
                'current': namespace == current,
                'first_seen_at': _isoformat(first_seen_at),
                'last_seen_at': _isoformat(last_seen_at),
                'rows': counts.get(namespace, 0),
            })
        return {'items': items}

    def scan_orphans(self, db=None, startup: bool = False) -> Optional[dict[str, Any]]:
        """Fix moved names and set or clear missing_since on the current namespace's rows."""
        state = self._state
        if state.global_unavailable_reason():
            return None
        if startup and state.marker_created:
            return {'skipped': True}
        db = db or self._db
        namespace = state.namespace
        with history_lock:
            with db.get_db_session() as session:
                rows = session.execute(
                    select(SnapshotStateRow.snapshot_id, SnapshotStateRow.snapshot_name, SnapshotStateRow.missing_since)
                    .where(SnapshotStateRow.namespace == namespace)
                ).all()
        view = run_blocking(self.read_store_view)
        if not view.directories:
            logger.info("Snapshot history orphan scan skipped: the snapshot store holds no snapshot directories")
            return {'skipped': True}
        self._warn_unreadable_sidecars(view)

        now = _utcnow()
        changes = []
        for snapshot_id, snapshot_name, missing_since in rows:
            holders = view.holders.get(snapshot_id, [])
            held_by_name = snapshot_name in view.unreadable or snapshot_name in holders
            held = held_by_name or bool(holders)
            values: dict[str, Any] = {}
            if not held_by_name and len(holders) == 1:
                values['snapshot_name'] = holders[0]
            if held and missing_since is not None:
                values['missing_since'] = None
            elif not held and missing_since is None:
                values['missing_since'] = now
            if values:
                changes.append((snapshot_id, snapshot_name, values))

        applied = {'skipped': False, 'renamed': 0, 'marked': 0, 'cleared': 0}
        if changes:
            with history_lock:
                with db.get_db_session() as session:
                    for snapshot_id, snapshot_name, values in changes:
                        updated = session.execute(update(SnapshotStateRow).where(
                            SnapshotStateRow.namespace == namespace,
                            SnapshotStateRow.snapshot_id == snapshot_id,
                            SnapshotStateRow.snapshot_name == snapshot_name,
                        ).values(**values)).rowcount
                        if updated != 1:
                            continue
                        if 'snapshot_name' in values:
                            applied['renamed'] += 1
                        if 'missing_since' in values:
                            applied['marked' if values['missing_since'] is not None else 'cleared'] += 1
        if applied['renamed'] or applied['marked'] or applied['cleared']:
            logger.info(
                "Snapshot history orphan scan in namespace %s: %d renamed, %d marked missing, %d found again",
                namespace,
                applied['renamed'],
                applied['marked'],
                applied['cleared'],
            )
        return applied

    def _warn_startup_orphans(self) -> None:
        namespace = self._state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                orphans = session.execute(
                    select(SnapshotStateRow.snapshot_name, SnapshotStateRow.snapshot_id, SnapshotStateRow.missing_since)
                    .where(SnapshotStateRow.namespace == namespace, SnapshotStateRow.missing_since.is_not(None))
                    .order_by(SnapshotStateRow.snapshot_name)
                ).all()
        if orphans:
            logger.warning(
                "Snapshot history of %d snapshots in namespace %s is orphaned because their directories are "
                "missing: %s. Purge it through DELETE /api/admin/snapshot-history/orphans once the snapshots are "
                "not expected to return.",
                len(orphans),
                namespace,
                ', '.join(
                    f"{name} (snapshot_id={snapshot_id}, missing_since={_isoformat(missing_since)})"
                    for name, snapshot_id, missing_since in orphans
                ),
            )

    def schedule_periodic_gc(self) -> bool:
        """Start the hourly maintenance run when due (inline for in-memory SQLite, else in a worker); never raises."""
        try:
            if self._db is None:
                return False
            now = time.monotonic()
            with self._periodic_lock:
                if self._periodic_running or now - self._last_periodic_run < PERIODIC_MAINTENANCE_INTERVAL_SECONDS:
                    return False
                self._last_periodic_run = now
                self._periodic_running = True
            try:
                if is_in_memory_sqlite(self._db.database_url):
                    self._run_periodic_worker(own_engine=False)
                elif _gevent_threading_patched():
                    import gevent
                    self.periodic_worker = gevent.spawn(self._run_periodic_worker, own_engine=False)
                else:
                    worker = threading.Thread(
                        target=self._run_periodic_worker,
                        kwargs={'own_engine': True},
                        name='snapshot-history-maintenance',
                        daemon=True,
                    )
                    self.periodic_worker = worker
                    worker.start()
            except BaseException:
                with self._periodic_lock:
                    self._periodic_running = False
                raise
            return True
        except Exception as exc:
            logger.warning("Hourly snapshot history maintenance could not be started (%s)", type(exc).__name__)
            return False

    def _run_periodic_worker(self, own_engine: bool) -> None:
        manager = None
        try:
            db = self._db
            if own_engine:
                manager = db = self._db.create_null_pool_manager()
            self.run_periodic_tasks(db)
        except Exception as exc:
            logger.warning("Hourly snapshot history maintenance failed (%s)", type(exc).__name__)
        finally:
            if manager is not None:
                manager.engine.dispose()
            with self._periodic_lock:
                self._periodic_running = False

    def run_periodic_tasks(self, db=None) -> None:
        """Upsert the namespace row, scan for orphans, collect unreferenced objects and sweep the result cache."""
        state = self._state
        if not self.db_id or state.storage_overlap or state.data_dir_fell_back:
            return
        db = db or self._db
        if not state.global_unavailable_reason():
            try:
                self.touch_namespace(db)
            except Exception as exc:
                logger.warning("Hourly snapshot history namespace upsert failed (%s)", type(exc).__name__)
            try:
                self.scan_orphans(db)
            except Exception as exc:
                logger.warning("Hourly snapshot history orphan scan failed (%s)", type(exc).__name__)
        try:
            self.gc_unreferenced(db=db)
        finally:
            self._sweep_result_cache(db=db, context='the hourly maintenance')

    def _ensure_db_id(self) -> str:
        for _ in range(2):
            try:
                with history_lock:
                    with self._db.get_db_session() as session:
                        meta = session.get(HistoryMeta, 1)
                        if meta is None:
                            meta = HistoryMeta(id=1, db_id=str(uuid.uuid4()), clear_counter=0)
                            session.add(meta)
                            try:
                                session.flush()
                            except IntegrityError:
                                session.rollback()
                                continue
                        db_id = meta.db_id
            except IntegrityError:
                continue
            if not is_canonical_uuid4(db_id):
                raise ValueError("history_meta.db_id is not a canonical UUID")
            return db_id
        raise RuntimeError("history_meta.db_id could not be created")

    def check_missing_objects(self) -> None:
        """Mark snapshots whose referenced objects are missing, or the whole store when it is lost."""
        state = self._state
        namespace = state.namespace
        with history_lock:
            with self._db.get_db_session() as session:
                references = session.execute(
                    select(SnapshotVersion.snapshot_id, SnapshotVersionFile.sha256, HistoryObject.size)
                    .join(SnapshotVersionFile, SnapshotVersionFile.version_id == SnapshotVersion.version_id)
                    .join(HistoryObject, HistoryObject.sha256 == SnapshotVersionFile.sha256)
                    .where(SnapshotVersion.namespace == namespace)
                    .distinct()
                ).all()
                names = dict(session.execute(
                    select(SnapshotStateRow.snapshot_id, SnapshotStateRow.snapshot_name)
                    .where(SnapshotStateRow.namespace == namespace)
                ).all())

        accept_value = (getattr(self.settings, 'HISTORY_ACCEPT_STORE_LOSS', '') or '').strip()
        accept_matches = bool(accept_value) and accept_value == self.db_id
        if accept_value and not accept_matches:
            logger.warning(
                "HISTORY_ACCEPT_STORE_LOSS does not match the current database identity; it is ignored",
            )

        marked = 0
        if references:
            sizes: dict[str, int] = {}
            by_snapshot: dict[str, set[str]] = {}
            for snapshot_id, sha256, size in references:
                sizes[sha256] = size
                by_snapshot.setdefault(snapshot_id, set()).add(sha256)

            objects_dir = self.objects_dir
            present: dict[str, bool] = {}
            any_exists = False
            for sha256, size in sizes.items():
                try:
                    object_stat = os.stat(self.object_path(sha256))
                except FileNotFoundError:
                    present[sha256] = False
                    continue
                any_exists = True
                present[sha256] = stat.S_ISREG(object_stat.st_mode) and object_stat.st_size == size

            if (not objects_dir.is_dir() or not any_exists) and not accept_matches:
                logger.error(
                    "Snapshot history object store %s is missing or holds none of the %d objects referenced by "
                    "namespace %s; snapshot versioning is unavailable. Restore the object store (DATA_DIR or "
                    "SNAPSHOT_HISTORY_DIR), or set HISTORY_ACCEPT_STORE_LOSS to the database identity in that "
                    "path to accept the loss and reset the affected histories in the application.",
                    objects_dir,
                    len(sizes),
                    namespace,
                )
                state.mark_globally_unavailable('storage')
                return

            for snapshot_id in sorted(by_snapshot):
                if all(present.get(sha256, False) for sha256 in by_snapshot[snapshot_id]):
                    continue
                logger.error(
                    "Snapshot history objects are missing: namespace=%s snapshot_id=%s snapshot_name=%s; "
                    "versioning is unavailable for this snapshot until its history is deleted",
                    namespace,
                    snapshot_id,
                    names.get(snapshot_id),
                )
                state.mark_versioning_unavailable(state.id_key(snapshot_id), 'missing_objects')
                marked += 1

        if accept_matches:
            logger.warning(
                "HISTORY_ACCEPT_STORE_LOSS matches the current database identity: the object store loss guard is "
                "disabled and %d snapshots are marked missing_objects. Remove the variable once that count is zero.",
                state.marked_snapshot_count('missing_objects'),
            )

    def run_startup_tasks(self) -> None:
        """Create the database identity, sweep temporary directories, check the store, record the namespace,
        scan for orphans and collect garbage."""
        state = self._state
        if self._db is not None:
            try:
                self.db_id = self._ensure_db_id()
            except Exception as exc:
                logger.error(
                    "Snapshot history database identity is unavailable (%s); snapshot versioning is unavailable",
                    type(exc).__name__,
                )
                state.mark_globally_unavailable('database')
        try:
            state.cleanup_all_staging(self.db_id)
        except Exception as exc:
            logger.warning("Startup cleanup of staging and temporary directories failed: %s", type(exc).__name__)

        if not self.db_id or state.storage_overlap or state.data_dir_fell_back:
            return
        if state.namespace_valid:
            try:
                self.check_missing_objects()
            except Exception as exc:
                if is_database_error(exc, self._db):
                    failure, reason = "could not query the database", 'database'
                elif isinstance(exc, OSError):
                    failure, reason = "could not read the object store", 'storage'
                else:
                    failure, reason = "failed", 'storage'
                logger.error(
                    "Startup snapshot history object check %s (%s); snapshot versioning is unavailable",
                    failure,
                    type(exc).__name__,
                )
                state.mark_globally_unavailable(reason)
                return
        self._run_startup_namespace_tasks()
        try:
            self.gc_unreferenced()
        except Exception as exc:
            logger.warning("Startup snapshot history garbage collection failed: %s", type(exc).__name__)
        self._sweep_result_cache(context='the startup maintenance')

    def _run_startup_namespace_tasks(self) -> None:
        if self._state.global_unavailable_reason():
            return
        try:
            created = self.touch_namespace()
        except Exception as exc:
            logger.warning("Startup snapshot history namespace upsert failed: %s", type(exc).__name__)
            created = False
        if created:
            try:
                self.warn_namespace_change()
            except Exception as exc:
                logger.warning("Startup snapshot history namespace check failed: %s", type(exc).__name__)
        try:
            self.scan_orphans(startup=True)
            self._warn_startup_orphans()
        except Exception as exc:
            logger.warning("Startup snapshot history orphan scan failed: %s", type(exc).__name__)
