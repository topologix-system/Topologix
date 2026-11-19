"""Server-side result cache for parameterless Batfish query endpoints"""
import gzip
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from services.snapshot_state_service import assert_under_root, make_private_dirs, run_blocking

logger = logging.getLogger(__name__)

ENTRY_MAGIC = b'TOPOLOGIX-RESULT-CACHE 1\n'
ENTRY_SUFFIX = '.json.gz'
HEADER_READ_LIMIT = 64 * 1024
HEADER_PREFIX_SIZE = 4096
TMP_DIRNAME = 'tmp'
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def owner_scope_for(auth_enabled: bool, db_id: Optional[str], owner_user_id) -> Optional[str]:
    """Return the cache owner scope: '' under AUTH OFF, <db_id>:<owner_user_id or unowned> under AUTH ON, else None."""
    if not auth_enabled:
        return ''
    if not db_id:
        return None
    return f"{db_id}:{owner_user_id if owner_user_id is not None else 'unowned'}"


class CacheEntryError(Exception):
    """A cache entry is corrupt or unreadable, the index could not be built, or storage is disabled"""


@dataclass
class CachedEntry:
    """One stored response body"""
    content_hash: str
    key_hash: str
    endpoint_key: str
    owner_scope: str
    body: bytes
    body_sha256: str
    db_id: Optional[str]
    loaded_clear_counter: Optional[int]
    indexed_before_read: tuple = field(default=(), repr=False, compare=False)

    def plain_body(self) -> bytes:
        """Return the decompressed body; raise CacheEntryError when it cannot be decompressed."""
        try:
            return gzip.decompress(self.body)
        except (OSError, EOFError) as exc:
            raise CacheEntryError("Cached body cannot be decompressed") from exc


@dataclass
class _IndexedEntry:
    path: Path
    file_size: int
    endpoint_key: str
    batfish_version: Optional[str]
    pybatfish_version: Optional[str]
    backend_build_id: Optional[str]
    schema_version: Optional[int]
    db_id: Optional[str]
    loaded_clear_counter: Optional[int]
    pending_removal: bool = False


def _pending_entry(path: Path) -> _IndexedEntry:
    """Index entry of a file whose removal failed: never served, taken by the next sweep or eviction reaching it."""
    try:
        file_size = os.lstat(path).st_size
    except OSError:
        file_size = 0
    return _IndexedEntry(
        path=path,
        file_size=file_size,
        endpoint_key=None,
        batfish_version=None,
        pybatfish_version=None,
        backend_build_id=None,
        schema_version=None,
        db_id=None,
        loaded_clear_counter=None,
        pending_removal=True,
    )


@dataclass
class _Group:
    entries: dict = field(default_factory=dict)
    last_access: float = 0.0
    last_used: Optional[float] = None

    @property
    def size(self) -> int:
        return sum(entry.file_size for entry in self.entries.values())


def _parse_entry(data: bytes) -> tuple[dict, int]:
    """Return (header, body offset) of an entry file's leading bytes."""
    if not data.startswith(ENTRY_MAGIC):
        raise CacheEntryError("Missing cache entry header")
    end = data.find(b'\n', len(ENTRY_MAGIC))
    if end < 0:
        raise CacheEntryError("Truncated cache entry header")
    try:
        header = json.loads(data[len(ENTRY_MAGIC):end].decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CacheEntryError("Unreadable cache entry header") from exc
    if not isinstance(header, dict) or not isinstance(header.get('body_size'), int):
        raise CacheEntryError("Invalid cache entry header")
    return header, end + 1


class ResultCache:
    """Gzip response bodies on disk with a complete per-process index; a forced-off cache stores and evicts nothing"""

    def __init__(self, cache_dir: Path | str, max_bytes: int, max_entries: int, protect_seconds: float,
                 build_id: str, pybatfish_version: str, schema_version: int, forced_off: bool = False,
                 clock: Callable[[], float] = time.time):
        self.cache_dir = Path(cache_dir)
        self.max_bytes = int(max_bytes)
        self.max_entries = int(max_entries)
        self.protect_seconds = float(protect_seconds)
        self.build_id = build_id
        self.pybatfish_version = pybatfish_version
        self.schema_version = schema_version
        self.forced_off = forced_off
        self.clock = clock
        self.current_batfish_version: Callable[[], Optional[str]] = lambda: None
        self._index_lock = threading.Lock()
        self._groups: dict[tuple, _Group] = {}
        self._index_ready = False
        self._index_event: Optional[threading.Event] = None
        self._pending_access: dict[tuple, float] = {}
        self._computing: dict[tuple, int] = {}
        self._key_locks: dict[tuple, list] = {}
        self._protected_overflow_logged = False

    @property
    def tmp_dir(self) -> Path:
        return self.cache_dir / TMP_DIRNAME

    def key_components(self, content_hash: str, endpoint_key: str, owner_scope: str,
                       batfish_version: Optional[str]) -> dict:
        return {
            'content_hash': content_hash,
            'batfish_version': batfish_version,
            'pybatfish_version': self.pybatfish_version,
            'backend_build_id': self.build_id,
            'schema_version': self.schema_version,
            'endpoint_key': endpoint_key,
            'owner_scope': owner_scope,
        }

    def key_hash(self, content_hash: str, endpoint_key: str, owner_scope: str, batfish_version: Optional[str]) -> str:
        components = self.key_components(content_hash, endpoint_key, owner_scope, batfish_version)
        return hashlib.sha256(
            json.dumps(components, sort_keys=True, separators=(',', ':')).encode('utf-8')
        ).hexdigest()

    def entry_path(self, content_hash: str, key_hash: str) -> Path:
        if not _HEX64.fullmatch(content_hash or '') or not _HEX64.fullmatch(key_hash or ''):
            raise ValueError("Invalid cache key")
        path = self.cache_dir / content_hash / f"{key_hash}{ENTRY_SUFFIX}"
        assert_under_root(path, self.cache_dir)
        return path

    @contextmanager
    def key_lock(self, key: tuple):
        """Serialize computations of one key; the lock is dropped from the map with its last holder."""
        with self._index_lock:
            holder = self._key_locks.get(key)
            if holder is None:
                holder = [threading.Lock(), 0]
                self._key_locks[key] = holder
            holder[1] += 1
        lock = holder[0]
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._index_lock:
                holder[1] -= 1
                if holder[1] <= 0 and self._key_locks.get(key) is holder:
                    del self._key_locks[key]

    @contextmanager
    def computing(self, *groups: tuple):
        """Mark (content_hash, owner_scope) groups as being computed."""
        marked = [group for group in groups if group[0]]
        with self._index_lock:
            for group in marked:
                self._computing[group] = self._computing.get(group, 0) + 1
        try:
            yield
        finally:
            with self._index_lock:
                for group in marked:
                    count = self._computing.get(group, 0) - 1
                    if count > 0:
                        self._computing[group] = count
                    else:
                        self._computing.pop(group, None)

    def key_lock_count(self) -> int:
        with self._index_lock:
            return len(self._key_locks)

    def _walk(self) -> tuple[dict, list, list]:
        """Read every entry header below the cache directory and remove corrupt, unreadable and stale entries, indexing
        those whose removal fails as pending removal (file-only work for run_blocking)."""
        groups: dict[tuple, _Group] = {}
        removals: list[tuple[Path, str, tuple]] = []
        try:
            content_dirs = list(os.scandir(self.cache_dir))
        except FileNotFoundError:
            return groups, [], []
        for content_dir in content_dirs:
            if content_dir.name == TMP_DIRNAME or not _HEX64.fullmatch(content_dir.name):
                continue
            if not content_dir.is_dir(follow_symlinks=False):
                continue
            try:
                files = list(os.scandir(content_dir.path))
            except FileNotFoundError:
                continue
            for entry_file in files:
                if not entry_file.name.endswith(ENTRY_SUFFIX) or not entry_file.is_file(follow_symlinks=False):
                    continue
                path = Path(entry_file.path)
                key_hash = entry_file.name[:-len(ENTRY_SUFFIX)]
                try:
                    file_stat = entry_file.stat(follow_symlinks=False)
                    with open(path, 'rb') as handle:
                        prefix = handle.read(HEADER_PREFIX_SIZE)
                        if b'\n' not in prefix[len(ENTRY_MAGIC):]:
                            prefix += handle.read(HEADER_READ_LIMIT - len(prefix))
                        header, offset = _parse_entry(prefix)
                    if file_stat.st_size != offset + header['body_size']:
                        raise CacheEntryError("Cache entry size does not match its header")
                    components = self.key_components(
                        header.get('content_hash'), header.get('endpoint_key'), header.get('owner_scope'),
                        header.get('batfish_version'),
                    )
                    components['pybatfish_version'] = header.get('pybatfish_version')
                    components['backend_build_id'] = header.get('backend_build_id')
                    components['schema_version'] = header.get('schema_version')
                    expected = hashlib.sha256(
                        json.dumps(components, sort_keys=True, separators=(',', ':')).encode('utf-8')
                    ).hexdigest()
                    if expected != key_hash or header.get('content_hash') != content_dir.name:
                        raise CacheEntryError("Cache entry header does not match its file name")
                except FileNotFoundError:
                    continue
                except OSError:
                    removals.append((path, 'unreadable', (content_dir.name, None)))
                    continue
                except CacheEntryError:
                    removals.append((path, 'corrupt', (content_dir.name, None)))
                    continue
                group_key = (content_dir.name, header.get('owner_scope'))
                if (
                    header.get('backend_build_id') != self.build_id
                    or header.get('pybatfish_version') != self.pybatfish_version
                    or header.get('schema_version') != self.schema_version
                ):
                    removals.append((path, 'stale', group_key))
                    continue
                group = groups.setdefault(group_key, _Group())
                group.entries[key_hash] = _IndexedEntry(
                    path=path,
                    file_size=file_stat.st_size,
                    endpoint_key=header.get('endpoint_key'),
                    batfish_version=header.get('batfish_version'),
                    pybatfish_version=header.get('pybatfish_version'),
                    backend_build_id=header.get('backend_build_id'),
                    schema_version=header.get('schema_version'),
                    db_id=header.get('db_id'),
                    loaded_clear_counter=header.get('loaded_clear_counter'),
                )
                group.last_access = max(group.last_access, file_stat.st_mtime)
        removed: list[str] = []
        failures: list[str] = []
        for path, kind, group_key in removals:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                failures.append(type(exc).__name__)
                group = groups.setdefault(group_key, _Group())
                group.entries[path.name[:-len(ENTRY_SUFFIX)]] = _pending_entry(path)
                continue
            removed.append(kind)
        return groups, removed, failures

    def ensure_index(self) -> None:
        """Build the complete index once per process; a failed build is retried by the next call."""
        with self._index_lock:
            if self._index_ready:
                return
            event = self._index_event
            builder = event is None
            if builder:
                event = self._index_event = threading.Event()
        if not builder:
            event.wait()
            with self._index_lock:
                if self._index_ready:
                    return
            raise CacheEntryError("Result cache index could not be built")
        try:
            groups, removed, failures = run_blocking(self._walk)
        except BaseException:
            with self._index_lock:
                self._index_event = None
            event.set()
            raise
        corrupt = removed.count('corrupt')
        unreadable = removed.count('unreadable')
        stale = removed.count('stale')
        with self._index_lock:
            indexed = {
                (group_key[0], key_hash) for group_key, group in self._groups.items() for key_hash in group.entries
            }
            for group_key, group in groups.items():
                for key_hash in [key for key in group.entries if (group_key[0], key) in indexed]:
                    del group.entries[key_hash]
                existing = self._groups.get(group_key)
                if existing is not None:
                    group.entries.update(existing.entries)
                    group.last_used = existing.last_used
                if group.entries:
                    self._groups[group_key] = group
            for group_key, accessed in self._pending_access.items():
                group = self._groups.get(group_key)
                if group is not None:
                    group.last_access = max(group.last_access, accessed)
                    group.last_used = max(group.last_used or accessed, accessed)
            self._pending_access.clear()
            self._index_ready = True
        event.set()
        if corrupt or unreadable:
            logger.warning(
                "Result cache: removed %d corrupt and %d unreadable entries while building the index",
                corrupt,
                unreadable,
            )
        if stale:
            logger.info("Result cache: evicted %d entries of another build, pybatfish or schema version", stale)
        if failures:
            logger.warning(
                "Result cache: %d corrupt, unreadable or stale entries could not be removed while building the index "
                "(%s); they are not served and stay in the index for a later eviction",
                len(failures),
                ', '.join(sorted(set(failures))),
            )

    def _touch(self, group_key: tuple, used: bool) -> None:
        now = self.clock()
        with self._index_lock:
            group = self._groups.get(group_key)
            if group is None:
                if not self._index_ready:
                    self._pending_access[group_key] = now
                return
            group.last_access = now
            if used:
                group.last_used = now

    def _protected(self, group_key: tuple, group: _Group, now: float) -> bool:
        if self._computing.get(group_key):
            return True
        return group.last_used is not None and now - group.last_used < self.protect_seconds

    def _indexed_groups(self, content_hash: str, key_hash: str) -> list:
        """Group keys whose entries hold the file of (content_hash, key_hash); the caller holds _index_lock."""
        return [
            group_key for group_key, group in self._groups.items()
            if group_key[0] == content_hash and key_hash in group.entries
        ]

    def _drop_indexed(self, content_hash: str, key_hash: str) -> None:
        """Remove every index entry of the file of (content_hash, key_hash); the caller holds _index_lock."""
        for group_key in self._indexed_groups(content_hash, key_hash):
            group = self._groups[group_key]
            del group.entries[key_hash]
            if not group.entries:
                del self._groups[group_key]

    def _entries_of_key(self, content_hash: str, owner_scope: str, key_hash: str) -> tuple:
        """(group_key, entry) pairs indexed for the key in its scope's group and in the unknown-scope group; the
        caller holds _index_lock."""
        found = []
        for group_key in ((content_hash, owner_scope), (content_hash, None)):
            group = self._groups.get(group_key)
            entry = group.entries.get(key_hash) if group is not None else None
            if entry is not None:
                found.append((group_key, entry))
        return tuple(found)

    def _drop_seen(self, key_hash: str, seen: tuple) -> None:
        """Remove the seen (group_key, entry) pairs that are still indexed as the same objects; the caller holds
        _index_lock."""
        for group_key, entry in seen:
            group = self._groups.get(group_key)
            if group is not None and group.entries.get(key_hash) is entry:
                del group.entries[key_hash]
                if not group.entries:
                    del self._groups[group_key]

    def _discard(self, path: Path, content_hash: str, owner_scope: str, key_hash: str, reason: str,
                 seen: tuple) -> None:
        """Remove a corrupt or unreadable entry file; only the index entries seen before it was read are dropped
        or replaced by a pending-removal entry."""
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            pending = _pending_entry(path)
            with self._index_lock:
                newer = [
                    entry for _, entry in self._entries_of_key(content_hash, owner_scope, key_hash)
                    if not any(entry is old for _, old in seen)
                ]
                if not newer:
                    self._drop_seen(key_hash, seen)
                    self._groups.setdefault((content_hash, None), _Group()).entries[key_hash] = pending
            if newer:
                logger.warning(
                    "Result cache: %s entry could not be removed (%s); its file has a newer index entry "
                    "(content hash %s)",
                    reason,
                    type(exc).__name__,
                    content_hash[:16],
                )
            else:
                logger.warning(
                    "Result cache: %s entry could not be removed (%s); it is not served and stays in the index for "
                    "a later eviction (content hash %s)",
                    reason,
                    type(exc).__name__,
                    content_hash[:16],
                )
            return
        with self._index_lock:
            self._drop_seen(key_hash, seen)
        logger.warning("Result cache: %s entry removed and recomputed (content hash %s)", reason, content_hash[:16])

    def discard(self, entry: CachedEntry) -> None:
        """Remove an entry whose body turned out to be corrupt, or keep it pending removal when its file stays."""
        path = self.entry_path(entry.content_hash, entry.key_hash)
        self._discard(
            path, entry.content_hash, entry.owner_scope, entry.key_hash, 'corrupt', entry.indexed_before_read,
        )

    def lookup(self, content_hash: str, endpoint_key: str, owner_scope: str, db_id: Optional[str],
               clear_seq: Optional[int], batfish_version: Optional[str] = None) -> Optional[CachedEntry]:
        """Return a valid stored entry for the key, or None."""
        if self.forced_off or not content_hash:
            return None
        version = batfish_version if batfish_version is not None else self.current_batfish_version()
        key_hash = self.key_hash(content_hash, endpoint_key, owner_scope, version)
        path = self.entry_path(content_hash, key_hash)
        with self._index_lock:
            seen = self._entries_of_key(content_hash, owner_scope, key_hash)
        if any(entry.pending_removal for _, entry in seen):
            return None
        try:
            with open(path, 'rb') as handle:
                data = handle.read()
        except FileNotFoundError:
            return None
        except OSError:
            self._discard(path, content_hash, owner_scope, key_hash, 'unreadable', seen)
            return None
        try:
            header, offset = _parse_entry(data[:HEADER_READ_LIMIT])
            if len(data) != offset + header['body_size']:
                raise CacheEntryError("Cache entry size does not match its header")
        except CacheEntryError:
            self._discard(path, content_hash, owner_scope, key_hash, 'corrupt', seen)
            return None
        if (
            header.get('content_hash') != content_hash
            or header.get('endpoint_key') != endpoint_key
            or header.get('owner_scope') != owner_scope
        ):
            return None
        if header.get('db_id') != db_id:
            return None
        stamp = header.get('loaded_clear_counter')
        if clear_seq is not None and (stamp is None or stamp < clear_seq):
            return None
        self._touch((content_hash, owner_scope), used=True)
        return CachedEntry(
            content_hash=content_hash,
            key_hash=key_hash,
            endpoint_key=endpoint_key,
            owner_scope=owner_scope,
            body=data[offset:],
            body_sha256=header.get('body_sha256') or '',
            db_id=header.get('db_id'),
            loaded_clear_counter=stamp,
            indexed_before_read=seen,
        )

    def _write_entry(self, path: Path, payload: bytes) -> int:
        make_private_dirs(self.tmp_dir)
        make_private_dirs(path.parent)
        fd, temp_name = tempfile.mkstemp(prefix='.entry-', suffix='.tmp', dir=self.tmp_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
        return len(payload)

    def store(self, content_hash: str, endpoint_key: str, owner_scope: str, body_bytes: bytes, db_id: Optional[str],
              loaded_clear_counter: Optional[int], batfish_version: Optional[str] = None) -> CachedEntry:
        """Write one response body under its key, stamped with the database id and the parse's clear counter."""
        if self.forced_off:
            raise CacheEntryError("Result cache storage is disabled")
        self.ensure_index()
        version = batfish_version if batfish_version is not None else self.current_batfish_version()
        key_hash = self.key_hash(content_hash, endpoint_key, owner_scope, version)
        path = self.entry_path(content_hash, key_hash)
        compressed = gzip.compress(body_bytes, compresslevel=6, mtime=0)
        body_sha256 = hashlib.sha256(body_bytes).hexdigest()
        header = {
            'content_hash': content_hash,
            'endpoint_key': endpoint_key,
            'owner_scope': owner_scope,
            'batfish_version': version,
            'pybatfish_version': self.pybatfish_version,
            'backend_build_id': self.build_id,
            'schema_version': self.schema_version,
            'db_id': db_id,
            'loaded_clear_counter': loaded_clear_counter,
            'body_size': len(compressed),
            'body_sha256': body_sha256,
        }
        payload = ENTRY_MAGIC + json.dumps(header, sort_keys=True, separators=(',', ':')).encode('utf-8') + b'\n'
        payload += compressed
        file_size = run_blocking(self._write_entry, path, payload)
        now = self.clock()
        with self._index_lock:
            self._drop_indexed(content_hash, key_hash)
            group = self._groups.setdefault((content_hash, owner_scope), _Group())
            group.entries[key_hash] = _IndexedEntry(
                path=path,
                file_size=file_size,
                endpoint_key=endpoint_key,
                batfish_version=version,
                pybatfish_version=self.pybatfish_version,
                backend_build_id=self.build_id,
                schema_version=self.schema_version,
                db_id=db_id,
                loaded_clear_counter=loaded_clear_counter,
            )
            group.last_access = now
            group.last_used = now
        logger.debug("Result cache: stored %s for content hash %s", endpoint_key, content_hash[:16])
        return CachedEntry(
            content_hash=content_hash,
            key_hash=key_hash,
            endpoint_key=endpoint_key,
            owner_scope=owner_scope,
            body=compressed,
            body_sha256=body_sha256,
            db_id=db_id,
            loaded_clear_counter=loaded_clear_counter,
        )

    @staticmethod
    def _unlink_entries(items: Iterable[tuple]) -> list[tuple]:
        """Remove the files of (group_key, key_hash, entry) items and emptied content directories; return
        (item, exception type name) for every file that stays (file-only work for run_blocking)."""
        failures = []
        parents = set()
        for item in items:
            path = item[2].path
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                failures.append((item, type(exc).__name__))
            parents.add(path.parent)
        for parent in parents:
            try:
                parent.rmdir()
            except OSError:
                pass
        return failures

    def _pop_groups(self, group_keys: Iterable[tuple]) -> list:
        removed = []
        for group_key in group_keys:
            group = self._groups.pop(group_key, None)
            if group is not None:
                removed.extend((group_key, key_hash, entry) for key_hash, entry in group.entries.items())
        return removed

    def _restore_entries(self, items: Iterable[tuple]) -> None:
        """Put popped (group_key, key_hash, entry) items back into the index as pending removal unless their file is
        indexed again."""
        with self._index_lock:
            for group_key, key_hash, entry in items:
                if self._indexed_groups(group_key[0], key_hash):
                    continue
                entry.pending_removal = True
                self._groups.setdefault(group_key, _Group()).entries[key_hash] = entry

    def _evict(self, removed: list, reason: str) -> int:
        """Unlink popped (group_key, key_hash, entry) items, put back the ones whose file stays, and return how many
        files were removed."""
        if not removed:
            return 0
        try:
            failures = run_blocking(self._unlink_entries, removed)
        except BaseException:
            self._restore_entries(removed)
            raise
        if failures:
            self._restore_entries(item for item, _ in failures)
            logger.warning(
                "Result cache: %d entries could not be removed (%s); they stay in the index for a later eviction",
                len(failures),
                ', '.join(sorted({name for _, name in failures})),
            )
        evicted = len(removed) - len(failures)
        if evicted:
            logger.info("Result cache: evicted %d entries (%s)", evicted, reason)
        return evicted

    def clear_snapshot_cache(self, content_hash: str, owner_scope: str, keep_if_shared: bool) -> int:
        """Remove the owner scope's entries of a working hash unless keep_if_shared is set."""
        if self.forced_off or keep_if_shared or not content_hash:
            return 0
        self.ensure_index()
        with self._index_lock:
            removed = self._pop_groups([(content_hash, owner_scope)])
        return self._evict(removed, 'cleared by request')

    def evict_unreferenced(self, owner_scope: str, referenced_hashes: Iterable[str]) -> int:
        """Evict the owner scope's entries whose content hash is not in referenced_hashes."""
        if self.forced_off or owner_scope is None:
            return 0
        referenced = set(referenced_hashes)
        self.ensure_index()
        with self._index_lock:
            victims = [
                group_key for group_key in self._groups
                if group_key[1] == owner_scope and group_key[0] not in referenced
            ]
            removed = self._pop_groups(victims)
        return self._evict(
            removed, 'not referenced by the snapshot history read for their owner scope after a deletion',
        )

    def sweep_unreferenced(self, db_id: Optional[str], referenced_by_scope: dict) -> int:
        """For a database id, evict its unprotected entries that their own scope's set does not reference, and the
        entries pending removal."""
        if self.forced_off or not db_id:
            return 0
        self.ensure_index()
        now = self.clock()
        unreferenced: list = []
        pending: list = []
        with self._index_lock:
            for group_key in list(self._groups):
                group = self._groups[group_key]
                content_hash, scope = group_key
                collectable = (
                    content_hash not in referenced_by_scope.get(scope, ())
                    and not self._protected(group_key, group, now)
                )
                for key in list(group.entries):
                    entry = group.entries[key]
                    if entry.pending_removal:
                        pending.append((group_key, key, group.entries.pop(key)))
                    elif collectable and entry.db_id == db_id:
                        unreferenced.append((group_key, key, group.entries.pop(key)))
                if not group.entries:
                    del self._groups[group_key]
        try:
            evicted = self._evict(unreferenced, 'not referenced by the snapshot history read for their owner scope')
        except BaseException:
            self._restore_entries(pending)
            raise
        return evicted + self._evict(pending, 'pending removal after a failed removal')

    def _stale(self, entry: _IndexedEntry, batfish_version: Optional[str]) -> bool:
        if entry.pending_removal:
            return True
        if (
            entry.backend_build_id != self.build_id
            or entry.pybatfish_version != self.pybatfish_version
            or entry.schema_version != self.schema_version
        ):
            return True
        return batfish_version is not None and entry.batfish_version != batfish_version

    def _over_limits(self) -> bool:
        entries = sum(len(group.entries) for group in self._groups.values())
        size = sum(group.size for group in self._groups.values())
        return entries > self.max_entries or size > self.max_bytes

    def evict_if_needed(self) -> int:
        """Apply the size limits when they are exceeded: stale and pending-removal entries first, then LRU groups,
        protected groups last."""
        if self.forced_off:
            return 0
        self.ensure_index()
        batfish_version = self.current_batfish_version()
        now = self.clock()
        removed: list = []
        protected_overflow = False
        with self._index_lock:
            if not self._over_limits():
                return 0
            for group_key in list(self._groups):
                group = self._groups[group_key]
                for key in [key for key, entry in group.entries.items() if self._stale(entry, batfish_version)]:
                    removed.append((group_key, key, group.entries.pop(key)))
                if not group.entries:
                    del self._groups[group_key]
            ordered = sorted(self._groups.items(), key=lambda item: item[1].last_access)
            unprotected = [key for key, group in ordered if not self._protected(key, group, now)]
            protected = [key for key, group in ordered if self._protected(key, group, now)]
            for candidates in (unprotected, protected):
                for group_key in candidates:
                    if not self._over_limits():
                        break
                    if candidates is protected:
                        protected_overflow = True
                    removed.extend(self._pop_groups([group_key]))
            first_overflow = protected_overflow and not self._protected_overflow_logged
            self._protected_overflow_logged = self._protected_overflow_logged or protected_overflow
        if protected_overflow:
            logger.log(
                logging.WARNING if first_overflow else logging.DEBUG,
                "Result cache: entries used recently or being computed alone exceed RESULT_CACHE_MAX_BYTES or "
                "RESULT_CACHE_MAX_ENTRIES; evicting them in least-recently-used order until the limits hold",
            )
        return self._evict(removed, 'size limits')

    def stats(self) -> dict:
        if self.forced_off:
            return {'entries': 0, 'bytes': 0, 'max_bytes': self.max_bytes, 'max_entries': self.max_entries}
        self.ensure_index()
        with self._index_lock:
            entries = sum(len(group.entries) for group in self._groups.values())
            size = sum(group.size for group in self._groups.values())
        return {'entries': entries, 'bytes': size, 'max_bytes': self.max_bytes, 'max_entries': self.max_entries}
