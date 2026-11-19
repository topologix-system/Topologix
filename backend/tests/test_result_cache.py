import test_00_environment  # noqa: F401
import collections
import errno
import gc
import gzip
import hashlib
import inspect
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pandas
import requests
from sqlalchemy.exc import OperationalError

import app as app_module
import services.batfish_service as batfish_service_module
import services.result_cache as cache_module
import services.snapshot_state_service as state_module
from config import config, derive_backend_build_id
from services.batfish_service import (
    BATFISH_NOT_INITIALIZED_MESSAGE,
    ActivationFailureCache,
    BatfishQueryError,
    BatfishService,
)
from services.result_cache import ENTRY_MAGIC, ResultCache, owner_scope_for
from versioning_support import CONFIG_R1, CONFIG_R2, VersioningSandbox, write_file

BACKEND_DIR = Path(__file__).resolve().parents[1]
IS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0
BATFISH_VERSION = '2025.07.07.2423'
NETWORK = config.BATFISH_NETWORK
CACHE_LOGGER = 'services.result_cache'
STATE_LOGGER = 'services.snapshot_state_service'
BODY = b'{"data":[{"node":"r1"}],"message":"Success","status":"success"}'
SAVED_SERVICE_ATTRIBUTES = (
    '_session', 'version_probe', '_state_service', 'network_name', 'current_snapshot_name',
    'reference_snapshot_name', '_initialized', '_query_snapshot_name', 'loaded_content_hash',
    'loaded_batfish_version', 'loaded_clear_counter', 'live_loaded', 'activation_payload', 'last_upload_hash',
    'activation_failures', 'state_drop_count', 'state_loss_events', 'state_loss_log',
)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def coordinator_response(status_code: int, body: str,
                         url: str = 'http://batfish:9996/v2/networks/net/snapshots/snap/answer') -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = body.encode('utf-8')
    response.encoding = 'utf-8'
    response.url = url
    return response


def coordinator_error(status_code: int, body: str, **kwargs) -> requests.HTTPError:
    try:
        batfish_service_module._check_coordinator_response_status(coordinator_response(status_code, body, **kwargs))
    except requests.HTTPError as error:
        return error
    raise AssertionError("the coordinator response did not fail")


def decoded(response) -> dict:
    data = response.get_data()
    if response.headers.get('Content-Encoding') == 'gzip':
        data = gzip.decompress(data)
    return json.loads(data)


class StubProbe:
    """Batfish version probe stand-in with injectable snapshot existence answers"""

    def __init__(self, version: str | None = BATFISH_VERSION):
        self.version = version
        self.clock = time.monotonic
        self.statuses: dict[str, tuple[int, str]] = {}
        self.error: Exception | None = None
        self.checked: list[tuple[str, str]] = []

    def current(self):
        return self.version

    def peek(self):
        return self.version

    def feed(self, version, observed_at):
        return self.version

    def snapshot_status(self, network, snapshot):
        self.checked.append((network, snapshot))
        if self.error is not None:
            raise self.error
        return self.statuses.get(snapshot, (200, '{}'))


@dataclass
class Upload:
    path: Path
    name: str
    network: str
    files: list


class FailingQuestion:
    def __init__(self, error: Exception):
        self.error = error

    def answer(self, **kwargs):
        raise self.error


class FakeSession:
    """pybatfish session stand-in that records every upload and the files it contained"""

    def __init__(self, version: str = BATFISH_VERSION):
        self.network = None
        self.snapshot = None
        self.version = version
        self.uploads: list[Upload] = []
        self.failures: list = []
        self.questions: dict = {}
        self.q = SimpleNamespace()

    def set_network(self, name):
        self.network = name

    def get_component_versions(self):
        return {'Batfish': self.version}

    def init_snapshot(self, path, name=None, overwrite=False):
        root = Path(path)
        files = sorted(item.relative_to(root).as_posix() for item in root.rglob('*') if not item.is_dir())
        self.uploads.append(Upload(path=root, name=name, network=self.network, files=files))
        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure
        self.snapshot = name
        return name


class ResultCacheUnitTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.cache_dir = Path(self.temp_dir.name) / 'result_cache'
        self.now = [1_000.0]
        self.db_id = str(uuid.uuid4())

    def make_cache(self, **overrides) -> ResultCache:
        options = dict(
            max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=900, build_id='build-1',
            pybatfish_version='pyb-1', schema_version=1, clock=lambda: self.now[0],
        )
        options.update(overrides)
        return ResultCache(self.cache_dir, **options)

    def store(self, cache, content_hash, endpoint='get_nodes', scope='', counter=None, version='bf-1', db_id=None,
              body=BODY):
        return cache.store(content_hash, endpoint, scope, body, db_id or self.db_id, counter, batfish_version=version)

    def lookup(self, cache, content_hash, endpoint='get_nodes', scope='', clear_seq=None, version='bf-1', db_id=None):
        return cache.lookup(content_hash, endpoint, scope, db_id or self.db_id, clear_seq, batfish_version=version)

    def test_every_key_component_selects_its_own_entry(self):
        cache = self.make_cache()
        content_hash = sha('content')
        self.store(cache, content_hash)

        self.assertIsNotNone(self.lookup(cache, content_hash))
        self.assertIsNone(self.lookup(cache, sha('other content')))
        self.assertIsNone(self.lookup(cache, content_hash, endpoint='get_routes'))
        self.assertIsNone(self.lookup(cache, content_hash, scope=owner_scope_for(True, self.db_id, 1)))
        self.assertIsNone(self.lookup(cache, content_hash, version='bf-2'))
        for component in ('build_id', 'pybatfish_version', 'schema_version'):
            with self.subTest(component=component):
                other = self.make_cache(**{component: 2 if component == 'schema_version' else 'other'})
                self.assertIsNone(self.lookup(other, content_hash))
        components = cache.key_components(content_hash, 'get_nodes', '', 'bf-1')
        self.assertEqual(set(components), {
            'content_hash', 'batfish_version', 'pybatfish_version', 'backend_build_id', 'schema_version',
            'endpoint_key', 'owner_scope',
        })

    def test_owner_scope_definition(self):
        self.assertEqual(owner_scope_for(False, self.db_id, 7), '')
        self.assertEqual(owner_scope_for(True, self.db_id, 7), f'{self.db_id}:7')
        self.assertEqual(owner_scope_for(True, self.db_id, None), f'{self.db_id}:unowned')
        self.assertIsNone(owner_scope_for(True, None, 7))

    def test_entries_of_another_database_or_computed_before_a_clear_are_ignored(self):
        cache = self.make_cache()
        content_hash = sha('stamps')
        self.store(cache, content_hash, counter=3)

        self.assertIsNone(self.lookup(cache, content_hash, db_id=str(uuid.uuid4())))
        self.assertIsNotNone(self.lookup(cache, content_hash, clear_seq=3))
        self.assertIsNone(self.lookup(cache, content_hash, clear_seq=4))
        self.store(cache, content_hash, counter=None)
        self.assertIsNotNone(self.lookup(cache, content_hash, clear_seq=None))
        self.assertIsNone(self.lookup(cache, content_hash, clear_seq=1))

    def test_entry_files_are_private_written_atomically_and_carry_an_uncompressed_header(self):
        cache = self.make_cache()
        content_hash = sha('private')
        replaced = []
        original_replace = os.replace

        def recording_replace(source, target):
            replaced.append((Path(source).parent, Path(target)))
            return original_replace(source, target)

        with mock.patch('services.result_cache.os.replace', side_effect=recording_replace), \
                mock.patch('services.result_cache.os.fsync', wraps=os.fsync) as fsync:
            entry = self.store(cache, content_hash)

        path = cache.entry_path(content_hash, entry.key_hash)
        self.assertEqual(replaced, [(cache.tmp_dir, path)])
        self.assertGreaterEqual(fsync.call_count, 1)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        raw = path.read_bytes()
        self.assertTrue(raw.startswith(ENTRY_MAGIC))
        header = json.loads(raw[len(ENTRY_MAGIC):raw.index(b'\n', len(ENTRY_MAGIC))])
        self.assertEqual(header['owner_scope'], '')
        self.assertEqual(header['db_id'], self.db_id)
        self.assertIsNone(header['loaded_clear_counter'])
        self.assertEqual(header['body_sha256'], hashlib.sha256(BODY).hexdigest())
        self.assertEqual(gzip.decompress(entry.body), BODY)
        self.assertEqual(list(cache.tmp_dir.iterdir()), [])

    def test_corrupt_and_truncated_entries_are_deleted_and_never_served(self):
        cache = self.make_cache()
        for label, mutate in (
            ('garbage', lambda data: b'not an entry'),
            ('truncated', lambda data: data[:-5]),
            ('extended', lambda data: data + b'xx'),
        ):
            with self.subTest(case=label):
                content_hash = sha(label)
                entry = self.store(cache, content_hash)
                path = cache.entry_path(content_hash, entry.key_hash)
                path.write_bytes(mutate(path.read_bytes()))

                with self.assertLogs(CACHE_LOGGER, level='WARNING'):
                    self.assertIsNone(self.lookup(cache, content_hash))
                self.assertFalse(path.exists())

    def test_a_fresh_index_evicts_entries_of_another_build_and_keeps_the_current_ones(self):
        current = self.make_cache()
        kept_hash = sha('current build')
        self.store(current, kept_hash)
        old = self.make_cache(build_id='build-0')
        old._index_ready = True
        stale_hash = sha('stale build')
        self.store(old, stale_hash)

        restarted = self.make_cache()
        restarted.current_batfish_version = lambda: None
        with self.assertLogs(CACHE_LOGGER, level='INFO'):
            restarted.evict_unreferenced('', {kept_hash})

        self.assertEqual(restarted.stats()['entries'], 1)
        self.assertIsNotNone(self.lookup(restarted, kept_hash))
        self.assertFalse(any(self.cache_dir.glob(f'{stale_hash}/*.json.gz')))

    def test_a_fresh_index_applies_the_limits_and_purge_evictions_to_earlier_entries(self):
        first = self.make_cache()
        hashes = [sha(f'entry-{index}') for index in range(3)]
        for index, content_hash in enumerate(hashes):
            self.now[0] = 1_000.0 + index
            entry = self.store(first, content_hash)
            os.utime(first.entry_path(content_hash, entry.key_hash), (1_000 + index, 1_000 + index))
        size = first.stats()['bytes'] // 3

        restarted = self.make_cache(max_bytes=size * 2)
        self.now[0] = 100_000.0
        restarted.evict_if_needed()
        self.assertEqual(restarted.stats()['entries'], 2)
        self.assertIsNone(self.lookup(restarted, hashes[0]))

        again = self.make_cache()
        again.evict_unreferenced('', {hashes[2]})
        self.assertEqual(again.stats()['entries'], 1)
        self.assertIsNotNone(self.lookup(again, hashes[2]))

    def test_forced_off_cache_is_neither_walked_nor_evicted_and_reports_zero(self):
        writer = self.make_cache()
        content_hash = sha('kept on disk')
        self.store(writer, content_hash)
        forced = self.make_cache(forced_off=True)

        with mock.patch.object(forced, '_walk', side_effect=AssertionError('no walk')):
            self.assertEqual(forced.evict_unreferenced('', set()), 0)
            self.assertEqual(forced.sweep_unreferenced(self.db_id, {}), 0)
            self.assertEqual(forced.evict_if_needed(), 0)
            self.assertEqual(forced.stats(), {
                'entries': 0, 'bytes': 0, 'max_bytes': 10 ** 9, 'max_entries': 10 ** 6,
            })
        self.assertTrue(any(self.cache_dir.glob(f'{content_hash}/*.json.gz')))

    def test_eviction_order_stale_components_first_then_lru_groups(self):
        cache = self.make_cache(max_entries=2, protect_seconds=10)
        cache.current_batfish_version = lambda: 'bf-2'
        stale, older, newer = sha('stale'), sha('older'), sha('newer')
        self.now[0] = 1_000.0
        self.store(cache, older, version='bf-2')
        self.now[0] = 1_001.0
        self.store(cache, stale, version='bf-1')
        self.now[0] = 1_002.0
        self.store(cache, newer, version='bf-2')
        self.now[0] = 2_000.0

        cache.evict_if_needed()

        self.assertIsNone(self.lookup(cache, stale, version='bf-1'))
        self.assertIsNotNone(self.lookup(cache, older, version='bf-2'))
        self.assertIsNotNone(self.lookup(cache, newer, version='bf-2'))
        third = sha('third')
        self.now[0] = 2_001.0
        self.store(cache, third, version='bf-2')
        self.now[0] = 3_000.0
        self.assertIsNotNone(self.lookup(cache, older, version='bf-2'))
        cache.evict_if_needed()
        self.assertIsNone(self.lookup(cache, newer, version='bf-2'))
        self.assertIsNotNone(self.lookup(cache, older, version='bf-2'))

    def test_protected_groups_survive_and_lru_applies_inside_the_protected_set_with_a_warning(self):
        cache = self.make_cache(max_entries=1, protect_seconds=900)
        computing, served, idle = sha('computing'), sha('served'), sha('idle')
        self.now[0] = 1_000.0
        self.store(cache, computing)
        self.store(cache, served)
        self.store(cache, idle)
        self.now[0] = 10_000.0
        self.assertIsNotNone(self.lookup(cache, served))

        with cache.computing((computing, '')):
            with self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
                cache.evict_if_needed()

        self.assertIsNone(self.lookup(cache, idle))
        remaining = [content_hash for content_hash in (computing, served) if self.lookup(cache, content_hash)]
        self.assertEqual(len(remaining), 1)
        self.assertIn(
            'WARNING:services.result_cache:Result cache: entries used recently or being computed alone exceed '
            'RESULT_CACHE_MAX_BYTES or RESULT_CACHE_MAX_ENTRIES; evicting them in least-recently-used order until '
            'the limits hold',
            logs.output,
        )

    def test_a_zero_limit_warns_about_protected_entries_once_and_evicts_every_store(self):
        cache = self.make_cache(max_entries=0, protect_seconds=900)
        overflow = 'entries used recently or being computed alone exceed'

        with self.assertLogs(CACHE_LOGGER, level='DEBUG') as logs:
            for index in range(2):
                content_hash = sha(f'zero limit {index}')
                self.store(cache, content_hash)
                self.assertEqual(cache.evict_if_needed(), 1)
                self.assertIsNone(self.lookup(cache, content_hash))

        overflow_lines = [line for line in logs.output if overflow in line]
        self.assertEqual([line.split(':', 1)[0] for line in overflow_lines], ['WARNING', 'DEBUG'])
        self.assertEqual(cache.stats()['entries'], 0)

    def test_owner_scopes_are_evicted_and_swept_separately(self):
        cache = self.make_cache(protect_seconds=0)
        content_hash = sha('shared bytes')
        scope_a = owner_scope_for(True, self.db_id, 1)
        scope_b = owner_scope_for(True, self.db_id, 2)
        self.store(cache, content_hash, scope=scope_a)
        self.store(cache, content_hash, scope=scope_b)

        cache.evict_unreferenced(scope_a, set())
        self.assertIsNone(self.lookup(cache, content_hash, scope=scope_a))
        self.assertIsNotNone(self.lookup(cache, content_hash, scope=scope_b))

        self.store(cache, content_hash, scope=scope_a)
        cache.sweep_unreferenced(self.db_id, {scope_b: {content_hash}})
        self.assertIsNone(self.lookup(cache, content_hash, scope=scope_a))
        self.assertIsNotNone(self.lookup(cache, content_hash, scope=scope_b))

        self.store(cache, content_hash, scope=scope_a)
        cache.clear_snapshot_cache(content_hash, scope_a, keep_if_shared=False)
        self.assertIsNone(self.lookup(cache, content_hash, scope=scope_a))
        self.assertIsNotNone(self.lookup(cache, content_hash, scope=scope_b))

    def test_per_key_locks_are_reference_counted_and_dropped(self):
        cache = self.make_cache()
        key = (sha('lock'), 'get_nodes', '')
        entered = threading.Event()
        release = threading.Event()
        order = []

        def first():
            with cache.key_lock(key):
                order.append('first')
                entered.set()
                release.wait(5)

        def second():
            with cache.key_lock(key):
                order.append('second')

        first_thread = threading.Thread(target=first)
        first_thread.start()
        entered.wait(5)
        second_thread = threading.Thread(target=second)
        second_thread.start()
        deadline = time.monotonic() + 10
        while cache._key_locks[key][1] < 2 and time.monotonic() < deadline:
            time.sleep(0.01)

        self.assertEqual(cache._key_locks[key][1], 2)
        self.assertEqual(order, ['first'])
        self.assertEqual(cache.key_lock_count(), 1)
        release.set()
        first_thread.join(5)
        second_thread.join(5)
        self.assertEqual(order, ['first', 'second'])
        self.assertEqual(cache.key_lock_count(), 0)

    def test_eviction_never_takes_per_key_locks(self):
        cache = self.make_cache(protect_seconds=0)
        content_hash = sha('held')
        self.store(cache, content_hash)
        finished = threading.Event()

        with cache.key_lock((content_hash, 'get_nodes', '')):
            thread = threading.Thread(target=lambda: (cache.evict_unreferenced('', set()), finished.set()))
            thread.start()
            self.assertTrue(finished.wait(5))
        thread.join(5)
        self.assertIsNone(self.lookup(cache, content_hash))

    def test_concurrent_processes_sharing_the_directory_see_each_others_entries(self):
        first = self.make_cache()
        second = self.make_cache()
        content_hash = sha('shared directory')
        self.store(first, content_hash)

        self.assertIsNotNone(self.lookup(second, content_hash))
        first.evict_unreferenced('', set())
        self.assertIsNone(self.lookup(second, content_hash))
        self.assertEqual(second.evict_unreferenced('', set()), 0)

    def test_build_id_covers_the_source_set_and_requirements_but_no_data_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            (base / 'services').mkdir()
            (base / 'data').mkdir()
            write_file(base / 'app.py', 'a = 1\n')
            write_file(base / 'requirements.txt', 'flask\n')
            write_file(base / 'services' / 'x.py', 'x = 1\n')
            write_file(base / 'data' / 'big.py', 'ignored = 1\n')
            first = derive_backend_build_id(base)
            write_file(base / 'data' / 'big.py', 'ignored = 2\n')
            self.assertEqual(derive_backend_build_id(base), first)
            write_file(base / 'services' / 'x.py', 'x = 2\n')
            second = derive_backend_build_id(base)
            self.assertNotEqual(second, first)
            write_file(base / 'requirements.txt', 'flask==3\n')
            self.assertNotEqual(derive_backend_build_id(base), second)

    def test_configured_defaults(self):
        self.assertEqual(config.RESULT_CACHE_MAX_BYTES, 512 * 1024 * 1024)
        self.assertEqual(config.RESULT_CACHE_MAX_ENTRIES, 4000)
        self.assertEqual(config.RESULT_CACHE_PROTECT_SECONDS, 900)
        self.assertEqual(config.BATFISH_VERSION_PROBE_TTL_SECONDS, 300)
        self.assertEqual(config.BATFISH_VERSION_GRACE_SECONDS, 3600)
        self.assertEqual(config.BACKEND_BUILD_ID, derive_backend_build_id(BACKEND_DIR))
        self.assertIsInstance(config.RESULT_CACHE_SCHEMA_VERSION, int)
        for header in ('X-Topologix-Snapshot-Id', 'X-Topologix-Content-Hash', 'X-Topologix-Cache'):
            self.assertIn(header, config.CORS_EXPOSE_HEADERS)

    def failing_unlink(self, paths: set, error: OSError):
        real_unlink = Path.unlink

        def unlink(path, *args, **kwargs):
            if path in paths:
                raise error
            return real_unlink(path, *args, **kwargs)

        return mock.patch.object(Path, 'unlink', autospec=True, side_effect=unlink)

    def test_an_entry_whose_file_stays_is_kept_in_the_index_and_removed_by_a_later_run(self):
        callers = {
            'clear': lambda cache, content_hash: cache.clear_snapshot_cache(content_hash, '', keep_if_shared=False),
            'unreferenced': lambda cache, content_hash: cache.evict_unreferenced('', set()),
            'sweep': lambda cache, content_hash: cache.sweep_unreferenced(self.db_id, {}),
            'limits': lambda cache, content_hash: cache.evict_if_needed(),
        }
        retries = dict(callers, unreferenced=callers['sweep'])
        for name, evict in callers.items():
            with self.subTest(caller=name):
                cache = self.make_cache(max_entries=0)
                content_hash = sha(f'stays {name}')
                path = cache.entry_path(content_hash, self.store(cache, content_hash, counter=3).key_hash)
                held = cache.stats()
                self.now[0] += 1_000

                with self.failing_unlink({path}, PermissionError(errno.EACCES, 'denied')), \
                        self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
                    self.assertEqual(evict(cache, content_hash), 0)

                self.assertTrue(path.is_file())
                self.assertEqual(cache.stats(), held)
                self.assert_one_entry_per_path(cache)
                self.assertEqual(logs.output, [
                    'WARNING:services.result_cache:Result cache: 1 entries could not be removed (PermissionError); '
                    'they stay in the index for a later eviction',
                ])
                for clear_seq in (None, 3, 4):
                    self.assertIsNone(self.lookup(cache, content_hash, clear_seq=clear_seq))
                self.assertEqual(retries[name](cache, content_hash), 1)
                self.assertFalse(path.exists())
                self.assertEqual(cache.stats()['entries'], 0)

    def test_an_absent_file_counts_as_removed(self):
        cache = self.make_cache()
        content_hash = sha('already gone')
        path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)

        with self.failing_unlink({path}, FileNotFoundError(errno.ENOENT, 'gone')), \
                self.assertNoLogs(CACHE_LOGGER, level='WARNING'):
            self.assertEqual(cache.evict_unreferenced('', set()), 1)

        self.assertEqual(cache.stats()['entries'], 0)

    def test_a_failed_unlink_batch_keeps_every_entry_and_a_newer_entry_of_the_key_wins(self):
        cache = self.make_cache()
        hashes = [sha('batch one'), sha('batch two')]
        for content_hash in hashes:
            self.store(cache, content_hash)
        real_run_blocking = cache_module.run_blocking

        def failing_unlinks(fn, *args, **kwargs):
            if fn == cache._unlink_entries:
                self.store(cache, hashes[0], counter=7)
                raise RuntimeError('worker pool unavailable')
            return real_run_blocking(fn, *args, **kwargs)

        with mock.patch.object(cache_module, 'run_blocking', side_effect=failing_unlinks), \
                self.assertRaises(RuntimeError):
            cache.evict_unreferenced('', set())

        on_disk = sorted(self.cache_dir.rglob('*.json.gz'))
        self.assertEqual(len(on_disk), 2)
        self.assertEqual(cache.stats()['entries'], 2)
        self.assertEqual(cache.stats()['bytes'], sum(path.stat().st_size for path in on_disk))
        self.assert_one_entry_per_path(cache)
        self.assertEqual([entry.loaded_clear_counter for entry in cache._groups[(hashes[0], '')].entries.values()], [7])
        self.assertEqual(cache.evict_unreferenced('', set()), 2)
        self.assertEqual(cache.stats()['entries'], 0)

    def test_a_corrupt_entry_whose_file_stays_is_counted_never_served_and_swept_later(self):
        cache = self.make_cache()
        content_hash = sha('corrupt and stuck')
        path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)
        path.write_bytes(path.read_bytes()[:-5])
        attempts = []
        real_unlink = Path.unlink

        def stuck_unlink(target, *args, **kwargs):
            if target == path:
                attempts.append(target)
                raise OSError(errno.EIO, 'io')
            return real_unlink(target, *args, **kwargs)

        with mock.patch.object(Path, 'unlink', autospec=True, side_effect=stuck_unlink), \
                self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
            for _ in range(3):
                self.assertIsNone(self.lookup(cache, content_hash))

        self.assertEqual(len(attempts), 1)
        self.assertEqual(logs.output, [
            'WARNING:services.result_cache:Result cache: corrupt entry could not be removed (OSError); it is not '
            f'served and stays in the index for a later eviction (content hash {content_hash[:16]})',
        ])
        self.assertTrue(path.is_file())
        self.assertEqual(cache.stats()['entries'], 1)
        self.assertEqual(cache.stats()['bytes'], path.stat().st_size)
        self.assert_one_entry_per_path(cache)
        self.assertEqual(cache.sweep_unreferenced(self.db_id, {'': {content_hash}}), 1)
        self.assertFalse(path.exists())
        self.assertEqual(cache.stats()['entries'], 0)

    def test_entries_the_index_walk_cannot_remove_are_indexed_never_served_and_removed_later(self):
        removals = {
            'sweep': lambda cache, hashes: cache.sweep_unreferenced(self.db_id, {'': set(hashes)}),
            'limits': lambda cache, hashes: cache.evict_if_needed(),
        }
        for name, remove in removals.items():
            with self.subTest(removal=name):
                writer = self.make_cache()
                corrupt_hash = sha(f'walk corrupt {name}')
                corrupt_path = writer.entry_path(corrupt_hash, self.store(writer, corrupt_hash).key_hash)
                corrupt_path.write_bytes(b'not an entry')
                old = self.make_cache(build_id='build-0')
                old._index_ready = True
                stale_hash = sha(f'walk stale {name}')
                stale_path = old.entry_path(stale_hash, self.store(old, stale_hash).key_hash)
                stuck = {corrupt_path, stale_path}

                restarted = self.make_cache(max_entries=1)
                with self.failing_unlink(stuck, OSError(errno.EBUSY, 'busy')), \
                        self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
                    held = restarted.stats()

                self.assertEqual(logs.output, [
                    'WARNING:services.result_cache:Result cache: 2 corrupt, unreadable or stale entries could not be '
                    'removed while building the index (OSError); they are not served and stay in the index for a '
                    'later eviction',
                ])
                self.assertEqual(held['entries'], 2)
                self.assertEqual(held['bytes'], sum(path.stat().st_size for path in stuck))
                self.assert_one_entry_per_path(restarted)
                self.assertEqual(restarted._groups[(corrupt_hash, None)].entries[corrupt_path.name[:-8]].file_size,
                                 corrupt_path.stat().st_size)
                self.assertIsNone(self.lookup(restarted, corrupt_hash))
                self.assertTrue(corrupt_path.is_file())

                self.assertEqual(remove(restarted, [corrupt_hash, stale_hash]), 2)
                self.assertFalse(any(path.exists() for path in stuck))
                self.assertEqual(restarted.stats()['entries'], 0)

    def test_a_store_replacing_a_file_pending_removal_makes_the_key_servable_again(self):
        writer = self.make_cache()
        content_hash = sha('replaced after a failed removal')
        path = writer.entry_path(content_hash, self.store(writer, content_hash).key_hash)
        path.write_bytes(b'not an entry')
        restarted = self.make_cache()
        with self.failing_unlink({path}, OSError(errno.EBUSY, 'busy')), self.assertLogs(CACHE_LOGGER, level='WARNING'):
            self.assertEqual(restarted.stats()['entries'], 1)
        self.assertIsNone(self.lookup(restarted, content_hash))

        self.store(restarted, content_hash)

        self.assertEqual(restarted.stats()['entries'], 1)
        self.assertIsNotNone(self.lookup(restarted, content_hash))
        self.assert_one_entry_per_path(restarted)
        self.assertEqual(restarted.sweep_unreferenced(self.db_id, {'': {content_hash}}), 0)
        self.assertTrue(path.is_file())

    def test_an_absent_file_counts_as_removed_for_a_discard_and_for_the_index_walk(self):
        cache = self.make_cache()
        content_hash = sha('absent on discard')
        path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)
        path.write_bytes(b'not an entry')
        gone = FileNotFoundError(errno.ENOENT, 'gone')

        with self.failing_unlink({path}, gone), self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
            self.assertIsNone(self.lookup(cache, content_hash))
        self.assertIn('corrupt entry removed and recomputed', logs.output[0])
        self.assertEqual(cache.stats()['entries'], 0)

        restarted = self.make_cache()
        with self.failing_unlink({path}, gone), self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
            self.assertEqual(restarted.stats()['entries'], 0)
        self.assertEqual(logs.output, [
            'WARNING:services.result_cache:Result cache: removed 1 corrupt and 0 unreadable entries while building '
            'the index',
        ])

    def test_an_entry_the_index_walk_cannot_open_is_removed_as_unreadable(self):
        writer = self.make_cache()
        corrupt_hash, unreadable_hash = sha('walk corrupt next to unreadable'), sha('walk unreadable')
        corrupt_path = writer.entry_path(corrupt_hash, self.store(writer, corrupt_hash).key_hash)
        corrupt_path.write_bytes(b'not an entry')
        unreadable_path = writer.entry_path(unreadable_hash, self.store(writer, unreadable_hash).key_hash)
        real_open = open

        def denied_open(file, *args, **kwargs):
            if Path(file) == unreadable_path:
                raise PermissionError(errno.EACCES, 'Permission denied')
            return real_open(file, *args, **kwargs)

        restarted = self.make_cache()
        with mock.patch('services.result_cache.open', create=True, side_effect=denied_open), \
                self.assertLogs(CACHE_LOGGER, level='WARNING') as logs:
            self.assertEqual(restarted.stats()['entries'], 0)

        self.assertEqual(logs.output, [
            'WARNING:services.result_cache:Result cache: removed 1 corrupt and 1 unreadable entries while building '
            'the index',
        ])
        self.assertFalse(corrupt_path.exists())
        self.assertFalse(unreadable_path.exists())

    def assert_one_entry_per_path(self, cache: ResultCache):
        paths = [entry.path for group in cache._groups.values() for entry in group.entries.values()]
        self.assertEqual(len(paths), len(set(paths)), paths)

    def test_a_file_whose_removal_fails_is_indexed_once_in_every_order(self):
        def discard_before_the_index():
            writer = self.make_cache()
            content_hash = sha('once before the index')
            path = writer.entry_path(content_hash, self.store(writer, content_hash).key_hash)
            path.write_bytes(b'not an entry')
            cache = self.make_cache()
            self.assertIsNone(self.lookup(cache, content_hash))
            self.assertFalse(cache._index_ready)
            cache.ensure_index()
            return cache, path

        def discard_during_the_index_walk():
            writer = self.make_cache()
            content_hash = sha('once during the walk')
            path = writer.entry_path(content_hash, self.store(writer, content_hash).key_hash)
            path.write_bytes(b'not an entry')
            cache = self.make_cache()
            real_run_blocking = cache_module.run_blocking

            def walk_after_a_lookup(fn, *args, **kwargs):
                if fn == cache._walk:
                    self.assertIsNone(self.lookup(cache, content_hash))
                return real_run_blocking(fn, *args, **kwargs)

            with mock.patch.object(cache_module, 'run_blocking', side_effect=walk_after_a_lookup):
                cache.ensure_index()
            return cache, path

        def discard_after_the_index():
            cache = self.make_cache()
            content_hash = sha('once after the index')
            path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)
            path.write_bytes(b'not an entry')
            self.assertIsNone(self.lookup(cache, content_hash))
            return cache, path

        def restore_after_a_discard():
            cache = self.make_cache()
            content_hash = sha('once after a restore')
            path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)
            path.write_bytes(b'not an entry')
            real_run_blocking = cache_module.run_blocking

            def unlink_after_a_lookup(fn, *args, **kwargs):
                if fn == cache._unlink_entries:
                    self.assertIsNone(self.lookup(cache, content_hash))
                return real_run_blocking(fn, *args, **kwargs)

            with mock.patch.object(cache_module, 'run_blocking', side_effect=unlink_after_a_lookup):
                self.assertEqual(cache.evict_unreferenced('', set()), 0)
            return cache, path

        for order in (discard_before_the_index, discard_during_the_index_walk, discard_after_the_index,
                      restore_after_a_discard):
            with self.subTest(order=order.__name__):
                real_unlink = Path.unlink
                stuck = []

                def read_only_unlink(target, *args, **kwargs):
                    if target.suffix == '.gz':
                        stuck.append(target)
                        raise OSError(errno.EROFS, 'read-only')
                    return real_unlink(target, *args, **kwargs)

                with mock.patch.object(Path, 'unlink', autospec=True, side_effect=read_only_unlink), \
                        self.assertLogs(CACHE_LOGGER, level='WARNING'):
                    cache, path = order()
                    held = cache.stats()

                self.assertTrue(stuck)
                self.assert_one_entry_per_path(cache)
                self.assertEqual(held['entries'], 1)
                self.assertEqual(held['bytes'], path.stat().st_size)
                self.assertEqual(cache.sweep_unreferenced(self.db_id, {}), 1)
                self.assertFalse(path.exists())
                self.assertEqual(cache.stats()['entries'], 0)

    def test_a_sweep_counts_unreferenced_and_pending_removal_entries_separately(self):
        cache = self.make_cache()
        referenced, unreferenced = sha('swept but referenced'), sha('swept and unreferenced')
        path = cache.entry_path(referenced, self.store(cache, referenced).key_hash)
        self.store(cache, unreferenced)
        path.write_bytes(b'not an entry')
        with self.failing_unlink({path}, OSError(errno.EIO, 'io')), self.assertLogs(CACHE_LOGGER, level='WARNING'):
            self.assertIsNone(self.lookup(cache, referenced))
        self.now[0] += 1_000

        with self.assertLogs(CACHE_LOGGER, level='INFO') as logs:
            self.assertEqual(cache.sweep_unreferenced(self.db_id, {'': {referenced}}), 2)

        self.assertEqual(logs.output, [
            'INFO:services.result_cache:Result cache: evicted 1 entries (not referenced by the snapshot history read '
            'for their owner scope)',
            'INFO:services.result_cache:Result cache: evicted 1 entries (pending removal after a failed removal)',
        ])
        self.assert_one_entry_per_path(cache)

    def test_a_store_between_a_discards_unlink_and_its_index_update_stays_indexed_and_servable(self):
        outcomes = {
            'unlink succeeds': None,
            'unlink finds no file': FileNotFoundError(errno.ENOENT, 'gone'),
            'unlink fails': OSError(errno.EBUSY, 'busy'),
        }
        for name, unlink_error in outcomes.items():
            with self.subTest(unlink=name):
                cache = self.make_cache()
                content_hash = sha(f'raced {name}')
                path = cache.entry_path(content_hash, self.store(cache, content_hash).key_hash)
                path.write_bytes(b'not an entry')
                real_unlink = Path.unlink
                raced = []

                def unlink_then_store(target, *args, **kwargs):
                    if target != path or raced:
                        return real_unlink(target, *args, **kwargs)
                    if unlink_error is None or isinstance(unlink_error, FileNotFoundError):
                        real_unlink(target)
                    raced.append(self.store(cache, content_hash, counter=5))
                    if unlink_error is not None:
                        raise unlink_error

                with mock.patch.object(Path, 'unlink', autospec=True, side_effect=unlink_then_store), \
                        self.assertLogs(CACHE_LOGGER, level='WARNING'):
                    self.assertIsNone(self.lookup(cache, content_hash))

                self.assertEqual(len(raced), 1)
                self.assert_one_entry_per_path(cache)
                [(group_key, entry)] = [
                    (group_key, entry) for group_key, group in cache._groups.items()
                    for entry in group.entries.values() if entry.path == path
                ]
                self.assertEqual(group_key, (content_hash, ''))
                self.assertFalse(entry.pending_removal)
                self.assertEqual(entry.loaded_clear_counter, 5)
                served = self.lookup(cache, content_hash)
                self.assertIsNotNone(served)
                self.assertEqual(served.loaded_clear_counter, 5)
                self.assertEqual(cache.stats()['entries'], 1)
                self.assertEqual(cache.stats()['bytes'], path.stat().st_size)
                self.assertEqual(cache.evict_unreferenced('', set()), 1)

    def test_a_sweep_whose_first_eviction_raises_keeps_the_pending_entries_indexed(self):
        cache = self.make_cache()
        referenced, unreferenced = sha('pending through a failed sweep'), sha('unreferenced in a failed sweep')
        path = cache.entry_path(referenced, self.store(cache, referenced).key_hash)
        self.store(cache, unreferenced)
        path.write_bytes(b'not an entry')
        with self.failing_unlink({path}, OSError(errno.EIO, 'io')), self.assertLogs(CACHE_LOGGER, level='WARNING'):
            self.assertIsNone(self.lookup(cache, referenced))
        held = cache.stats()
        self.now[0] += 1_000
        real_run_blocking = cache_module.run_blocking

        def first_unlink_batch_fails(fn, *args, **kwargs):
            if fn == cache._unlink_entries:
                raise RuntimeError('worker pool unavailable')
            return real_run_blocking(fn, *args, **kwargs)

        with mock.patch.object(cache_module, 'run_blocking', side_effect=first_unlink_batch_fails), \
                self.assertRaises(RuntimeError):
            cache.sweep_unreferenced(self.db_id, {'': {referenced}})

        self.assertEqual(cache.stats(), held)
        self.assert_one_entry_per_path(cache)
        self.assertTrue(any(
            entry.pending_removal and entry.path == path
            for group in cache._groups.values() for entry in group.entries.values()
        ))
        self.assertEqual(cache.sweep_unreferenced(self.db_id, {'': {referenced}}), 2)
        self.assertEqual(cache.stats()['entries'], 0)


class StagingOffloadTest(unittest.TestCase):
    def test_hashing_and_staging_run_through_run_blocking(self):
        sandbox = VersioningSandbox()
        self.addCleanup(sandbox.cleanup)
        snapshot = sandbox.create_snapshot('offload')
        calls = []
        original = state_module.run_blocking

        def recording(fn, *args, **kwargs):
            calls.append(getattr(fn, '__name__', repr(fn)))
            return original(fn, *args, **kwargs)

        with mock.patch.object(state_module, 'run_blocking', side_effect=recording):
            staged, staged_hash = sandbox.state.stage_for_upload(snapshot)
            manifest = sandbox.state.compute_manifest(snapshot)
        sandbox.state.cleanup_staging(staged)

        self.assertIn('copy_files', calls)
        self.assertIn('hash_files', calls)
        self.assertEqual(staged_hash, manifest.content_hash)


class CachedRouteTestCase(unittest.TestCase):
    """The app's routes over a sandboxed store, a recording Batfish session and a stubbed version probe"""

    sandbox_options: dict = {}

    def setUp(self):
        self.service = app_module.batfish_service
        self.saved_service = {name: getattr(self.service, name) for name in SAVED_SERVICE_ATTRIBUTES}
        self.saved_app = (app_module.snapshot_state_service, app_module.snapshot_history_service,
                          app_module.result_cache)
        options = {'RESULT_CACHE_ENABLED': True, **self.sandbox_options}
        self.sandbox = VersioningSandbox(snapshot_service=app_module.snapshot_service, **options)
        self.cache = self.make_cache()
        self.install()
        self.session = FakeSession()
        self.probe = StubProbe()
        service = self.service
        service._session = self.session
        service.version_probe = self.probe
        service.network_name = NETWORK
        service.current_snapshot_name = None
        service.reference_snapshot_name = None
        service._initialized = False
        service._query_snapshot_name = None
        service._reset_loaded_state()
        service.last_upload_hash = None
        service.activation_failures = ActivationFailureCache()
        service.state_loss_log = collections.deque(maxlen=batfish_service_module.STATE_LOSS_LOG_SIZE)
        self.getter_calls: list[tuple] = []
        self.node_rows = [{'node': 'r1'}]
        self.node_failures = 0
        self.query_errors: list = []
        self.all_data_hook = None
        patches = [
            mock.patch.object(service, name, return_value=[])
            for name in ('get_file_parse_status', 'get_init_issues', 'get_parse_warnings')
        ]
        patches += [
            mock.patch.object(service, 'get_node_properties', side_effect=self.node_properties),
            mock.patch.object(service, 'fetch_all_data', side_effect=self.all_data),
            mock.patch.object(service, 'traceroute', side_effect=self.traceroute),
            mock.patch.object(service, 'get_filter_line_reachability', side_effect=self.traceroute),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        app_module._cache_degradations_logged.clear()
        self.client = app_module.app.test_client()

    def tearDown(self):
        for name, value in self.saved_service.items():
            setattr(self.service, name, value)
        (app_module.snapshot_state_service, app_module.snapshot_history_service,
         app_module.result_cache) = self.saved_app
        self.sandbox.cleanup()

    def make_cache(self, **overrides) -> ResultCache:
        options = dict(
            max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=900, build_id='test-build',
            pybatfish_version='test-pybatfish', schema_version=1,
            forced_off=self.sandbox.state.result_cache_forced_off,
        )
        options.update(overrides)
        cache = ResultCache(self.sandbox.settings.RESULT_CACHE_DIR, **options)
        cache.current_batfish_version = lambda: self.probe.peek() if hasattr(self, 'probe') else None
        return cache

    def install(self, cache: ResultCache | None = None) -> None:
        if cache is not None:
            self.cache = cache
        self.sandbox.history.attach_result_cache(self.cache)
        app_module.snapshot_state_service = self.sandbox.state
        app_module.snapshot_history_service = self.sandbox.history
        app_module.result_cache = self.cache
        self.service.attach_state_service(self.sandbox.state)

    def restart(self, seed: bool = True) -> None:
        """Simulate a process restart: new services and cache index, Batfish process state forgotten."""
        self.sandbox.start()
        self.install(self.make_cache())
        service = self.service
        service.current_snapshot_name = None
        service._initialized = False
        service._reset_loaded_state()
        service.activation_failures = ActivationFailureCache()
        if seed:
            app_module.seed_active_snapshot_from_file()

    def node_properties(self):
        self.service._ensure_initialized()
        self.getter_calls.append(('nodes', self.service.loaded_content_hash))
        if self.node_failures:
            self.node_failures -= 1
            self.service._count_query_failure()
        return list(self.node_rows)

    def all_data(self):
        self.service._ensure_initialized()
        self.getter_calls.append(('all-data', self.service.loaded_content_hash))
        if self.all_data_hook is not None:
            self.all_data_hook()
        return {'query_errors': list(self.query_errors), 'node_properties': list(self.node_rows)}

    def traceroute(self, *args, **kwargs):
        self.service._ensure_initialized()
        self.getter_calls.append(('traceroute', self.service.loaded_content_hash))
        return []

    def create(self, name: str, files: dict | None = None) -> Path:
        return self.sandbox.create_snapshot(name, files)

    def select(self, name: str | None) -> None:
        self.service.current_snapshot_name = name

    def parses(self) -> int:
        return len(self.session.uploads)

    def calls(self, kind: str = 'nodes') -> int:
        return len([call for call in self.getter_calls if call[0] == kind])

    def nodes(self, **headers):
        return self.client.get('/api/network/nodes', headers=headers)

    def all_data_request(self, **headers):
        return self.client.get('/api/network/all-data', headers=headers)

    def run_traceroute(self):
        return self.client.post('/api/path/traceroute', json={'startLocation': 'r1', 'headers': {}})

    def activate(self, name: str, if_stale: bool = False):
        if if_stale:
            return self.client.post(f'/api/snapshots/{name}/activate', json={'if_stale': True})
        return self.client.post(f'/api/snapshots/{name}/activate')

    def version_state(self, name: str) -> dict:
        response = self.client.get(f'/api/snapshots/{name}/version-state')
        return response.get_json()

    def working_hash(self, name: str) -> str:
        return self.sandbox.poll(name).content_hash

    def snapshot_id(self, name: str) -> str:
        return self.sandbox.snapshot_id(name)

    def upload(self, name: str, filename: str, content: str):
        return self.client.post(
            f'/api/snapshots/{name}/files',
            data={'file': (io.BytesIO(content.encode('utf-8')), filename)},
            content_type='multipart/form-data',
        )

    def active_file(self) -> Path:
        return self.sandbox.data_dir / self.sandbox.state.namespace / 'active_snapshot.json'

    def entry_hashes(self) -> set:
        return {path.parent.name for path in Path(self.sandbox.settings.RESULT_CACHE_DIR).glob('*/*.json.gz')}


class CountingLock:
    """Records every acquisition of the Batfish request lock"""

    def __init__(self, lock):
        self.lock = lock
        self.acquired = 0

    def acquire(self, *args, **kwargs):
        self.acquired += 1
        return self.lock.acquire(*args, **kwargs)

    def release(self):
        return self.lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


class HitAndMissTest(CachedRouteTestCase):
    def test_miss_stores_and_a_hit_serves_the_body_without_the_getter(self):
        self.create('web')
        self.select('web')

        miss = self.nodes()
        hit = self.nodes()

        self.assertEqual(miss.status_code, 200, miss.get_data(as_text=True)[:300])
        self.assertEqual(miss.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(hit.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(decoded(hit), decoded(miss))
        self.assertEqual((self.parses(), self.calls()), (1, 1))
        working = self.working_hash('web')
        for response in (miss, hit):
            self.assertEqual(response.headers['X-Topologix-Snapshot-Id'], self.snapshot_id('web'))
            self.assertEqual(response.headers['X-Topologix-Content-Hash'], working)
            self.assertEqual(response.headers['Cache-Control'], 'private, no-cache')
            self.assertEqual(response.headers['Vary'], 'Accept-Encoding')
            self.assertTrue(response.headers['ETag'].startswith('"') and response.headers['ETag'].endswith('"'))
        self.assertEqual(miss.headers['ETag'], hit.headers['ETag'])
        self.assertEqual(self.entry_hashes(), {working})

    def test_gzip_and_plain_clients_get_the_identical_body_without_the_getter(self):
        self.create('web')
        self.select('web')
        self.nodes()

        compressed = self.nodes(**{'Accept-Encoding': 'gzip'})
        plain = self.nodes()

        self.assertEqual(compressed.headers['Content-Encoding'], 'gzip')
        self.assertNotIn('Content-Encoding', plain.headers)
        self.assertEqual(gzip.decompress(compressed.get_data()), plain.get_data())
        self.assertEqual(self.calls(), 1)

    def test_a_hit_takes_no_lock_switches_no_network_and_activates_nothing(self):
        self.create('web')
        self.select('web')
        self.nodes()
        counting = CountingLock(app_module.batfish_request_lock)

        with mock.patch.object(app_module, 'batfish_request_lock', counting), \
                mock.patch.object(self.service, 'set_network_context', side_effect=AssertionError('switched')), \
                mock.patch.object(self.service, 'initialize_network', side_effect=AssertionError('activated')):
            hit = self.nodes()

        self.assertEqual(hit.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(counting.acquired, 0)
        with app_module.app.test_request_context('/api/network/nodes'):
            self.assertFalse(app_module.request_uses_batfish())

    def test_not_modified_only_for_a_stored_entry(self):
        self.create('web')
        self.select('web')
        stored = self.nodes()
        etag = stored.headers['ETag']
        bare = etag.strip('"')

        for header in (etag, f'W/{etag}', f'"other", {etag}', '*', f'"{bare}:gzip"', f'"{bare}:zstd"',
                       f'W/"{bare}:br"'):
            with self.subTest(header=header):
                response = self.nodes(**{'If-None-Match': header})
                self.assertEqual(response.status_code, 304)
                self.assertEqual(response.headers['ETag'], etag)
                self.assertEqual(response.headers['Cache-Control'], 'private, no-cache')
                self.assertEqual(response.headers['X-Topologix-Snapshot-Id'], self.snapshot_id('web'))
                self.assertEqual(response.headers['X-Topologix-Content-Hash'], self.working_hash('web'))
        self.assertEqual(self.nodes(**{'If-None-Match': '"something-else"'}).status_code, 200)
        self.assertEqual(self.calls(), 1)

    def test_unstored_responses_carry_no_store_and_are_never_answered_304(self):
        self.create('web')
        self.select('web')
        self.node_failures = 2

        first = self.nodes()
        second = self.nodes(**{'If-None-Match': '*'})

        for response in (first, second):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['X-Topologix-Cache'], 'unstored')
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertNotIn('ETag', response.headers)
            self.assertEqual(response.headers['X-Topologix-Content-Hash'], self.working_hash('web'))
        self.assertEqual(self.entry_hashes(), set())
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')

    def test_query_errors_and_error_responses_are_never_stored(self):
        self.create('web')
        self.select('web')
        self.query_errors = [{'data_key': 'bgp_edges'}]

        partial = self.all_data_request()
        self.assertEqual(partial.headers['X-Topologix-Cache'], 'unstored')

        with mock.patch.object(self.service, 'get_node_properties', side_effect=RuntimeError('broken getter')):
            failed = self.nodes()
        self.assertEqual(failed.status_code, 400)
        self.assertEqual(failed.headers['X-Topologix-Cache'], 'unstored')
        self.assertEqual(self.entry_hashes(), set())

    def test_query_failure_count_is_reset_after_the_activation_parse_status_queries(self):
        self.create('web')
        self.select('web')

        def swallowing(*args, **kwargs):
            self.service._count_query_failure()
            return []

        with mock.patch.object(self.service, 'get_file_parse_status', side_effect=swallowing):
            response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')

    def test_a_legacy_md5_if_none_match_on_a_miss_gets_the_full_body(self):
        self.create('web')
        self.select('web')

        response = self.nodes(**{'If-None-Match': hashlib.md5(b'legacy').hexdigest()})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(decoded(response)['data'], [{'node': 'r1'}])

    def test_identical_content_snapshots_never_share_an_etag(self):
        self.create('first', {'configs/r1.cfg': CONFIG_R1})
        self.create('second', {'configs/r1.cfg': CONFIG_R1})
        self.select('first')
        first = self.nodes()
        self.select('second')
        second = self.nodes()

        self.assertEqual(first.headers['X-Topologix-Content-Hash'], second.headers['X-Topologix-Content-Hash'])
        self.assertNotEqual(first.headers['ETag'], second.headers['ETag'])

    def test_hits_still_enforce_the_current_snapshot(self):
        self.create('web')
        self.select('web')
        self.nodes()

        self.select(None)
        missing = self.nodes()
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.get_json()['code'], 'no_active_snapshot')
        self.assertEqual(missing.get_json()['message'], BATFISH_NOT_INITIALIZED_MESSAGE)
        self.assertEqual(missing.headers['X-Topologix-Cache'], 'bypass')

        self.select('vanished')
        gone = self.nodes(**{'If-None-Match': '*'})
        self.assertEqual(gone.status_code, 404)

    def test_a_miss_with_the_loaded_hash_equal_to_the_working_hash_computes_without_activation(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)

        response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 1)
        stale = self.activate('web', if_stale=True)
        self.assertEqual(stale.status_code, 200)
        self.assertFalse(stale.get_json()['data']['parsed'])
        forced = self.activate('web')
        self.assertTrue(forced.get_json()['data']['parsed'])
        self.assertEqual(self.parses(), 2)

    def test_a_stale_load_runs_the_consumable_empty_check_and_uploads_a_staged_copy(self):
        empty = self.create('empty', {'batfish/layer1_topology.json': '{"edges": []}', 'top.cfg': 'x'})
        self.select('empty')
        refused = self.nodes()
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.get_json()['code'], 'snapshot_empty')
        self.assertEqual(self.parses(), 0)
        self.assertTrue(empty.is_dir())

        snapshot = self.create('web', {
            'configs/r1.cfg': CONFIG_R1,
            'configs/.hidden.cfg': 'hidden',
            'configs/r1.cfg~': 'backup',
            'configs/r1.cfg.swp': 'swap',
            'configs/#r1.cfg#': 'autosave',
            '.git/config': 'dot directory',
        })
        os.symlink(snapshot / 'configs' / 'r1.cfg', snapshot / 'configs' / 'link.cfg')
        self.select('web')
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        upload = self.session.uploads[-1]
        self.assertEqual(upload.files, ['configs/r1.cfg'])
        self.assertEqual(upload.path.name, 'web')
        self.assertNotEqual(upload.path, snapshot)
        self.assertFalse(upload.path.exists())
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], self.working_hash('web'))

    def test_a_failed_lazy_activation_keeps_the_name_and_is_negative_cached(self):
        self.create('web')
        self.select('web')
        self.session.failures = [RuntimeError('Work terminated abnormally\nCaused by: x: Parser crashed')]

        first = self.nodes()
        second = self.nodes()

        for response in (first, second):
            self.assertEqual(response.status_code, 422, response.get_data(as_text=True)[:300])
            self.assertEqual(response.get_json()['code'], 'snapshot_activation_failed')
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.parses(), 1)
        self.assertEqual(self.service.current_snapshot_name, 'web')
        self.assertFalse(self.service._initialized)
        self.assertIsNone(self.service.loaded_content_hash)
        self.assertEqual(self.entry_hashes(), set())

    def test_lookups_are_repeated_after_the_key_lock_and_after_ensure_loaded(self):
        self.create('web')
        self.select('web')
        self.nodes()
        original = self.cache.lookup
        seen = []

        def miss_first_then_delegate(*args, **kwargs):
            seen.append(args[0])
            if len(seen) == 1:
                return None
            return original(*args, **kwargs)

        with mock.patch.object(self.cache, 'lookup', side_effect=miss_first_then_delegate):
            relocked = self.nodes()
        self.assertEqual(relocked.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(len(seen), 2)

        seen.clear()

        def miss_twice_then_delegate(*args, **kwargs):
            seen.append(args[0])
            if len(seen) <= 2:
                return None
            return original(*args, **kwargs)

        with mock.patch.object(self.cache, 'lookup', side_effect=miss_twice_then_delegate):
            reloaded = self.nodes()
        self.assertEqual(reloaded.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(len(seen), 3)
        self.assertEqual((self.calls(), self.parses()), (1, 1))

    def test_the_lookup_after_ensure_loaded_uses_the_loaded_hash_while_settling(self):
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 3600
        snapshot = self.create('web')
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 0
        settled = self.working_hash('web')
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 3600
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.assertTrue(self.sandbox.poll('web').external_settling)
        self.assertEqual(self.activate('web').status_code, 200)
        loaded = self.service.loaded_content_hash
        self.assertNotEqual(loaded, settled)

        first = self.nodes()
        second = self.nodes()

        self.assertEqual(first.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(first.headers['X-Topologix-Content-Hash'], loaded)
        self.assertEqual(second.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(second.headers['X-Topologix-Content-Hash'], loaded)
        self.assertEqual(self.parses(), 1)
        self.assertEqual(self.entry_hashes(), {loaded})

    def test_an_external_edit_never_stores_old_parse_results_under_the_new_hash(self):
        snapshot = self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        old = self.service.loaded_content_hash
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        new = self.working_hash('web')
        self.session.failures = [RuntimeError('Batfish unreachable')]

        failed = self.nodes()

        self.assertEqual(failed.status_code, 500)
        self.assertNotIn(new, self.entry_hashes())
        self.assertNotIn(old, self.entry_hashes())
        self.service.activation_failures.clear()
        stored = self.nodes()
        self.assertEqual(stored.headers['X-Topologix-Content-Hash'], new)
        self.assertEqual(self.getter_calls[-1], ('nodes', new))

    def test_corrupt_and_truncated_entries_are_recomputed(self):
        self.create('web')
        self.select('web')
        self.nodes()
        working = self.working_hash('web')
        path = next(Path(self.sandbox.settings.RESULT_CACHE_DIR).glob(f'{working}/*.json.gz'))

        for mutate in (lambda data: b'garbage', lambda data: data[:len(data) // 2]):
            path.write_bytes(mutate(path.read_bytes()))
            with self.assertLogs(CACHE_LOGGER, level='WARNING'):
                response = self.nodes()
            self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.calls(), 3)

    def test_a_partial_temporary_entry_is_removed_at_startup(self):
        tmp_dir = Path(self.sandbox.settings.RESULT_CACHE_DIR) / 'tmp'
        tmp_dir.mkdir(parents=True)
        (tmp_dir / '.entry-crash.tmp').write_bytes(b'partial body')

        self.sandbox.start()

        self.assertEqual(list(tmp_dir.iterdir()), [])

    def test_snapshot_version_is_the_loaded_hash_at_compute_time_on_every_path(self):
        self.create('web')
        self.select('web')
        miss = decoded(self.all_data_request())
        hit = decoded(self.all_data_request())
        working = self.working_hash('web')

        self.assertEqual(miss['data']['snapshot_version'], {'content_hash': working, 'live': False, 'live_hash': None})
        self.assertEqual(hit['data']['snapshot_version'], miss['data']['snapshot_version'])

        self.probe.version = None
        bypass = self.all_data_request()
        self.assertEqual(bypass.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual(decoded(bypass)['data']['snapshot_version']['content_hash'], working)

        self.service._drop_loaded_state()
        self.service.current_snapshot_name = 'web'
        with mock.patch.object(self.service, 'initialize_network', side_effect=RuntimeError('down')):
            failed = self.all_data_request()
        self.assertEqual(failed.status_code, 500)

    def test_health_and_stats_report_the_cache(self):
        health = self.client.get('/api/health').get_json()['data']
        self.assertEqual(health['result_cache'], {'enabled': True})

        self.create('web')
        self.select('web')
        self.nodes()
        stats = self.client.get('/api/cache/stats')
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(set(stats.get_json()['data']), {'entries', 'bytes', 'max_bytes', 'max_entries'})
        self.assertEqual(stats.get_json()['data']['entries'], 1)

    def test_deleting_a_snapshot_viewed_at_two_uncommitted_states_leaves_no_entry(self):
        snapshot = self.create('web')
        self.create('kept', {'configs/r1.cfg': CONFIG_R2})
        self.select('web')
        self.nodes()
        first = self.working_hash('web')
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        self.nodes()
        second = self.working_hash('web')
        self.select('kept')
        self.nodes()
        kept = self.working_hash('kept')
        self.assertEqual(self.entry_hashes(), {first, second, kept})

        self.assertEqual(self.client.delete('/api/snapshots/web').status_code, 200)

        self.assertEqual(self.entry_hashes(), {kept})
        self.assertEqual(self.client.get('/api/cache/stats').get_json()['data']['entries'], 1)

    def test_identity_headers_are_exposed_through_cors(self):
        origin = config.CORS_ORIGINS[0]
        response = self.client.get('/api/health', headers={'Origin': origin})

        exposed = response.headers.get('Access-Control-Expose-Headers', '')
        for header in ('X-Topologix-Snapshot-Id', 'X-Topologix-Content-Hash', 'X-Topologix-Cache'):
            self.assertIn(header, exposed)


class KillSwitchTest(CachedRouteTestCase):
    sandbox_options = {'RESULT_CACHE_ENABLED': False}

    def test_version_state_reports_the_switch(self):
        self.create('web')
        self.assertFalse(self.version_state('web')['data']['result_cache_enabled'])
        self.sandbox.settings.RESULT_CACHE_ENABLED = True
        self.assertTrue(self.version_state('web')['data']['result_cache_enabled'])
        self.assertTrue(self.client.get('/api/health').get_json()['data']['result_cache']['enabled'])

    def test_cached_endpoints_pass_through_with_no_store_only(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        original = app_module.success_response

        def with_legacy_headers(*args, **kwargs):
            response = original(*args, **kwargs)
            response.headers['ETag'] = 'legacy'
            response.headers['Expires'] = 'Thu, 01 Jan 2099 00:00:00 GMT'
            response.headers['Cache-Control'] = 'public, max-age=300'
            return response

        counting = CountingLock(app_module.batfish_request_lock)
        with mock.patch.object(app_module, 'success_response', side_effect=with_legacy_headers), \
                mock.patch.object(app_module, 'batfish_request_lock', counting):
            first = self.nodes()
            second = self.nodes(**{'If-None-Match': '*'})

        for response in (first, second):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            for header in ('ETag', 'Expires', 'X-Topologix-Snapshot-Id', 'X-Topologix-Content-Hash',
                           'X-Topologix-Cache'):
                self.assertNotIn(header, response.headers)
        self.assertEqual(counting.acquired, 2)
        self.assertEqual(self.calls(), 2)
        self.assertEqual(self.entry_hashes(), set())
        with app_module.app.test_request_context('/api/network/nodes'):
            self.assertTrue(app_module.request_uses_batfish())

    def test_nodes_without_a_snapshot_answer_todays_not_initialized_message(self):
        response = self.nodes()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['message'], BATFISH_NOT_INITIALIZED_MESSAGE)
        self.assertNotIn('code', response.get_json())

    def test_no_seeding_and_cache_clear_is_a_pure_no_op(self):
        self.create('web')
        self.working_hash('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertTrue(self.active_file().is_file())
        self.restart(seed=True)
        self.assertIsNone(self.service.current_snapshot_name)

        cleared = self.client.post('/api/snapshots/web/cache/clear')
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.get_json()['data'], {'cleared': False})
        self.assertFalse(self.sandbox.state.reparse_requested(self.snapshot_id('web')))
        self.assertIsNone(self.sandbox.row(self.snapshot_id('web')).clear_seq)

    def test_a_live_parse_keeps_its_live_hash_after_an_external_edit(self):
        snapshot = self.create('web')
        working = self.working_hash('web')
        with mock.patch.object(self.sandbox.state, 'stage_for_upload', side_effect=OSError(errno.ENOSPC, 'full')), \
                self.assertLogs('services.batfish_service', level='WARNING'):
            self.assertEqual(self.activate('web').status_code, 200)
        before = decoded(self.all_data_request())['data']['snapshot_version']
        self.assertEqual(before, {'content_hash': None, 'live': True, 'live_hash': working})
        self.assertTrue(self.version_state('web')['data']['loaded_live'])

        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        self.assertFalse(self.version_state('web')['data']['loaded_live'])
        after = decoded(self.all_data_request())['data']['snapshot_version']
        self.assertEqual(after['live_hash'], working)
        self.assertEqual(self.parses(), 1)

    def test_snapshot_version_is_the_loaded_hash_under_the_kill_switch(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)

        body = decoded(self.all_data_request())

        self.assertEqual(body['data']['snapshot_version'], {
            'content_hash': self.working_hash('web'), 'live': False, 'live_hash': None,
        })

    def test_name_only_fallback_re_activates_a_dropped_state_and_negative_caches_failures(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.service._drop_loaded_state()

        recovered = self.nodes()
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(self.parses(), 2)

        self.service._drop_loaded_state()
        self.session.failures = [RuntimeError('Batfish restarting')]
        failed = self.nodes()
        again = self.nodes()
        for response in (failed, again):
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.get_json()['code'], 'snapshot_activation_error')
        self.assertEqual(self.parses(), 3)
        self.assertEqual(self.service.current_snapshot_name, 'web')
        self.assertTrue(self.active_file().is_file())
        key = app_module.activation_failure_key(self.snapshot_id('web'), 'web')
        self.assertEqual(key[0], 'id')
        self.assertIsNotNone(self.service.activation_failures.get(key))

    def test_a_snapshot_without_an_id_is_negative_cached_by_its_name(self):
        legacy = self.sandbox.snapshots_dir / 'legacy'
        write_file(legacy / 'configs' / 'r1.cfg', CONFIG_R1)
        self.assertEqual(self.activate('legacy').status_code, 200)
        self.assertIsNone(self.sandbox.state.read_sidecar_id(legacy))
        self.service._drop_loaded_state()
        self.session.failures = [RuntimeError('Batfish restarting')]

        self.assertEqual(self.nodes().status_code, 500)
        self.assertEqual(self.nodes().status_code, 500)

        self.assertEqual(self.parses(), 2)
        key = ('name', self.sandbox.state.namespace, 'legacy')
        self.assertIsNotNone(self.service.activation_failures.get(key))

    def test_a_deleted_snapshots_entries_are_evicted_under_the_kill_switch(self):
        self.create('web')
        working = self.working_hash('web')
        writer = self.make_cache()
        writer.store(working, 'get_nodes', '', BODY, self.sandbox.history.db_id, None,
                     batfish_version=BATFISH_VERSION)
        self.install(self.make_cache())
        self.assertEqual(self.entry_hashes(), {working})

        self.assertEqual(self.client.delete('/api/snapshots/web').status_code, 200)

        self.assertEqual(self.entry_hashes(), set())
        self.assertEqual(self.client.get('/api/cache/stats').get_json()['data']['entries'], 0)


class BypassTest(CachedRouteTestCase):
    def assert_bypass(self, response, snapshot_id: str | None = None):
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], '')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('ETag', response.headers)
        self.assertNotIn('Expires', response.headers)
        if snapshot_id is not None:
            self.assertEqual(response.headers['X-Topologix-Snapshot-Id'], snapshot_id)
        self.assertEqual(self.entry_hashes(), set())

    def prepared(self) -> str:
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        return self.snapshot_id('web')

    def test_unknown_batfish_version_bypasses(self):
        snapshot_id = self.prepared()
        self.probe.version = None
        self.assert_bypass(self.nodes(), snapshot_id)
        self.assert_bypass(self.nodes(), snapshot_id)
        self.assertEqual(self.calls(), 2)

    def test_globally_and_per_snapshot_unavailable_versioning_bypasses(self):
        snapshot_id = self.prepared()
        self.sandbox.state.mark_versioning_unavailable(self.sandbox.state.id_key(snapshot_id), 'missing_objects')
        self.assert_bypass(self.nodes(), snapshot_id)
        self.sandbox.state.clear_versioning_unavailable(self.sandbox.state.id_key(snapshot_id))
        self.sandbox.state.mark_globally_unavailable('namespace')
        self.assert_bypass(self.nodes(), snapshot_id)

    def test_null_working_hash_bypasses(self):
        self.create('web')
        self.select('web')
        original_scan = self.sandbox.state.scan_tree_or_none
        counter = iter(range(10_000))

        def moving(snapshot_dir):
            scan = original_scan(snapshot_dir)
            if scan is not None:
                scan.fingerprint = sha(f'{scan.fingerprint}:{next(counter)}')
            return scan

        with mock.patch.object(self.sandbox.state, 'scan_tree_or_none', side_effect=moving):
            self.assert_bypass(self.nodes())

    def test_injected_machinery_failures_bypass_and_a_store_failure_only_skips_storing(self):
        snapshot_id = self.prepared()
        failures = {
            'state evaluation': mock.patch.object(self.sandbox.state, 'evaluate_snapshot',
                                                  side_effect=RuntimeError('evaluation failed')),
            'hashing': mock.patch.object(self.sandbox.state, '_hash_scan', side_effect=OSError(errno.EIO, 'io')),
            'runtime database error': mock.patch.object(
                self.sandbox.state, '_resolve_rows',
                side_effect=OperationalError('SELECT 1', {}, Exception('database is unavailable')),
            ),
            'cache read': mock.patch.object(self.cache, 'lookup', side_effect=OSError(errno.EIO, 'io')),
        }
        for label, patch in failures.items():
            with self.subTest(failure=label):
                write_file(self.sandbox.snapshots_dir / 'web' / 'configs' / f'{uuid.uuid4().hex}.cfg', label)
                app_module._cache_degradations_logged.clear()
                with patch, self.assertLogs('app', level='WARNING') as logs:
                    self.assert_bypass(self.nodes(), snapshot_id)
                warnings = [line for line in logs.output if line.startswith('WARNING:app:')]
                self.assertEqual(len(warnings), 1, warnings)
                self.assertTrue(warnings[0].endswith('; the request is answered without the result cache'))
                if label == 'cache read':
                    self.assertEqual(warnings[0], 'WARNING:app:Result cache lookup failed (OSError); '
                                                  'the request is answered without the result cache')

        with mock.patch.object(self.cache, 'store', side_effect=OSError(errno.ENOSPC, 'full')), \
                self.assertLogs('app', level='WARNING') as logs:
            response = self.nodes()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Topologix-Cache'], 'unstored')
        self.assertEqual(self.entry_hashes(), set())
        self.assertEqual(
            logs.output, ['WARNING:app:Result cache store failed (OSError); the result is served without being stored'],
        )

    def test_an_eviction_failure_keeps_the_stored_entry_and_warns_once_that_limits_are_not_enforced(self):
        self.prepared()
        app_module._cache_degradations_logged.clear()
        expected = 'Result cache eviction failed (OSError); size limits are not enforced until it succeeds'

        with mock.patch.object(self.cache, 'evict_if_needed', side_effect=OSError(errno.EIO, 'io')), \
                self.assertLogs('app', level='DEBUG') as logs:
            stored = self.nodes()
            again = self.all_data_request()

        self.assertEqual(stored.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(again.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual([line for line in logs.output if line.startswith('WARNING:app:')], [f'WARNING:app:{expected}'])
        self.assertIn(f'DEBUG:app:{expected}', logs.output)
        self.assertFalse(any('bypass' in line for line in logs.output))

    def test_a_missing_auth_off_selection_stays_selected_with_one_warning(self):
        snapshot = self.create('gone')
        self.select('gone')
        os.rename(snapshot, snapshot.with_name('gone-moved-away'))
        app_module._kept_selections_logged.clear()
        expected = 'Active snapshot gone is missing; it stays selected'

        with self.assertLogs('app', level='DEBUG') as logs:
            first = self.nodes()
            second = self.all_data_request()

        self.assertEqual((first.status_code, second.status_code), (404, 404))
        self.assertEqual(self.service.current_snapshot_name, 'gone')
        self.assertEqual([line for line in logs.output if line.startswith('WARNING:app:')], [f'WARNING:app:{expected}'])
        self.assertIn(f'DEBUG:app:{expected}', logs.output)
        self.assertFalse(any('Cleared' in line for line in logs.output))

    def test_bypass_keeps_todays_hook_semantics_and_re_activates_a_dropped_state(self):
        self.prepared()
        self.probe.version = None
        self.service._drop_loaded_state()

        response = self.nodes()

        self.assert_bypass(response)
        self.assertEqual(self.parses(), 2)


def failing_staging():
    return mock.patch.object(
        state_module.SnapshotStateService, 'stage_for_upload', side_effect=OSError(errno.ENOSPC, 'full'),
    )


class LiveFallbackTest(CachedRouteTestCase):
    def failing_staging(self):
        return failing_staging()

    def test_a_persistent_staging_failure_costs_one_live_parse(self):
        snapshot = self.create('web')
        self.select('web')
        working = self.working_hash('web')
        with self.failing_staging(), self.assertLogs('services.batfish_service', level='WARNING'):
            first = self.nodes()
            second = self.nodes()
            traced = self.run_traceroute()
            other = self.create('other')
            self.service._load_snapshot(other, 'other')
            stale = self.activate('web', if_stale=True)
            state = self.version_state('web')['data']
            all_data = decoded(self.all_data_request())

        self.assertEqual(self.session.uploads[0].path, snapshot)
        self.assertEqual(self.session.uploads[1].path, other)
        self.assertEqual(self.parses(), 2)
        for response in (first, second):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual(traced.status_code, 200)
        self.assertFalse(stale.get_json()['data']['parsed'])
        self.assertTrue(state['loaded_live'])
        self.assertIsNone(state['loaded_content_hash'])
        self.assertEqual(all_data['data']['snapshot_version'], {'content_hash': None, 'live': True, 'live_hash': working})
        self.assertEqual(self.service.live_loaded[:3], (NETWORK, 'web', working))
        self.assertEqual(self.entry_hashes(), set())

    def test_the_staging_retry_after_60_seconds_uploads_nothing_until_staging_recovers(self):
        self.create('web')
        self.select('web')
        with self.failing_staging(), self.assertLogs('services.batfish_service', level='WARNING'):
            self.nodes()
        marker = self.service.live_loaded
        self.service.live_loaded = (*marker[:3], time.monotonic() - 61)

        with self.failing_staging():
            self.nodes()
        self.assertEqual(self.parses(), 1)
        self.assertGreater(self.service.live_loaded[3], time.monotonic() - 5)

        self.service.live_loaded = (*marker[:3], time.monotonic() - 61)
        recovered = self.nodes()

        self.assertEqual(self.parses(), 2)
        self.assertIsNone(self.service.live_loaded)
        self.assertEqual(recovered.headers['X-Topologix-Cache'], 'stored')
        state = self.version_state('web')['data']
        self.assertFalse(state['loaded_live'])
        self.assertEqual(state['loaded_content_hash'], state['content_hash'])
        self.assertEqual(decoded(self.all_data_request())['data']['snapshot_version']['live'], False)

    def test_a_live_fallback_is_refused_when_the_snapshot_contains_a_symlink(self):
        for label, link in (('plain', 'configs/link.cfg'), ('dot directory', '.hidden/link.cfg'),
                            ('excluded name', 'configs/x~')):
            with self.subTest(link=label):
                name = f"link-{label.replace(' ', '-')}"
                snapshot = self.create(name)
                (snapshot / link).parent.mkdir(parents=True, exist_ok=True)
                os.symlink(snapshot / 'configs' / 'r1.cfg', snapshot / link)
                self.service._reset_loaded_state()
                before = self.parses()

                with self.failing_staging(), self.assertLogs('services.batfish_service', level='WARNING'):
                    response = self.activate(name)

                self.assertEqual(response.status_code, 500)
                self.assertEqual(response.get_json()['code'], 'snapshot_activation_error')
                self.assertEqual(self.parses(), before)

    def test_clear_in_live_mode_costs_exactly_one_parse_also_after_a_restart(self):
        self.create('web')
        self.select('web')
        with self.failing_staging(), self.assertLogs('services.batfish_service', level='WARNING'):
            self.nodes()
            self.assertEqual(self.client.post('/api/snapshots/web/cache/clear').get_json()['data'], {'cleared': True})
            for _ in range(3):
                self.assertEqual(self.nodes().status_code, 200)
            self.assertEqual(self.parses(), 2)

            self.restart()
            self.assertEqual(self.service.current_snapshot_name, 'web')
            for _ in range(3):
                self.assertEqual(self.nodes().status_code, 200)
        self.assertEqual(self.parses(), 3)


class InvalidNamespaceTest(CachedRouteTestCase):
    sandbox_options = {'DEPLOYMENT_ID': '../x'}

    def test_active_snapshot_file_is_neither_written_nor_read(self):
        self.create('web')
        self.assertFalse(self.sandbox.state.namespace_valid)

        self.assertEqual(self.activate('web').status_code, 200)

        written = list(self.sandbox.root.rglob('active_snapshot.json'))
        self.assertEqual(written, [])
        self.assertFalse((self.sandbox.data_dir.parent / 'x').exists())
        self.assertIsNone(self.sandbox.state._active_snapshot_path())
        self.assertIsNone(self.sandbox.state.load_active_snapshot_once())
        self.assertEqual(self.parses(), 1)
        self.assertEqual(self.session.uploads[0].path.name, 'web')
        self.assertIn(state_module.INVALID_NAMESPACE_DIRNAME, str(self.session.uploads[0].path))


class CacheClearTest(CachedRouteTestCase):
    def clear(self, name: str = 'web'):
        return self.client.post(f'/api/snapshots/{name}/cache/clear')

    def test_clear_drops_the_entry_requests_a_re_parse_and_the_etag_tracks_the_body(self):
        self.create('web')
        self.select('web')
        first = self.nodes()
        snapshot_id = self.snapshot_id('web')

        cleared = self.clear()

        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.get_json()['data'], {'cleared': True})
        self.assertTrue(self.sandbox.state.reparse_requested(snapshot_id))
        self.assertEqual(self.sandbox.row(snapshot_id).clear_seq, 1)
        self.assertEqual(self.entry_hashes(), set())
        same = self.nodes()
        self.assertEqual(same.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)
        self.assertFalse(self.sandbox.state.reparse_requested(snapshot_id))
        self.assertEqual(same.headers['ETag'], first.headers['ETag'])

        self.clear()
        self.node_rows = [{'node': 'r1'}, {'node': 'r2'}]
        changed = self.nodes()
        self.assertEqual(self.parses(), 3)
        self.assertNotEqual(changed.headers['ETag'], first.headers['ETag'])
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')

    def test_a_cleared_entry_whose_file_stays_is_kept_in_the_index_and_never_served_as_a_hit(self):
        self.create('web')
        self.select('web')
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
        entry_files = set(Path(self.cache.cache_dir).rglob('*.json.gz'))
        real_unlink = Path.unlink

        def unlink(path, *args, **kwargs):
            if path in entry_files:
                raise PermissionError(errno.EACCES, 'denied')
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, 'unlink', autospec=True, side_effect=unlink), \
                self.assertLogs(CACHE_LOGGER, level='WARNING'):
            self.assertEqual(self.clear().get_json()['data'], {'cleared': True})

        self.assertEqual(len(entry_files), 1)
        self.assertTrue(all(path.is_file() for path in entry_files))
        self.assertEqual(self.cache.stats()['entries'], 1)
        after = self.nodes()
        self.assertEqual(after.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)

    def test_clear_keeps_a_hash_shared_with_another_snapshot_and_every_endpoint_is_recomputed_once(self):
        self.create('cleared', {'configs/r1.cfg': CONFIG_R1})
        self.create('sharing', {'configs/r1.cfg': CONFIG_R1})
        self.select('sharing')
        self.nodes()
        self.all_data_request()
        shared = self.working_hash('sharing')
        self.select('cleared')
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')

        self.assertEqual(self.clear('cleared').get_json()['data'], {'cleared': True})
        self.assertEqual(self.entry_hashes(), {shared})

        parses = self.parses()
        recomputed_nodes = self.nodes()
        recomputed_all = self.all_data_request()
        self.assertEqual(recomputed_nodes.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(recomputed_all.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), parses + 1)
        self.assertEqual((self.calls('nodes'), self.calls('all-data')), (2, 2))
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')

        self.select('sharing')
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')

    def test_a_pre_clear_parse_of_a_sharing_snapshot_never_serves_the_cleared_one(self):
        self.create('cleared', {'configs/r1.cfg': CONFIG_R1})
        self.create('sharing', {'configs/r1.cfg': CONFIG_R1})
        self.assertEqual(self.activate('sharing').status_code, 200)
        self.assertEqual(self.service.loaded_clear_counter, 0)
        self.clear('cleared')

        self.assertEqual(self.all_data_request().headers['X-Topologix-Cache'], 'stored')
        self.select('cleared')
        response = self.all_data_request()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.calls('all-data'), 2)

    def test_an_entry_of_another_database_is_ignored_and_overwritten(self):
        self.create('web')
        self.select('web')
        working = self.working_hash('web')
        foreign_db = str(uuid.uuid4())
        self.cache.store(working, 'get_nodes', '', b'{"data":"foreign","status":"success"}', foreign_db, 99,
                         batfish_version=BATFISH_VERSION)

        response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(decoded(response)['data'], [{'node': 'r1'}])
        path = next(Path(self.sandbox.settings.RESULT_CACHE_DIR).glob(f'{working}/*.json.gz'))
        self.assertIn(self.sandbox.history.db_id.encode(), path.read_bytes())

    def test_a_failed_clear_counter_read_stores_a_none_stamp_until_the_next_clear(self):
        self.create('web')
        self.select('web')
        state = self.sandbox.state
        original_read = state.read_clear_counter

        def failing_read():
            database = state._db
            broken = mock.Mock()
            broken.get_db_session.side_effect = OperationalError('SELECT 1', {}, Exception('database is unavailable'))
            state._db = broken
            try:
                return original_read()
            finally:
                state._db = database

        with mock.patch.object(state, 'read_clear_counter', side_effect=failing_read), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            stored = self.nodes()
        self.assertEqual(stored.headers['X-Topologix-Cache'], 'stored')
        self.assertIsNone(self.service.loaded_clear_counter)
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')

        self.clear()
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertFalse(self.sandbox.state.reparse_requested(self.snapshot_id('web')))
        self.cache.store(self.working_hash('web'), 'get_nodes', '', BODY, self.sandbox.history.db_id, None,
                         batfish_version=BATFISH_VERSION)
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)

    def test_a_restart_after_a_clear_of_a_shared_hash_still_recomputes(self):
        self.create('cleared', {'configs/r1.cfg': CONFIG_R1})
        self.create('sharing', {'configs/r1.cfg': CONFIG_R1})
        self.select('sharing')
        self.nodes()
        self.clear('cleared')
        self.assertEqual(self.entry_hashes(), {self.working_hash('cleared')})

        self.restart(seed=False)
        self.install(self.make_cache(clock=lambda: 0.0))
        self.select('cleared')
        response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.calls(), 2)

    def test_clear_with_a_null_working_hash_only_requests_a_re_parse(self):
        self.create('web')
        unrelated = sha('unrelated entry')
        self.cache.store(unrelated, 'get_nodes', '', BODY, self.sandbox.history.db_id, None,
                         batfish_version=BATFISH_VERSION)
        original_scan = self.sandbox.state.scan_tree
        counter = iter(range(10_000))

        def moving(snapshot_dir):
            scan = original_scan(snapshot_dir)
            scan.fingerprint = sha(f'{scan.fingerprint}:{next(counter)}')
            return scan

        with mock.patch.object(self.sandbox.state, 'scan_tree', side_effect=moving):
            response = self.clear()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['data'], {'cleared': False})
        self.assertTrue(self.sandbox.state.reparse_requested(self.snapshot_id('web')))
        self.assertEqual(self.entry_hashes(), {unrelated})

    def test_unavailable_versioning_answers_503_before_the_kill_switch(self):
        self.create('web')
        self.sandbox.settings.RESULT_CACHE_ENABLED = False
        self.sandbox.settings.DATA_DIR_FELL_BACK = True
        self.restart(seed=False)
        response = self.clear()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['details'], {'reason': 'storage'})

        self.sandbox.settings.DATA_DIR_FELL_BACK = False
        database = self.sandbox.db
        self.sandbox.db = None
        try:
            self.restart(seed=False)
            response = self.clear()
        finally:
            self.sandbox.db = database
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['details'], {'reason': 'database'})

    def test_clear_then_an_edit_its_if_stale_activation_and_a_cached_request_cost_one_parse(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.clear()
        parses = self.parses()

        self.assertEqual(self.upload('web', 'r2.cfg', CONFIG_R2).status_code, 200)
        stale = self.activate('web', if_stale=True)
        response = self.nodes()

        self.assertTrue(stale.get_json()['data']['parsed'])
        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), parses + 1)

    def test_forced_activation_layer1_reload_and_initialize_clear_the_request(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        snapshot_id = self.snapshot_id('web')
        layer1 = {'edges': [{'node1': {'hostname': 'r1', 'interfaceName': 'e0'},
                             'node2': {'hostname': 'r2', 'interfaceName': 'e0'}}]}
        for label, trigger in (
            ('forced activation', lambda: self.activate('web')),
            ('layer 1 reload', lambda: self.client.put('/api/snapshots/web/layer1-topology', json=layer1)),
            ('initialize', lambda: self.client.post('/api/network/initialize', json={'snapshot_name': 'web'})),
        ):
            with self.subTest(trigger=label):
                self.clear()
                self.assertTrue(self.sandbox.state.reparse_requested(snapshot_id))
                self.assertEqual(trigger().status_code, 200)
                self.assertFalse(self.sandbox.state.reparse_requested(snapshot_id))
                parses = self.parses()
                self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
                self.assertEqual(self.parses(), parses)


class ActivationTest(CachedRouteTestCase):
    def test_activate_and_initialize_responses_carry_parsed(self):
        self.create('web')
        self.assertTrue(self.activate('web').get_json()['data']['parsed'])
        initialized = self.client.post('/api/network/initialize', json={'snapshot_dir': 'web'})
        self.assertEqual(initialized.status_code, 200)
        self.assertEqual(initialized.get_json()['message'], 'Network initialized successfully')
        self.assertTrue(initialized.get_json()['data']['parsed'])
        self.assertFalse(self.activate('web', if_stale=True).get_json()['data']['parsed'])
        self.assertEqual(self.client.post('/api/snapshots/web/activate', json={'if_stale': 'yes'}).status_code, 400)

    def test_a_failed_if_stale_parse_is_a_forced_failure_and_is_replayed_without_parsing(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertEqual(self.upload('web', 'r2.cfg', CONFIG_R2).status_code, 200)
        self.session.failures = [RuntimeError('Batfish rejected the snapshot')]

        failed = self.activate('web', if_stale=True)
        self.assertEqual(failed.status_code, 500)
        self.assertIsNone(self.service.current_snapshot_name)
        self.assertFalse(self.active_file().exists())
        parses = self.parses()

        self.select('web')
        self.service._initialized = True
        self.service.loaded_content_hash = 'previous'
        replayed = self.activate('web', if_stale=True)

        self.assertEqual(replayed.status_code, 500)
        self.assertEqual(self.parses(), parses)
        self.assertIsNone(self.service.current_snapshot_name)
        self.assertFalse(self.service._initialized)
        self.assertIsNone(self.service.loaded_content_hash)

        forced = self.activate('web')
        self.assertEqual(forced.status_code, 200)
        self.assertEqual(self.parses(), parses + 1)

    def test_if_stale_without_a_working_hash_always_parses_and_never_replays(self):
        self.create('web')
        self.sandbox.state.mark_globally_unavailable('database')
        self.session.failures = [RuntimeError('broken file')]

        self.assertEqual(self.activate('web', if_stale=True).status_code, 500)
        fixed = self.activate('web', if_stale=True)
        again = self.activate('web', if_stale=True)

        self.assertEqual(fixed.status_code, 200)
        self.assertTrue(fixed.get_json()['data']['parsed'])
        self.assertTrue(again.get_json()['data']['parsed'])
        self.assertEqual(self.parses(), 3)

    def test_if_stale_for_a_missing_objects_snapshot_parses_once(self):
        self.create('web')
        snapshot_id = self.snapshot_id('web')
        self.sandbox.poll('web')
        self.sandbox.state.mark_versioning_unavailable(self.sandbox.state.id_key(snapshot_id), 'missing_objects')

        response = self.activate('web', if_stale=True)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['data']['parsed'])
        self.assertEqual(self.parses(), 1)

    def test_a_forced_activation_within_60_seconds_of_a_failure_parses_again(self):
        self.create('web')
        self.session.failures = [RuntimeError('broken')]
        self.assertEqual(self.activate('web').status_code, 500)

        self.assertEqual(self.activate('web').status_code, 200)
        self.assertEqual(self.parses(), 2)

    def test_a_success_removes_every_failure_so_drops_and_clears_re_parse(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.sandbox.state.mark_globally_unavailable('database')
        self.service._drop_loaded_state()
        self.session.failures = [RuntimeError('broken')]
        self.assertEqual(self.run_traceroute().status_code, 500)
        self.assertEqual(self.run_traceroute().status_code, 500)
        self.assertEqual(self.parses(), 2)

        self.assertEqual(self.activate('web').status_code, 200)
        self.service._drop_loaded_state()
        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 4)
        self.sandbox.state._global_reasons.discard('database')
        self.assertEqual(self.client.post('/api/snapshots/web/cache/clear').get_json()['data'], {'cleared': True})
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 5)

    def test_a_layer1_reload_failure_records_the_failure(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.session.failures = [RuntimeError('broken')]
        layer1 = {'edges': []}

        response = self.client.put('/api/snapshots/web/layer1-topology', json=layer1)

        self.assertEqual(response.status_code, 500)
        snapshot_id = self.snapshot_id('web')
        recorded = [key for key in self.service.activation_failures._entries if snapshot_id in key]
        self.assertEqual(len(recorded), 1)

    def test_forced_failures_clear_the_stored_name_and_lazy_failures_keep_it(self):
        self.create('alpha')
        self.create('beta')
        self.assertEqual(self.activate('alpha').status_code, 200)
        loaded = self.service.loaded_content_hash
        self.session.failures = [RuntimeError('broken beta')]

        self.assertEqual(self.activate('beta').status_code, 500)
        self.assertEqual(
            (self.service.current_snapshot_name, self.service._initialized, self.service.loaded_content_hash),
            ('alpha', True, loaded),
        )
        self.assertEqual(json.loads(self.active_file().read_text())['snapshot_name'], 'alpha')

        self.service._drop_loaded_state()
        self.session.failures = [RuntimeError('Batfish restarting')]
        self.assertEqual(self.run_traceroute().status_code, 500)
        self.assertEqual(self.service.current_snapshot_name, 'alpha')
        self.assertTrue(self.active_file().is_file())

        self.session.failures = [RuntimeError('broken alpha')]
        self.assertEqual(self.activate('alpha').status_code, 500)
        self.assertIsNone(self.service.current_snapshot_name)
        self.assertFalse(self.active_file().exists())

    def test_a_negative_cache_replay_for_another_snapshot_keeps_the_current_one(self):
        self.create('alpha')
        self.create('beta')
        self.assertEqual(self.upload('alpha', 'r2.cfg', CONFIG_R2).status_code, 200)
        self.session.failures = [RuntimeError('broken alpha')]
        self.assertEqual(self.activate('alpha', if_stale=True).status_code, 500)
        self.assertEqual(self.activate('beta').status_code, 200)

        replayed = self.activate('alpha', if_stale=True)

        self.assertEqual(replayed.status_code, 500)
        self.assertEqual(self.service.current_snapshot_name, 'beta')
        self.assertTrue(self.service._initialized)
        self.assertEqual(json.loads(self.active_file().read_text())['snapshot_name'], 'beta')

    def test_active_snapshot_file_failures_never_change_the_outcome(self):
        self.create('web')
        for code in (errno.ENOSPC, errno.EACCES):
            with self.subTest(errno=errno.errorcode[code]):
                with mock.patch('services.snapshot_state_service.tempfile.mkstemp', side_effect=OSError(code, 'x')), \
                        self.assertLogs(STATE_LOGGER, level='WARNING'):
                    response = self.activate('web')
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()['data']['parsed'])
                self.assertEqual(self.service.current_snapshot_name, 'web')

        self.assertEqual(self.activate('web').status_code, 200)
        self.assertTrue(self.active_file().is_file())
        with mock.patch.object(Path, 'unlink', side_effect=OSError(errno.EACCES, 'read-only')), \
                self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            response = self.client.delete('/api/snapshots/web')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any('could not be removed' in line for line in logs.output))
        self.assertTrue(self.active_file().is_file())

    def test_unusable_stored_names_leave_the_start_unseeded(self):
        self.create('web')
        path = self.active_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        for label, content in (('corrupt', '{not json'), ('invalid name', '{"snapshot_name": "../web"}'),
                               ('gone', '{"snapshot_name": "vanished"}'), ('not a string', '{"snapshot_name": 5}')):
            with self.subTest(content=label):
                path.write_text(content, encoding='utf-8')
                with self.assertLogs(STATE_LOGGER, level='WARNING'):
                    self.restart(seed=True)
                self.assertIsNone(self.service.current_snapshot_name)

        path.unlink()
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            self.restart(seed=True)
        self.assertIsNone(self.service.current_snapshot_name)

    def test_deleting_the_named_snapshot_removes_the_file_whatever_the_process_name(self):
        self.create('other')
        for current in (None, 'other'):
            with self.subTest(current=current):
                self.create('named')
                self.assertEqual(self.activate('named').status_code, 200)
                self.select(current)

                self.assertEqual(self.client.delete('/api/snapshots/named').status_code, 200)

                self.assertFalse(self.active_file().exists())
                self.assertEqual(self.service.current_snapshot_name, current)

    def test_a_hit_is_served_after_a_restart_with_the_seeded_name(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')

        self.restart(seed=True)
        self.assertEqual(self.service.current_snapshot_name, 'web')
        self.assertFalse(self.service._initialized)
        response = self.nodes()

        self.assertEqual(response.headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(self.parses(), 1)

    def test_clear_active_snapshot_deletes_the_stored_name(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)

        self.assertEqual(self.client.delete('/api/snapshots/web').status_code, 200)

        self.assertFalse(self.active_file().exists())
        self.assertIsNone(self.service.current_snapshot_name)


class LazyLoadHookTest(CachedRouteTestCase):
    def test_non_cached_requests_re_parse_lazily_after_a_restart_and_a_state_drop(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.restart(seed=True)

        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 2)
        self.service._drop_loaded_state()
        excluded = self.client.get('/api/acl/filter-line-reachability')
        self.assertEqual(excluded.status_code, 200)
        self.assertEqual(self.parses(), 3)
        self.assertNotIn('X-Topologix-Cache', excluded.headers)
        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 3)

    def test_initialize_is_skipped_and_no_snapshot_passes_through(self):
        response = self.run_traceroute()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['message'], BATFISH_NOT_INITIALIZED_MESSAGE)

        self.create('web')
        self.select('web')
        initialized = self.client.post('/api/network/initialize', json={'snapshot_name': 'web'})
        self.assertEqual(initialized.status_code, 200)
        self.assertEqual(self.parses(), 1)

    def test_name_only_semantics_when_versioning_is_unavailable_or_the_state_fails(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertEqual(self.upload('web', 'r2.cfg', CONFIG_R2).status_code, 200)
        self.sandbox.state.mark_globally_unavailable('database')

        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 1)
        self.service._drop_loaded_state()
        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 2)

        self.sandbox.state._global_reasons.discard('database')
        with mock.patch.object(self.sandbox.state, 'evaluate_snapshot', side_effect=RuntimeError('state failed')), \
                self.assertLogs('app', level='WARNING'):
            self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 2)

    def test_a_hash_driven_lazy_failure_keeps_the_snapshot_selected(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.service._drop_loaded_state()
        self.session.failures = [ConnectionError('Batfish is restarting')]

        response = self.run_traceroute()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()['code'], 'snapshot_activation_error')
        self.assertEqual(self.service.current_snapshot_name, 'web')
        self.assertEqual(json.loads(self.active_file().read_text())['snapshot_name'], 'web')

    def test_a_probed_version_change_re_parses(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.assertEqual(self.service.loaded_batfish_version, BATFISH_VERSION)
        self.probe.version = '2026.01.01'

        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 2)
        self.assertEqual(self.service.loaded_batfish_version, '2026.01.01')
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)

    def test_a_fresh_activation_is_not_repeated_while_settling(self):
        snapshot = self.create('web')
        self.working_hash('web')
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 3600
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.assertEqual(self.activate('web').status_code, 200)

        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), 1)


class InitializeRouteTest(CachedRouteTestCase):
    def initialize(self, body: dict):
        return self.client.post('/api/network/initialize', json=body)

    def test_the_name_rule_and_the_resolved_path_comparison(self):
        self.create('web')
        outside = Path(self.sandbox.root) / 'outside' / 'web'
        outside.mkdir(parents=True)
        nested = self.sandbox.snapshots_dir / 'web' / 'configs'

        cases = {
            'missing name': ({'snapshot_name': 'nothing'}, 404),
            'missing directory basename': ({'snapshot_dir': 'nothing'}, 404),
            'absolute outside the store': ({'snapshot_dir': str(outside)}, 400),
            'relative outside the store': ({'snapshot_dir': '../outside/web'}, 400),
            'nested path': ({'snapshot_dir': str(nested), 'snapshot_name': 'web'}, 400),
            'mismatched name': ({'snapshot_dir': 'web', 'snapshot_name': 'other'}, 404),
            'dot dot': ({'snapshot_name': '..'}, 400),
            'slash': ({'snapshot_name': '/'}, 400),
            'separator': ({'snapshot_name': 'a/b'}, 400),
            'traversal pair': ({'snapshot_dir': '../x', 'snapshot_name': '../x'}, 400),
        }
        self.create('other')
        cases['mismatched name'] = ({'snapshot_dir': 'web', 'snapshot_name': 'other'}, 400)
        sidecar = self.sandbox.snapshots_dir / 'web' / '.topologix-snapshot.json'
        before = sidecar.read_bytes()
        for label, (body, status) in cases.items():
            with self.subTest(case=label):
                response = self.initialize(body)
                self.assertEqual(response.status_code, status, response.get_data(as_text=True)[:300])
        self.assertEqual(self.parses(), 0)
        self.assertEqual(sidecar.read_bytes(), before)
        staging = self.sandbox.data_dir / self.sandbox.state.namespace / 'staging'
        self.assertFalse(staging.exists() and any(staging.iterdir()))

        for body in ({'snapshot_dir': 'web'}, {'snapshot_dir': str(self.sandbox.snapshots_dir / 'web')},
                     {'snapshot_name': 'web'}):
            with self.subTest(body=body):
                response = self.initialize(body)
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.get_json()['data']['parsed'])
        self.assertEqual(self.parses(), 3)

    def test_an_empty_snapshot_is_refused_without_parsing(self):
        self.create('empty', {'batfish/layer1_topology.json': '{"edges": []}'})

        response = self.initialize({'snapshot_dir': 'empty'})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['code'], 'snapshot_empty')
        self.assertEqual(self.parses(), 0)


class StagingTest(CachedRouteTestCase):
    def test_load_snapshot_uploads_a_staged_copy_and_removes_it(self):
        snapshot = self.create('other', {'configs/r1.cfg': CONFIG_R1, 'configs/.swap': 'x'})

        self.service._load_snapshot(snapshot, 'other')

        upload = self.session.uploads[0]
        self.assertEqual((upload.path.name, upload.files), ('other', ['configs/r1.cfg']))
        self.assertNotEqual(upload.path, snapshot)
        self.assertFalse(upload.path.exists())
        self.assertIsNone(self.service.loaded_content_hash)

    def test_a_vanishing_source_file_re_runs_the_copy_once_and_a_second_vanish_fails_without_fallback(self):
        snapshot = self.create('web', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2,
                                       'configs/r3.cfg': CONFIG_R1})
        original_copy = state_module.copy_files
        removals = ['configs/r2.cfg']

        def vanishing_copy(files, destination):
            if removals:
                (snapshot / removals.pop(0)).unlink()
            return original_copy(files, destination)

        with mock.patch.object(state_module, 'copy_files', side_effect=vanishing_copy):
            response = self.activate('web')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session.uploads[-1].files, ['configs/r1.cfg', 'configs/r3.cfg'])
        self.assertNotEqual(self.session.uploads[-1].path, snapshot)

        removals.extend(['configs/r1.cfg', 'configs/r3.cfg'])
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        write_file(snapshot / 'configs' / 'r4.cfg', CONFIG_R2)
        uploads = self.parses()
        with mock.patch.object(state_module, 'copy_files', side_effect=vanishing_copy), \
                self.assertLogs('services.batfish_service', level='WARNING'):
            failed = self.activate('web')
        self.assertEqual(failed.status_code, 500)
        self.assertEqual(failed.get_json()['code'], 'snapshot_activation_error')
        self.assertEqual(self.parses(), uploads)
        self.assertEqual(self.service.activation_failures._entries, {})
        staging_root = self.sandbox.state.staging_root()
        self.assertEqual(list(staging_root.iterdir()) if staging_root.exists() else [], [])

        self.select('web')
        recovered = self.nodes()
        self.assertEqual(recovered.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.session.uploads[-1].files, ['configs/r4.cfg'])

    def test_staging_needs_no_database_sidecar_or_valid_namespace(self):
        snapshot = self.create('web')
        os.symlink(snapshot / 'configs' / 'r1.cfg', snapshot / 'configs' / 'link.cfg')
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            self.sandbox.state.scan_tree(snapshot)
        for label, prepare in (
            ('unreadable sidecar', lambda: mock.patch.object(self.sandbox.state, 'read_sidecar_id', return_value=None)),
            ('failed database lookup', lambda: mock.patch.object(
                self.sandbox.state, '_resolve_rows', side_effect=OperationalError('SELECT', {}, Exception('db')))),
        ):
            with self.subTest(mode=label), prepare():
                self.service._reset_loaded_state()
                staged, content_hash = self.sandbox.state.stage_for_upload(snapshot)
                self.assertEqual(staged.name, 'web')
                self.assertTrue((staged / 'configs' / 'r1.cfg').is_file())
                self.assertFalse((staged / 'configs' / 'link.cfg').exists())
                self.sandbox.state.cleanup_staging(staged)
                self.service.initialize_network(snapshot, 'web')
                self.assertEqual(self.session.uploads[-1].files, ['configs/r1.cfg'])
                self.assertIsNotNone(self.service.loaded_content_hash)

    def test_temp_fallback_data_dir_still_stages(self):
        self.sandbox.settings.DATA_DIR_FELL_BACK = True
        self.restart(seed=False)
        snapshot = self.create('web')
        os.symlink(snapshot / 'configs' / 'r1.cfg', snapshot / 'configs' / 'link.cfg')

        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            response = self.activate('web')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session.uploads[-1].files, ['configs/r1.cfg'])
        self.assertNotEqual(self.session.uploads[-1].path.parent.parent, snapshot.parent)

    def test_a_service_without_a_state_service_uploads_the_live_directory(self):
        snapshot = self.create('web')
        service = BatfishService()
        service._session = FakeSession()
        with mock.patch.object(service, 'get_file_parse_status', return_value=[]), \
                mock.patch.object(service, 'get_init_issues', return_value=[]), \
                mock.patch.object(service, 'get_parse_warnings', return_value=[]):
            service.initialize_network(snapshot, 'web')

        self.assertEqual(service._session.uploads[0].path, snapshot)
        self.assertIsNone(service.loaded_content_hash)
        self.assertIsNone(service.live_loaded)


class PassThroughStaging:
    """State service stand-in that hands the snapshot directory itself to the upload"""

    def stage_for_upload(self, snapshot_dir):
        return Path(snapshot_dir), None

    def cleanup_staging(self, staged_dir):
        return None

    def read_clear_counter(self):
        return None


class StateLossClassificationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        for name in ('active-x', 'base-a', 'comp-b'):
            (self.root / name / 'configs').mkdir(parents=True)
        self.service = BatfishService()
        self.service._session = FakeSession()
        self.service._session.snapshot = 'active-x'
        self.service.current_snapshot_name = 'active-x'
        self.service._initialized = True
        self.service.loaded_content_hash = sha('loaded')
        self.probe = StubProbe()
        self.service.version_probe = self.probe
        self.service._state_service = PassThroughStaging()

    def classify(self, status: int, body: str, **kwargs):
        return self.service._build_query_error('nodeProperties', coordinator_error(status, body, **kwargs)).state_loss

    def assert_intact(self):
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.loaded_content_hash, sha('loaded'))

    def assert_dropped(self):
        self.assertFalse(self.service._initialized)
        self.assertIsNone(self.service.loaded_content_hash)
        self.assertEqual(self.service.current_snapshot_name, 'active-x')

    def test_the_matcher_accepts_the_real_reasons_and_rejects_the_question_404(self):
        self.assertEqual(self.classify(404, "Network 'net' does not exist"), (None, True))
        self.assertEqual(self.classify(500, "Missing snapshot 'snap' for network 'net'"), ('snap', False))
        self.assertEqual(self.classify(500, "Missing snapshot 'snap' for network: 'net'"), ('snap', False))
        self.assertEqual(self.classify(404, 'Snapshot snap not found in network net'), ('snap', False))
        self.assertEqual(
            self.classify(404, '', url='http://batfish:9996/v2/networks/net/snapshots/snap%20x/answer'),
            ('snap x', False),
        )
        self.assertIsNone(self.classify(404, "Question 'q' does not exist for network: net"))
        self.assertIsNone(self.classify(500, 'No value present'))
        self.assertEqual(self.probe.checked, [])

    def failing_query(self, error: Exception):
        return FailingQuestion(error)

    def test_every_executor_drops_the_state_on_a_missing_network(self):
        missing = coordinator_error(404, "Network 'net' does not exist")
        executors = {
            '_execute_query': lambda: self.service._execute_query(self.failing_query(missing), 'q'),
            '_execute_query raising': lambda: self.service._execute_query(
                self.failing_query(missing), 'q', raise_on_error=True),
            '_execute_query_factory': lambda: self.service._execute_query_factory(
                lambda: self.failing_query(missing), 'q'),
            '_execute_query_records': lambda: self.service._execute_query_records(self.failing_query(missing), 'q'),
            '_execute_query_records_factory': lambda: self.service._execute_query_records_factory(
                lambda: self.failing_query(missing), 'q'),
        }
        for label, run in executors.items():
            with self.subTest(executor=label):
                self.service._initialized = True
                self.service.loaded_content_hash = sha('loaded')
                try:
                    run()
                except BatfishQueryError as error:
                    self.assertEqual(error.error_type, 'batfish_state_lost')
                    self.assertEqual(error.status_code, 400)
                self.assert_dropped()

        self.service._initialized = True
        self.service.loaded_content_hash = sha('loaded')
        self.service._session.q.differentialReachability = lambda **kwargs: self.failing_query(missing)
        with self.assertRaises(BatfishQueryError) as raised:
            self.service.get_differential_reachability('base-a', snapshot='comp-b')
        self.assertEqual(raised.exception.error_type, 'batfish_state_lost')
        self.assert_dropped()

    def test_swallowed_failures_are_counted(self):
        BatfishService.reset_query_failure_count()
        self.service._execute_query(self.failing_query(RuntimeError('boom')), 'q')
        self.service._execute_query_factory(lambda: (_ for _ in ()).throw(RuntimeError('construction')), 'q')
        self.assertEqual(BatfishService.query_failure_count(), 2)
        BatfishService.reset_query_failure_count()
        self.assertEqual(BatfishService.query_failure_count(), 0)

    def test_a_500_no_value_present_with_a_404_check_on_the_active_snapshot_drops_the_state(self):
        self.probe.statuses['active-x'] = (404, 'Snapshot active-x not found')
        error = coordinator_error(500, 'No value present')

        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(self.failing_query(error), 'q')

        self.assertEqual(raised.exception.error_type, 'batfish_state_lost')
        self.assertEqual(raised.exception.details['batfish_status_code'], 500)
        self.assertEqual(self.probe.checked, [(NETWORK, 'active-x')])
        self.assert_dropped()

    def test_missing_non_active_snapshots_are_not_loaded_without_a_drop(self):
        anchored = coordinator_error(500, "Missing snapshot 'base-a' for network 'net'")
        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(self.failing_query(anchored), 'q', answer_kwargs={'snapshot': 'base-a'})
        self.assertEqual(raised.exception.error_type, 'snapshot_not_loaded')
        self.assertIn("'base-a'", raised.exception.hints[0])
        self.assert_intact()

        self.probe.statuses['comp-b'] = (404, '')
        generic = coordinator_error(500, 'No value present')
        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(
                self.failing_query(generic), 'compareFilters', answer_kwargs={'reference_snapshot': 'comp-b'},
            )
        self.assertEqual(raised.exception.error_type, 'snapshot_not_loaded')
        self.assertIn("'comp-b'", raised.exception.hints[0])
        self.assert_intact()

    def test_a_redacted_name_with_every_snapshot_present_keeps_the_category_without_a_drop(self):
        wrapped = RuntimeError(f"Unknown error: {coordinator_error(500, 'Missing snapshot ' + repr(str(uuid.uuid4())) + ' for network ' + repr('net'))}")
        wrapped.__cause__ = None

        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(self.failing_query(wrapped), 'q')

        self.assertEqual(raised.exception.error_type, 'batfish_state_lost')
        self.assertIn('could not be identified', raised.exception.hints[0])
        self.assertEqual(self.probe.checked, [(NETWORK, 'active-x')])
        self.assert_intact()

    def test_an_active_snapshot_with_a_uuid_name_is_recognised_from_the_raw_text(self):
        name = f'snap-{uuid.uuid4()}'
        self.service.current_snapshot_name = name
        error = coordinator_error(500, f"Missing snapshot '{name}' for network 'net'")

        with self.assertRaises(BatfishQueryError):
            self.service._execute_query_records(self.failing_query(error), 'q')

        self.assertFalse(self.service._initialized)
        self.assertIn('[id]', str(error))

    def test_work_log_and_client_side_failures_never_run_the_check(self):
        for error in (RuntimeError('Work terminated abnormally\nCaused by: x'), ConnectionError('refused')):
            with self.subTest(error=type(error).__name__):
                self.service._execute_query(self.failing_query(error), 'q')
        self.assertEqual(self.probe.checked, [])
        self.assert_intact()

    def test_a_failing_helper_keeps_the_original_classification(self):
        for helper_error in (ConnectionRefusedError('refused'), TimeoutError('timed out')):
            with self.subTest(helper=type(helper_error).__name__):
                self.probe.error = helper_error
                with self.assertRaises(BatfishQueryError) as raised:
                    self.service._execute_query_records(self.failing_query(coordinator_error(500, 'No value present')), 'q')
                self.assertEqual(raised.exception.error_type, 'batfish_coordinator_error')
                self.assert_intact()

        from services.batfish_version_probe import BatfishVersionProbe
        self.service.version_probe = BatfishVersionProbe('127.0.0.1', 1)
        started = time.monotonic()
        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(self.failing_query(coordinator_error(500, 'No value present')), 'q')
        self.assertEqual(raised.exception.error_type, 'batfish_coordinator_error')
        self.assertLess(time.monotonic() - started, 2.0)
        self.assert_intact()

    def test_a_non_active_compare_side_error_does_not_drop_the_active_state(self):
        self.service._session.snapshot = 'comp-b'
        error = coordinator_error(500, 'Expected BGP session properties')

        with self.assertRaises(BatfishQueryError) as raised:
            self.service._execute_query_records(self.failing_query(error), 'q')

        self.assertEqual(raised.exception.error_type, 'batfish_coordinator_error')
        self.assertEqual(self.probe.checked, [(NETWORK, 'comp-b')])
        self.assert_intact()

    def test_the_check_is_skipped_without_a_state_service(self):
        self.service._state_service = None

        with self.assertRaises(BatfishQueryError):
            self.service._execute_query_records(self.failing_query(coordinator_error(500, 'No value present')), 'q')

        self.assertEqual(self.probe.checked, [])
        self.assert_intact()

    def test_network_creation_during_a_load_drops_the_active_state_per_call(self):
        from pybatfish.client import restv2helper

        class CreatingSession(FakeSession):
            def __init__(self):
                super().__init__()
                self.create_next = False

            def set_network(self, name):
                if self.create_next:
                    self.create_next = False
                    restv2helper.init_network(self, name)
                self.network = name

        session = CreatingSession()
        session.snapshot = 'active-x'
        self.service._session = session
        self.service._state_service = None
        with mock.patch.object(restv2helper, '_post', return_value=None):
            session.create_next = True
            self.service._load_snapshot(self.root / 'base-a', 'base-a')
            self.assert_dropped()

            self.service._initialized = True
            self.service.loaded_content_hash = sha('loaded')
            self.service._load_snapshot(self.root / 'comp-b', 'comp-b')
            self.assert_intact()

            session.create_next = True
            with mock.patch.object(self.service, 'get_file_parse_status', return_value=[]), \
                    mock.patch.object(self.service, 'get_init_issues', return_value=[]), \
                    mock.patch.object(self.service, 'get_parse_warnings', return_value=[]):
                self.service.initialize_network(self.root / 'active-x', 'active-x')
                self.service._load_snapshot(self.root / 'comp-b', 'comp-b')
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.current_snapshot_name, 'active-x')

    def test_compare_reloads_only_the_dropped_active_side_and_queries_once_more(self):
        drops = {'count': 1}

        def nodes():
            snapshot = self.service._session.snapshot
            if snapshot == 'active-x' and drops['count']:
                drops['count'] -= 1
                self.service._refine_query_error(
                    self.service._build_query_error('nodeProperties', coordinator_error(404, "Network 'n' does not exist"))
                )
                return []
            return [{'node': f'{snapshot}-r1'}]

        with mock.patch.object(self.service, 'get_node_properties', side_effect=nodes), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]), \
                mock.patch.object(self.service, 'get_differential_reachability', return_value=[]):
            result = self.service.compare_snapshots(
                'active-x', 'comp-b', base_snapshot_path=self.root / 'active-x',
                comparison_snapshot_path=self.root / 'comp-b',
            )

        self.assertEqual(result['nodes']['added'], ['comp-b-r1'])
        self.assertEqual(result['nodes']['removed'], ['active-x-r1'])
        self.assertEqual([upload.name for upload in self.service._session.uploads], ['comp-b', 'active-x'])

        drops['count'] = 2
        self.service._initialized = True
        with mock.patch.object(self.service, 'get_node_properties', side_effect=nodes), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]), \
                self.assertRaises(BatfishQueryError) as raised:
            self.service.compare_snapshots(
                'active-x', 'comp-b', base_snapshot_path=self.root / 'active-x',
                comparison_snapshot_path=self.root / 'comp-b',
            )
        self.assertEqual(raised.exception.error_type, 'batfish_state_lost')

    def test_interface_properties_reload_after_a_drop_and_never_return_an_empty_list(self):
        drops = {'count': 1}

        def interfaces(ospf_interfaces=None):
            if drops['count']:
                drops['count'] -= 1
                self.service._drop_loaded_state()
                return []
            return [{'hostname': 'r1', 'interface': 'e0'}]

        with mock.patch.object(self.service, 'get_interface_properties', side_effect=interfaces):
            result = self.service.get_snapshot_interface_properties(self.root / 'active-x', 'active-x')

        self.assertEqual(result, [{'hostname': 'r1', 'interface': 'e0'}])
        self.assertEqual([upload.name for upload in self.service._session.uploads], ['active-x'])


class RouteStateLossTest(CachedRouteTestCase):
    def drop_like_a_lost_network(self):
        self.service._refine_query_error(
            self.service._build_query_error('q', coordinator_error(404, "Network 'n' does not exist"))
        )

    def test_a_drop_during_all_data_re_parses_once_in_the_request(self):
        self.create('web')
        self.select('web')
        drops = {'count': 1}

        def drop_once():
            if drops['count']:
                drops['count'] -= 1
                self.drop_like_a_lost_network()
                raise RuntimeError(BATFISH_NOT_INITIALIZED_MESSAGE)

        self.all_data_hook = drop_once
        recovered = self.all_data_request()

        self.assertEqual(recovered.status_code, 200, recovered.get_data(as_text=True)[:300])
        self.assertEqual(recovered.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)

        drops['count'] = 2
        write_file(self.sandbox.snapshots_dir / 'web' / 'configs' / 'r2.cfg', CONFIG_R2)
        failed = self.all_data_request()
        self.assertEqual(failed.status_code, 400)
        self.assertEqual(failed.get_json()['code'], 'batfish_state_lost')
        self.assertEqual(failed.headers['Cache-Control'], 'no-store')

    def test_compare_and_interfaces_routes_answer_batfish_state_lost(self):
        self.create('active-x')
        self.create('comp-b')
        self.assertEqual(self.activate('active-x').status_code, 200)

        def always_dropping(*args, **kwargs):
            if self.service._session.snapshot == 'active-x':
                self.drop_like_a_lost_network()
            return []

        with mock.patch.object(self.service, 'get_node_properties', side_effect=always_dropping), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]):
            self.service._initialized = True
            compared = self.client.post('/api/snapshots/compare', json={
                'base_snapshot': 'active-x', 'comparison_snapshot': 'comp-b',
            })
        self.assertEqual(compared.status_code, 400, compared.get_data(as_text=True)[:300])
        self.assertEqual(compared.get_json()['code'], 'batfish_state_lost')
        self.assertTrue(compared.get_json()['hints'])

        self.assertEqual(self.activate('active-x').status_code, 200)

        def interfaces_dropping(ospf_interfaces=None):
            self.service._drop_loaded_state()
            return []

        with mock.patch.object(self.service, 'get_interface_properties', side_effect=interfaces_dropping):
            response = self.client.get('/api/snapshots/active-x/interfaces')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['code'], 'batfish_state_lost')

    def test_compare_filters_with_an_unloaded_reference_answers_snapshot_not_loaded(self):
        self.create('web')
        self.create('reference')
        self.assertEqual(self.activate('web').status_code, 200)
        self.probe.statuses['reference'] = (404, '')
        self.session.q.compareFilters = lambda **kwargs: FailingQuestion(coordinator_error(500, 'No value present'))
        parses = self.parses()

        response = self.client.post('/api/validation/compare-filters', json={'reference_snapshot': 'reference'})

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        payload = response.get_json()
        self.assertEqual(payload['code'], 'snapshot_not_loaded')
        self.assertIn("'reference'", payload['hints'][0])
        self.assertEqual(payload['details']['batfish_status_code'], 500)
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.parses(), parses)

    def test_a_coordinator_error_against_the_unreachable_test_coordinator_keeps_its_classification(self):
        from services.batfish_version_probe import BatfishVersionProbe
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        self.service.version_probe = BatfishVersionProbe(config.BATFISH_HOST, config.BATFISH_PORT)
        self.session.q.compareFilters = lambda **kwargs: FailingQuestion(coordinator_error(500, 'No value present'))
        self.create('reference')

        response = self.client.post('/api/validation/compare-filters', json={'reference_snapshot': 'reference'})

        self.assertEqual(response.status_code, 502, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['code'], 'batfish_coordinator_error')
        self.assertTrue(self.service._initialized)
        self.assertIsNotNone(self.service.loaded_content_hash)


class QueuedSelectionChangeTest(CachedRouteTestCase):
    """AUTH OFF requests that resolved a snapshot before another one was selected while they waited for Batfish"""

    def setUp(self):
        super().setUp()
        self.create('s1', {'configs/r1.cfg': CONFIG_R1})
        self.create('s2', {'configs/r1.cfg': CONFIG_R2})
        self.s1_hash = self.working_hash('s1')
        self.s2_hash = self.working_hash('s2')
        self.assertEqual(self.activate('s1').status_code, 200)
        patch = mock.patch.object(
            self.service, 'get_node_properties',
            side_effect=lambda: [{'node': 'r1', 'snapshot': self.service.current_snapshot_name}],
        )
        patch.start()
        self.addCleanup(patch.stop)

    def queued(self, while_queued):
        """Run a nodes request in a thread that resolves its snapshot and then waits for the held Batfish lock."""
        planned = threading.Event()
        original_plan = app_module.plan_cached_query
        result = {}

        def signalling_plan(snapshot_path):
            plan = original_plan(snapshot_path)
            planned.set()
            return plan

        client = app_module.app.test_client()
        with mock.patch.object(app_module, 'plan_cached_query', side_effect=signalling_plan):
            with app_module.batfish_request_lock:
                thread = threading.Thread(target=lambda: result.setdefault('response', client.get('/api/network/nodes')))
                thread.start()
                self.assertTrue(planned.wait(10))
                while_queued()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        return result['response']

    def assert_served_for_s2(self, response, status: str):
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.headers['X-Topologix-Cache'], status)
        self.assertEqual(response.headers['X-Topologix-Snapshot-Id'], self.snapshot_id('s2'))
        self.assertEqual(decoded(response)['data'], [{'node': 'r1', 'snapshot': 's2'}])
        self.assertEqual(self.service.current_snapshot_name, 's2')
        self.assertEqual(json.loads(self.active_file().read_text())['snapshot_name'], 's2')
        self.assertEqual([upload.name for upload in self.session.uploads], ['s1', 's2'])

    def test_a_queued_miss_is_planned_again_for_the_newly_selected_snapshot(self):
        response = self.queued(lambda: self.assertEqual(self.activate('s2').status_code, 200))

        self.assert_served_for_s2(response, 'stored')
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], self.s2_hash)
        self.assertEqual(self.entry_hashes(), {self.s2_hash})

    def test_a_queued_bypass_is_planned_again_for_the_newly_selected_snapshot(self):
        self.probe.version = None

        response = self.queued(lambda: self.assertEqual(self.activate('s2').status_code, 200))

        self.assert_served_for_s2(response, 'bypass')
        self.assertEqual(self.entry_hashes(), set())

    def test_a_selection_cleared_while_queued_answers_no_active_snapshot(self):
        response = self.queued(lambda: self.assertEqual(self.client.delete('/api/snapshots/s1').status_code, 200))

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['code'], 'no_active_snapshot')
        self.assertEqual(response.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual([upload.name for upload in self.session.uploads], ['s1'])
        self.assertIsNone(self.service.current_snapshot_name)
        self.assertFalse(self.active_file().exists())

    def test_alternating_selections_end_in_a_bypass_for_the_current_snapshot(self):
        self.assertEqual(self.activate('s2').status_code, 200)
        names = iter(['s1', 's2'] * 10)

        def alternating(network_name):
            self.service.current_snapshot_name = next(names)

        with mock.patch.object(self.service, 'set_network_context', side_effect=alternating):
            response = self.nodes()

        current = self.service.current_snapshot_name
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual(response.headers['X-Topologix-Snapshot-Id'], self.snapshot_id(current))
        self.assertEqual(decoded(response)['data'], [{'node': 'r1', 'snapshot': current}])
        self.assertEqual(self.parses(), 2)
        self.assertEqual(self.entry_hashes(), set())


class ProbeGraceTest(CachedRouteTestCase):
    def use_probe(self, grace_seconds: float) -> None:
        from services.batfish_version_probe import BatfishVersionProbe
        self.clock = [1_000.0]
        self.versions = [BATFISH_VERSION]
        probe = BatfishVersionProbe('127.0.0.1', 1, ttl_seconds=300, grace_seconds=grace_seconds,
                                    clock=lambda: self.clock[0])
        probe.fetch_version = lambda: self.versions[0]
        self.service.version_probe = probe
        self.cache.current_batfish_version = probe.peek
        original = self.session.init_snapshot

        def slow_parse(path, name=None, overwrite=False):
            result = original(path, name=name, overwrite=overwrite)
            self.clock[0] += 120
            return result

        self.session.init_snapshot = slow_parse
        self.create('web')
        self.select('web')

    def assert_no_re_parse_after_a_long_parse(self):
        stored = self.nodes()
        self.assertEqual(stored.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.service.loaded_batfish_version, BATFISH_VERSION)
        self.assertEqual(self.run_traceroute().status_code, 200)
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'hit')
        self.assertEqual(self.parses(), 1)

    def test_a_parse_outlasting_the_grace_period_causes_no_re_parse(self):
        self.use_probe(grace_seconds=60)
        self.assert_no_re_parse_after_a_long_parse()

    def test_a_zero_grace_period_causes_no_re_parse(self):
        self.use_probe(grace_seconds=0)
        self.assert_no_re_parse_after_a_long_parse()

    def test_a_real_version_change_is_still_detected(self):
        self.use_probe(grace_seconds=60)
        self.assert_no_re_parse_after_a_long_parse()
        self.versions[0] = '2026.01.01'
        self.session.version = '2026.01.01'
        self.clock[0] += 301

        self.assertEqual(self.run_traceroute().status_code, 200)

        self.assertEqual(self.parses(), 2)
        self.assertEqual(self.service.loaded_batfish_version, '2026.01.01')
        self.assertEqual(self.nodes().headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(self.parses(), 2)


class ActivationFailureCacheTest(unittest.TestCase):
    def test_expired_entries_are_pruned_when_a_failure_is_recorded(self):
        now = [100.0]
        failures = ActivationFailureCache(ttl_seconds=60, clock=lambda: now[0])
        failures.record(('id', 'ns', 'a'), RuntimeError('a'), 'a', 'alpha')
        now[0] = 200.0

        failures.record(('id', 'ns', 'b'), RuntimeError('b'), 'b', 'beta')

        self.assertEqual(list(failures._entries), [('id', 'ns', 'b')])

    def test_no_exception_traceback_or_caller_frame_is_retained(self):
        failures = ActivationFailureCache()
        holder = {}

        class FrameLocal:
            pass

        def explode():
            local = FrameLocal()
            holder['ref'] = weakref.ref(local)
            raise RuntimeError('Work terminated abnormally\nCaused by: x.Error: Parser crashed')

        try:
            explode()
        except RuntimeError as error:
            failures.record(('id', 'ns', 's'), error, 's', 'snap')
        gc.collect()

        self.assertIsNone(holder['ref']())
        self.assertFalse(any(
            isinstance(value, BaseException) for entry in failures._entries.values() for value in entry
        ))
        replayed = failures.get(('id', 'ns', 's'))
        self.assertIsNone(replayed.__traceback__)
        self.assertEqual(replayed.error_type, 'RuntimeError')
        with app_module.app.app_context():
            response, status = app_module.snapshot_activation_error_response('snap', replayed)
        self.assertEqual(status, 422)
        self.assertEqual(response.get_json()['details']['reason'], 'Parser crashed')


class StaleStoredNameTest(CachedRouteTestCase):
    def test_deleting_the_active_snapshot_removes_a_stored_name_of_another_snapshot(self):
        self.create('alpha')
        self.create('beta')
        self.assertEqual(self.activate('beta').status_code, 200)
        with mock.patch('services.snapshot_state_service.tempfile.mkstemp', side_effect=OSError(errno.ENOSPC, 'full')), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            self.assertEqual(self.activate('alpha').status_code, 200)
        self.assertEqual(json.loads(self.active_file().read_text())['snapshot_name'], 'beta')
        self.assertEqual(self.service.current_snapshot_name, 'alpha')

        self.assertEqual(self.client.delete('/api/snapshots/alpha').status_code, 200)

        self.assertFalse(self.active_file().exists())
        self.restart(seed=True)
        self.assertIsNone(self.service.current_snapshot_name)


class NullHashHookTest(CachedRouteTestCase):
    def test_a_null_working_hash_on_the_hook_path_keeps_name_only_semantics(self):
        snapshot = self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        original_scan = self.sandbox.state.scan_tree_or_none
        counter = iter(range(10_000))

        def moving(snapshot_dir):
            scan = original_scan(snapshot_dir)
            if scan is not None:
                scan.fingerprint = sha(f'{scan.fingerprint}:{next(counter)}')
            return scan

        with mock.patch.object(self.sandbox.state, 'scan_tree_or_none', side_effect=moving):
            self.assertEqual(self.run_traceroute().status_code, 200)
            self.assertEqual(self.parses(), 1)
            self.service._drop_loaded_state()
            self.assertEqual(self.run_traceroute().status_code, 200)
            self.assertEqual(self.parses(), 2)

        self.assertIsNone(self.sandbox.row(self.snapshot_id('web')))


class LostSideReloadTest(CachedRouteTestCase):
    """Reloads after a lost-state event while the disk already holds newer content than Batfish"""

    def setUp(self):
        super().setUp()
        self.active = self.create('active', {'configs/r1.cfg': CONFIG_R1})
        self.create('other', {'configs/r1.cfg': CONFIG_R2})
        self.h1 = self.working_hash('active')
        self.assertEqual(self.activate('active').status_code, 200)
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 3600
        write_file(self.active / 'configs' / 'r1.cfg', 'hostname active-edited\n')
        self.h2 = self.sandbox.state.compute_manifest(self.active).content_hash
        settling = self.sandbox.poll('active')
        self.assertTrue(settling.external_settling)
        self.assertEqual(settling.content_hash, self.h1)
        self.assertEqual(self.service.loaded_content_hash, self.h1)

    def unidentified_loss(self):
        reason = f"Missing snapshot '{uuid.uuid4()}' for network 'net'"
        error = RuntimeError(f"Unknown error: {coordinator_error(500, reason)}")
        self.service._refine_query_error(self.service._build_query_error('q', error))

    def uploads(self) -> list:
        return [upload.name for upload in self.session.uploads]

    def assert_the_next_miss_re_parses_and_stores_under_the_new_hash(self):
        parses = self.parses()
        response = self.nodes()
        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], self.h2)
        self.assertEqual(self.parses(), parses + 1)
        self.assertEqual(self.entry_hashes(), {self.h2})

    def test_compare_drops_a_re_uploaded_active_side(self):
        losses = {'pending': 1}

        def nodes():
            snapshot = self.service._session.snapshot
            if snapshot == 'active' and losses['pending']:
                losses['pending'] -= 1
                self.unidentified_loss()
            return [{'node': f'{snapshot}-r1'}]

        with mock.patch.object(self.service, 'get_node_properties', side_effect=nodes), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]), \
                mock.patch.object(self.service, 'get_differential_reachability', return_value=[]):
            response = self.client.post('/api/snapshots/compare', json={
                'base_snapshot': 'active', 'comparison_snapshot': 'other',
            })

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.uploads(), ['active', 'other', 'active'])
        self.assertFalse(self.service._initialized)
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def test_interface_lookup_drops_a_re_uploaded_active_snapshot(self):
        losses = {'pending': 1}

        def interfaces(ospf_interfaces=None):
            if losses['pending']:
                losses['pending'] -= 1
                self.unidentified_loss()
                return []
            return [{'hostname': 'r1', 'interface': 'e0'}]

        with mock.patch.object(self.service, 'get_interface_properties', side_effect=interfaces):
            response = self.client.get('/api/snapshots/active/interfaces')

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIn('r1', response.get_json()['data'])
        self.assertEqual(self.uploads(), ['active', 'active'])
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def other_interfaces(self, losses: list):
        """GET the interfaces of the non-active snapshot 'other'; each query records the next loss of losses."""
        calls = []

        def interfaces(ospf_interfaces=None):
            calls.append(self.service._session.snapshot)
            if losses:
                failure = losses.pop(0)
                self.service._refine_query_error(self.service._build_query_error('interfaceProperties', failure))
                return []
            return [{'hostname': 'r1', 'interface': 'e0'}]

        with mock.patch.object(self.service, 'get_interface_properties', side_effect=interfaces):
            response = self.client.get('/api/snapshots/other/interfaces')
        return response, calls

    def test_interface_lookup_of_another_snapshot_reloads_it_once_after_a_loss_naming_it(self):
        response, calls = self.other_interfaces([coordinator_error(500, "Missing snapshot 'other' for network 'net'")])

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIn('r1', response.get_json()['data'])
        self.assertEqual(calls, ['other', 'other'])
        self.assertEqual(self.uploads(), ['active', 'other', 'other'])
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.loaded_content_hash, self.h1)

    def test_interface_lookup_of_another_snapshot_reloads_it_after_a_lost_network_and_the_active_one_re_parses(self):
        response, calls = self.other_interfaces([coordinator_error(404, "Network 'net' does not exist")])

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIn('r1', response.get_json()['data'])
        self.assertEqual(calls, ['other', 'other'])
        self.assertEqual(self.uploads(), ['active', 'other', 'other'])
        self.assertFalse(self.service._initialized)
        self.assertEqual(self.service.current_snapshot_name, 'active')
        self.assertEqual(self.entry_hashes(), set())
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def test_interface_lookup_of_another_snapshot_answers_state_lost_after_a_second_loss(self):
        missing = "Missing snapshot 'other' for network 'net'"
        response, calls = self.other_interfaces([coordinator_error(500, missing), coordinator_error(500, missing)])

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['code'], 'batfish_state_lost')
        self.assertEqual(calls, ['other', 'other'])
        self.assertEqual(self.uploads(), ['active', 'other', 'other'])

    def test_interface_lookup_of_another_snapshot_without_a_loss_uploads_it_once(self):
        response, calls = self.other_interfaces([])

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIn('r1', response.get_json()['data'])
        self.assertEqual(calls, ['other'])
        self.assertEqual(self.uploads(), ['active', 'other'])
        self.assertTrue(self.service._initialized)

    def test_differential_reachability_drops_a_re_uploaded_active_side(self):
        losses = {'pending': 1}

        class Question:
            def answer(self, **kwargs):
                if losses['pending']:
                    losses['pending'] -= 1
                    reason = f"Missing snapshot '{uuid.uuid4()}' for network 'net'"
                    raise RuntimeError(f"Unknown error: {coordinator_error(500, reason)}")
                return SimpleNamespace(frame=lambda: SimpleNamespace(empty=True))

        self.session.q.differentialReachability = lambda **kwargs: Question()

        response = self.client.post('/api/advanced/differential-reachability', json={
            'reference_snapshot': 'active', 'snapshot': 'other',
        })

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.uploads(), ['active', 'other', 'active'])
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def differential(self, failures: list, body: dict) -> tuple:
        """Post differential reachability; return the response, (answer kwargs, session snapshot) per answer and the
        snapshot names the route authorized."""
        answers = []
        session = self.session

        class Question:
            def answer(self, **kwargs):
                answers.append((kwargs, session.snapshot))
                if failures:
                    raise failures.pop(0)
                return SimpleNamespace(frame=lambda: SimpleNamespace(empty=True))

        self.session.q.differentialReachability = lambda **kwargs: Question()
        with mock.patch.object(app_module, 'require_snapshot_access', wraps=app_module.require_snapshot_access) as access:
            response = self.client.post('/api/advanced/differential-reachability', json=body)
        return response, answers, [call.args[0] for call in access.call_args_list]

    def create_the_network_on_the_next_load(self):
        from pybatfish.client import restv2helper

        pending = {'create': True}
        set_network = self.session.set_network

        def creating_set_network(name):
            if pending['create']:
                pending['create'] = False
                restv2helper.init_network(self.session, name)
            set_network(name)

        self.session.set_network = creating_set_network
        patch = mock.patch.object(restv2helper, '_post', return_value=None)
        patch.start()
        self.addCleanup(patch.stop)

    @staticmethod
    def missing_snapshot(name: str) -> RuntimeError:
        reason = f"Missing snapshot '{name}' for network 'net'"
        return RuntimeError(f"Unknown error: {coordinator_error(500, reason)}")

    def test_differential_reachability_reloads_an_implicit_active_side_the_network_lost(self):
        self.create_the_network_on_the_next_load()

        response, answers, authorized = self.differential(
            [self.missing_snapshot('active')], {'reference_snapshot': 'other'},
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['data'], [])
        self.assertEqual(authorized, ['other', 'active'])
        self.assertEqual(self.uploads(), ['active', 'other', 'active'])
        self.assertEqual(answers, [({'reference_snapshot': 'other'}, 'active')] * 2)
        self.assertIn(batfish_service_module.LOST_NETWORK, [loss for _, loss in self.service.state_loss_log])
        self.assertFalse(self.service._initialized)
        self.assertEqual(self.entry_hashes(), set())
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def test_differential_reachability_reloads_an_implicit_active_side_after_an_unidentified_loss(self):
        reason = f"Missing snapshot '{uuid.uuid4()}' for network 'net'"

        response, answers, _ = self.differential(
            [RuntimeError(f"Unknown error: {coordinator_error(500, reason)}")], {'reference_snapshot': 'other'},
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.uploads(), ['active', 'other', 'active'])
        self.assertEqual(answers, [({'reference_snapshot': 'other'}, 'active')] * 2)
        self.assertFalse(self.service._initialized)
        self.assertEqual(self.entry_hashes(), set())
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def test_differential_reachability_keeps_an_implicit_active_side_that_was_not_lost(self):
        response, answers, _ = self.differential([self.missing_snapshot('other')], {'reference_snapshot': 'other'})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.uploads(), ['active', 'other', 'other'])
        self.assertEqual(answers, [({'reference_snapshot': 'other'}, 'active')] * 2)
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.loaded_content_hash, self.h1)

    def test_differential_reachability_re_uploads_nothing_after_a_failure_that_lost_no_state(self):
        response, answers, _ = self.differential(
            [RuntimeError('Work terminated abnormally')], {'reference_snapshot': 'other'},
        )

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['code'], 'query_error')
        self.assertEqual(self.uploads(), ['active', 'other'])
        self.assertEqual(len(answers), 1)
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.loaded_content_hash, self.h1)

    def test_differential_reachability_with_an_explicit_active_snapshot_is_unchanged(self):
        reason = f"Missing snapshot '{uuid.uuid4()}' for network 'net'"

        response, answers, authorized = self.differential(
            [RuntimeError(f"Unknown error: {coordinator_error(500, reason)}")],
            {'reference_snapshot': 'other', 'snapshot': 'active'},
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(authorized, ['other', 'active'])
        self.assertEqual(self.uploads(), ['active', 'other', 'active'])
        self.assertEqual(answers, [({'reference_snapshot': 'other', 'snapshot': 'active'}, 'active')] * 2)
        self.assertFalse(self.service._initialized)
        self.assert_the_next_miss_re_parses_and_stores_under_the_new_hash()

    def test_a_lost_non_active_side_is_the_only_side_reloaded(self):
        losses = {'pending': 1}

        def nodes():
            snapshot = self.service._session.snapshot
            if snapshot == 'other' and losses['pending']:
                losses['pending'] -= 1
                missing = coordinator_error(500, "Missing snapshot 'other' for network 'net'")
                self.service._refine_query_error(self.service._build_query_error('q', missing), {'snapshot': 'other'})
            return [{'node': f'{snapshot}-r1'}]

        with mock.patch.object(self.service, 'get_node_properties', side_effect=nodes), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]), \
                mock.patch.object(self.service, 'get_differential_reachability', return_value=[]):
            response = self.client.post('/api/snapshots/compare', json={
                'base_snapshot': 'active', 'comparison_snapshot': 'other',
            })

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.uploads(), ['active', 'other', 'other'])
        self.assertTrue(self.service._initialized)
        self.assertEqual(self.service.loaded_content_hash, self.h1)
        parses = self.parses()
        cached = self.nodes()
        self.assertEqual(cached.headers['X-Topologix-Content-Hash'], self.h1)
        self.assertEqual(self.parses(), parses)

    @staticmethod
    def planned_loss(kind: str) -> requests.HTTPError:
        """Coordinator error of a planned loss: 'network', 'unidentified' or 'missing:<snapshot>'."""
        if kind == 'network':
            return coordinator_error(404, "Network 'net' does not exist")
        if kind == 'unidentified':
            return coordinator_error(500, f"Missing snapshot '{uuid.uuid4()}' for network 'net'")
        return coordinator_error(500, f"Missing snapshot '{kind.split(':', 1)[1]}' for network 'net'")

    def run_reload_path(self, path: str, plan: list, differential_body: dict | None = None) -> tuple:
        """Request one lost-state reload path; plan[i] is the loss of query run i (None for none). Return the
        response and the planned losses of the runs made."""
        runs = []

        def next_loss():
            kind = plan[len(runs)] if len(runs) < len(plan) else None
            runs.append(kind)
            return kind

        def record(kind):
            error = RuntimeError(f"Unknown error: {self.planned_loss(kind)}")
            self.service._refine_query_error(self.service._build_query_error('q', error))

        if path.startswith('interface_lookup'):
            name = 'active' if path == 'interface_lookup_of_the_active_snapshot' else 'other'

            def interfaces(ospf_interfaces=None):
                kind = next_loss()
                if kind:
                    record(kind)
                    return []
                return [{'hostname': 'r1', 'interface': 'e0'}]

            with mock.patch.object(self.service, 'get_interface_properties', side_effect=interfaces):
                return self.client.get(f'/api/snapshots/{name}/interfaces'), runs

        if path == 'differential_reachability':
            planned_loss = self.planned_loss

            class Question:
                def answer(self, **kwargs):
                    kind = next_loss()
                    if kind:
                        raise RuntimeError(f"Unknown error: {planned_loss(kind)}")
                    return SimpleNamespace(frame=lambda: pandas.DataFrame([{'Flow': 'flow'}]))

            self.session.q.differentialReachability = lambda **kwargs: Question()
            body = differential_body or {'reference_snapshot': 'other'}
            return self.client.post('/api/advanced/differential-reachability', json=body), runs

        def nodes():
            kind = next_loss()
            if kind:
                record(kind)
                return []
            return [{'node': f'{self.service._session.snapshot}-r1'}]

        with mock.patch.object(self.service, 'get_node_properties', side_effect=nodes), \
                mock.patch.object(self.service, 'get_layer3_edges', return_value=[]), \
                mock.patch.object(self.service, 'get_routes', return_value=[]), \
                mock.patch.object(self.service, 'get_differential_reachability', return_value=[]):
            return self.client.post('/api/snapshots/compare', json={
                'base_snapshot': 'active', 'comparison_snapshot': 'other',
            }), runs

    def assert_reload_case(self, path: str, case: str) -> None:
        plan, upload_creates_network, uploads, runs, status, code, active_invalidated = (
            LOST_STATE_RELOAD_CASES[(path, case)]
        )
        if upload_creates_network:
            self.create_the_network_on_the_next_load()

        response, made = self.run_reload_path(path, plan)

        self.assertEqual(response.status_code, status, response.get_data(as_text=True)[:300])
        if code is None:
            self.assertTrue(response.get_json()['data'])
        else:
            self.assertEqual(response.get_json()['code'], code)
        self.assertEqual(self.uploads()[1:], uploads)
        self.assertEqual(len(made), runs)
        self.assertEqual(not self.service._initialized, active_invalidated)

    def test_differential_reachability_re_runs_once_after_a_loss_that_leaves_no_side_lost(self):
        body = {'reference_snapshot': 'other', 'snapshot': 'other'}
        response, made = self.run_reload_path('differential_reachability', ['unidentified', None], body)

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertTrue(response.get_json()['data'])
        self.assertEqual(len(made), 2)
        self.assertEqual(self.uploads()[1:], ['other'])
        self.assertTrue(self.service._initialized)


# (path, case): (planned loss per query run, network created by the first upload, uploads after the activation,
# query runs, HTTP status, error code, active snapshot's loaded state invalidated)
LOST_STATE_RELOAD_CASES = {
    ('interface_lookup_of_the_active_snapshot', 'without_a_loss'): ([None], False, [], 1, 200, None, False),
    ('interface_lookup_of_the_active_snapshot', 'after_a_loss_naming_a_side'): (
        ['missing:active', None], False, ['active'], 2, 200, None, True),
    ('interface_lookup_of_the_active_snapshot', 'after_a_lost_network'): (
        ['network', None], False, ['active'], 2, 200, None, True),
    ('interface_lookup_of_the_active_snapshot', 'after_an_unidentified_loss'): (
        ['unidentified', None], False, ['active'], 2, 200, None, True),
    ('interface_lookup_of_the_active_snapshot', 'after_a_second_loss'): (
        ['missing:active', 'missing:active'], False, ['active'], 2, 400, 'batfish_state_lost', True),
    ('interface_lookup_of_another_snapshot', 'without_a_loss'): ([None], False, ['other'], 1, 200, None, False),
    ('interface_lookup_of_another_snapshot', 'after_a_loss_naming_a_side'): (
        ['missing:other', None], False, ['other', 'other'], 2, 200, None, False),
    ('interface_lookup_of_another_snapshot', 'after_a_lost_network'): (
        ['network', None], False, ['other', 'other'], 2, 200, None, True),
    ('interface_lookup_of_another_snapshot', 'after_an_unidentified_loss'): (
        ['unidentified', None], False, ['other'], 2, 200, None, False),
    ('interface_lookup_of_another_snapshot', 'after_a_loss_during_the_upload'): (
        [None], True, ['other'], 1, 200, None, True),
    ('interface_lookup_of_another_snapshot', 'after_a_second_loss'): (
        ['missing:other', 'missing:other'], False, ['other', 'other'], 2, 400, 'batfish_state_lost', False),
    ('differential_reachability', 'without_a_loss'): ([None], False, ['other'], 1, 200, None, False),
    ('differential_reachability', 'after_a_loss_naming_a_side'): (
        ['missing:other', None], False, ['other', 'other'], 2, 200, None, False),
    ('differential_reachability', 'after_a_lost_network'): (
        ['network', None], False, ['other', 'other', 'active'], 2, 200, None, True),
    ('differential_reachability', 'after_an_unidentified_loss'): (
        ['unidentified', None], False, ['other', 'active'], 2, 200, None, True),
    ('differential_reachability', 'after_a_loss_during_the_upload'): (
        ['missing:active', None], True, ['other', 'active'], 2, 200, None, True),
    ('differential_reachability', 'after_a_second_loss'): (
        ['missing:other', 'missing:other'], False, ['other', 'other'], 2, 400, 'batfish_state_lost', False),
    ('compare', 'without_a_loss'): ([None, None], False, ['other'], 2, 200, None, False),
    ('compare', 'after_a_loss_naming_a_side'): (
        [None, 'missing:other', None, None], False, ['other', 'other'], 4, 200, None, False),
    ('compare', 'after_a_lost_network'): (
        [None, 'network', None, None], False, ['other', 'active', 'other'], 4, 200, None, True),
    ('compare', 'after_an_unidentified_loss'): (
        ['unidentified', None, None, None], False, ['other', 'active'], 4, 200, None, True),
    ('compare', 'after_a_loss_during_the_upload'): (
        [None, None, None, None], True, ['other', 'active'], 4, 200, None, True),
    ('compare', 'after_a_second_loss'): (
        [None, 'missing:other', None, 'missing:other'], False, ['other', 'other'], 4, 400, 'batfish_state_lost', False),
}


def _lost_state_reload_test(path: str, case: str):
    def test(self):
        self.assert_reload_case(path, case)
    return test


for _path, _case in LOST_STATE_RELOAD_CASES:
    setattr(LostSideReloadTest, f'test_{_path}_{_case}', _lost_state_reload_test(_path, _case))


class PlannedBeforeWriteTest(CachedRouteTestCase):
    def test_a_request_planned_before_an_api_write_never_parses_the_new_content_again(self):
        self.create('web')
        self.assertEqual(self.activate('web').status_code, 200)
        h1 = self.working_hash('web')
        planned = threading.Event()
        original_plan = app_module.plan_cached_query
        result = {}

        def signalling_plan(snapshot_path):
            plan = original_plan(snapshot_path)
            planned.set()
            return plan

        client = app_module.app.test_client()
        with mock.patch.object(app_module, 'plan_cached_query', side_effect=signalling_plan):
            with app_module.batfish_request_lock:
                thread = threading.Thread(target=lambda: result.setdefault('response', client.get('/api/network/nodes')))
                thread.start()
                self.assertTrue(planned.wait(10))
                self.assertEqual(self.upload('web', 'r2.cfg', CONFIG_R2).status_code, 200)
                self.assertTrue(self.activate('web', if_stale=True).get_json()['data']['parsed'])
            thread.join(10)

        h2 = self.working_hash('web')
        response = result['response']
        self.assertNotEqual(h1, h2)
        self.assertEqual(self.parses(), 2)
        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], h2)
        self.assertEqual(self.entry_hashes(), {h2})


class StagingRaceAndSymlinkTest(CachedRouteTestCase):
    SECRET = 'hostname outside-secret\n'

    def test_copy_files_never_recreates_a_staging_directory_that_disappeared(self):
        snapshot = self.create('web', {'configs/r1.cfg': CONFIG_R1})
        scan = self.sandbox.state.scan_tree(snapshot)
        destination = self.sandbox.root / 'staging-container' / 'web'

        with self.assertRaises(state_module.StagingVanishedError):
            state_module.copy_files(scan.files, destination)

        self.assertFalse(destination.exists())

    def test_the_delete_purge_never_removes_an_in_flight_staging_copy_of_an_unopened_copy(self):
        origin = self.create('origin', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2})
        self.working_hash('origin')
        shutil.copytree(origin, self.sandbox.snapshots_dir / 'twin')
        twin_hash = self.sandbox.state.compute_manifest(self.sandbox.snapshots_dir / 'twin').content_hash
        removal_ready = threading.Event()
        twin_copying = threading.Event()
        removal_done = threading.Event()
        original_remove = self.sandbox.history._remove_staging_copy
        original_copy = state_module.copy_files

        def observed_remove(snapshot_id, snapshot_name):
            removal_ready.set()
            twin_copying.wait(1)
            original_remove(snapshot_id, snapshot_name)
            removal_done.set()

        def pausing_copy(files, destination):
            if destination.name != 'twin' or len(files) < 2:
                return original_copy(files, destination)
            first = original_copy(files[:1], destination)
            twin_copying.set()
            removal_done.wait(5)
            rest = original_copy(files[1:], destination)
            return state_module.Manifest.from_entries(list(first.files) + list(rest.files))

        results = {}
        delete_client = app_module.app.test_client()
        activate_client = app_module.app.test_client()
        with mock.patch.object(self.sandbox.history, '_remove_staging_copy', side_effect=observed_remove), \
                mock.patch.object(state_module, 'copy_files', side_effect=pausing_copy):
            deleting = threading.Thread(
                target=lambda: results.setdefault('delete', delete_client.delete('/api/snapshots/origin')),
            )
            deleting.start()
            self.assertTrue(removal_ready.wait(10))
            activating = threading.Thread(
                target=lambda: results.setdefault('activate', activate_client.post('/api/snapshots/twin/activate')),
            )
            activating.start()
            deleting.join(20)
            activating.join(20)

        self.assertEqual(results['delete'].status_code, 200)
        self.assertEqual(results['activate'].status_code, 200, results['activate'].get_data(as_text=True)[:300])
        upload = self.session.uploads[-1]
        self.assertEqual((upload.name, upload.files), ('twin', ['configs/r1.cfg', 'configs/r2.cfg']))
        self.assertEqual(self.service.loaded_content_hash, twin_hash)

    def swap_configs_for_a_symlink(self, snapshot: Path) -> None:
        outside = self.sandbox.root / 'outside'
        write_file(outside / 'r1.cfg', self.SECRET)
        (snapshot / 'configs').rename(snapshot / 'configs-moved')
        os.symlink(outside, snapshot / 'configs')

    def test_a_symlinked_directory_swapped_in_after_the_scan_is_never_followed(self):
        snapshot = self.create('web', {'configs/r1.cfg': CONFIG_R1})
        scan = self.sandbox.state.scan_tree(snapshot)
        self.swap_configs_for_a_symlink(snapshot)
        destination = self.sandbox.root / 'copy-target' / 'web'
        destination.mkdir(parents=True)

        with self.assertRaises(state_module.TreeMovedError):
            state_module.hash_files(scan.files)
        with self.assertRaises(state_module.TreeMovedError):
            state_module.copy_files(scan.files, destination)
        with self.assertRaises(state_module.TreeMovedError):
            self.sandbox.history.put_files(scan.files)

        copied = [path.read_text() for path in destination.rglob('*') if path.is_file()]
        self.assertNotIn(self.SECRET, copied)
        self.assertFalse(self.sandbox.history.object_path(sha(self.SECRET)).exists())

    def test_staging_never_follows_a_directory_swapped_for_a_symlink_during_the_copy(self):
        snapshot = self.create('web', {'configs/r1.cfg': CONFIG_R1})
        state = self.sandbox.state
        original_scan = state.scan_tree
        swapped = []

        def swapping_scan(snapshot_dir):
            scan = original_scan(snapshot_dir)
            if not swapped:
                swapped.append(True)
                self.swap_configs_for_a_symlink(snapshot)
            return scan

        with mock.patch.object(state, 'scan_tree', side_effect=swapping_scan), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            staged, _ = state.stage_for_upload(snapshot)
        staged_texts = [path.read_text() for path in staged.rglob('*') if path.is_file()]
        state.cleanup_staging(staged)

        self.assertNotIn(self.SECRET, staged_texts)
        self.assertEqual(staged_texts, [CONFIG_R1])

    def test_a_tree_changed_during_the_staging_copy_fails_the_activation_without_an_upload(self):
        snapshot = self.create('web', {'configs/r1.cfg': CONFIG_R1})
        original_copy = state_module.copy_files
        counter = iter(range(100))

        def changing_copy(files, destination):
            manifest = original_copy(files, destination)
            write_file(snapshot / 'configs' / 'r1.cfg', f'hostname changed-{next(counter)}\n')
            return manifest

        with mock.patch.object(state_module, 'copy_files', side_effect=changing_copy), \
                self.assertLogs('services.batfish_service', level='WARNING'):
            response = self.activate('web')

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()['code'], 'snapshot_activation_error')
        self.assertEqual(self.parses(), 0)
        staging_root = self.sandbox.state.staging_root()
        self.assertEqual(list(staging_root.iterdir()) if staging_root.exists() else [], [])
        self.assertEqual(self.service.activation_failures._entries, {})


class AllowlistTest(unittest.TestCase):
    FORBIDDEN = ('request.args', 'request.get_json', 'request.json', 'request.data', 'request.form',
                 'request.values', 'request.files', 'get_data(', 'get_query_specifier')

    def test_the_table_generates_the_cached_endpoints_of_parameterless_get_routes(self):
        routes = app_module.CACHED_QUERY_ROUTES
        self.assertEqual(len(routes), 61)
        self.assertEqual(app_module.CACHED_QUERY_ENDPOINTS, frozenset(view for _, view in routes))
        rules = {rule.rule: rule for rule in app_module.app.url_map.iter_rules()}
        for path, view in routes:
            with self.subTest(path=path):
                rule = rules[path]
                self.assertEqual(rule.endpoint, view)
                self.assertEqual(rule.methods - {'HEAD', 'OPTIONS'}, {'GET'})
                self.assertFalse(rule.arguments)
                wrapped = app_module.app.view_functions[view]
                self.assertEqual(getattr(wrapped, 'cached_endpoint_key', None), view)
                source = inspect.getsource(inspect.unwrap(wrapped))
                for token in self.FORBIDDEN:
                    self.assertNotIn(token, source)

        listed = {path for path, _ in routes}
        for path, reason in app_module.CACHED_QUERY_EXCLUSIONS.items():
            self.assertIn(path, rules)
            self.assertTrue(reason)
        for rule in app_module.app.url_map.iter_rules():
            if 'GET' in rule.methods and rule.rule.startswith(app_module.SNAPSHOT_QUERY_PREFIXES) and not rule.arguments:
                self.assertTrue(
                    rule.rule in listed or rule.rule in app_module.CACHED_QUERY_EXCLUSIONS,
                    f"{rule.rule} is neither cached nor excluded with a reason",
                )

    def test_the_cache_clear_route_is_unlocked_and_accepts_no_body(self):
        self.assertIs(app_module.VERSION_ENDPOINT_USES_BATFISH['clear_snapshot_result_cache'], False)
        self.assertIn('clear_snapshot_result_cache', app_module.OPTIONAL_BODY_ENDPOINTS)


AUTH_CACHE_SCRIPT = r'''
import gzip
import io
import json
import os
import sys
import uuid
from types import SimpleNamespace
from unittest import mock

from app import app

app_module = sys.modules["app"]
service = app_module.batfish_service
ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
CONFIG = b"hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
results = {}
uploads = []
getter_calls = []


class Probe:
    clock = staticmethod(lambda: 0.0)

    def current(self):
        return "bf-test"

    def peek(self):
        return "bf-test"

    def feed(self, version, observed_at):
        return "bf-test"

    def snapshot_status(self, network, snapshot):
        return 200, "{}"


class Session:
    def __init__(self):
        self.network = None
        self.snapshot = None
        self.fail_next = None

    def set_network(self, name):
        self.network = name

    def get_component_versions(self):
        return {"Batfish": "bf-test"}

    def init_snapshot(self, path, name=None, overwrite=False):
        uploads.append((self.network, name))
        if self.fail_next is not None:
            failure, self.fail_next = self.fail_next, None
            raise failure
        self.snapshot = name
        return name


def nodes():
    service._ensure_initialized()
    getter_calls.append((service.network_name, service.current_snapshot_name))
    return [{"node": "r1"}]


service.version_probe = Probe()
service._session = Session()
for name in ("get_file_parse_status", "get_init_issues", "get_parse_warnings"):
    mock.patch.object(service, name, return_value=[]).start()
mock.patch.object(service, "get_node_properties", side_effect=nodes).start()
mock.patch.object(service, "traceroute", side_effect=lambda **kwargs: (service._ensure_initialized(), [])[1]).start()


def login(username, password):
    client = app.test_client()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    data = (response.get_json(silent=True) or {}).get("data") or {}
    client.environ_base["HTTP_X_CSRF_TOKEN"] = data.get("csrf_token") or ""
    return client


def record(key, response):
    payload = response.get_json(silent=True) or {}
    results[key] = {
        "status": response.status_code,
        "code": payload.get("code"),
        "data": payload.get("data"),
        "cache": response.headers.get("X-Topologix-Cache"),
        "hash": response.headers.get("X-Topologix-Content-Hash"),
        "etag": response.headers.get("ETag"),
        "cache_control": response.headers.get("Cache-Control"),
        "expose": response.headers.get("Access-Control-Expose-Headers"),
    }


def create(client, name):
    client.post("/api/snapshots", json={"name": name})
    client.post(f"/api/snapshots/{name}/files", data={"file": (io.BytesIO(CONFIG), "r1.cfg")},
                content_type="multipart/form-data")


admin = login("admin", ADMIN_PASSWORD)
bearer = {"Authorization": f"Bearer {admin.get_cookie('access_token').value}"}
results["create_user"] = admin.post(
    "/api/users", json={"username": "bob", "email": "bob@example.test", "password": "Pw!bobA9xyz12"},
    headers=bearer,
).status_code
bob = login("bob", "Pw!bobA9xyz12")
create(admin, "admin-snap")
create(admin, "admin-other")
create(bob, "bob-snap")

admin.post("/api/snapshots/admin-snap/activate")
record("admin_miss", admin.get("/api/network/nodes"))
record("admin_hit", admin.get("/api/network/nodes", headers={"If-None-Match": "*", "Accept-Encoding": "gzip"}))
bob.post("/api/snapshots/bob-snap/activate")
record("bob_first", bob.get("/api/network/nodes"))

admin_hit_calls = len(getter_calls)
service.network_name = "topologix_network_user_1"
service.current_snapshot_name = "admin-other"
counting = {"acquired": 0}
real_lock = app_module.batfish_request_lock


class CountingLock:
    def acquire(self, *args, **kwargs):
        counting["acquired"] += 1
        return real_lock.acquire(*args, **kwargs)

    def release(self):
        return real_lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()


with mock.patch.object(app_module, "batfish_request_lock", CountingLock()), \
        mock.patch.object(app_module, "activate_batfish_snapshot", side_effect=AssertionError("activated")), \
        mock.patch.object(service, "set_network_context", side_effect=AssertionError("switched")):
    record("session_hit", admin.get("/api/network/nodes"))
results["session_hit_lock"] = counting["acquired"]
results["session_hit_calls"] = len(getter_calls) - admin_hit_calls
results["process_snapshot"] = service.current_snapshot_name

db_id = app_module.snapshot_history_service.db_id
admin_scope = f"{db_id}:1"
working = results["admin_miss"]["hash"]
foreign = app_module.result_cache.store(
    working, "get_routes", f"{uuid.uuid4()}:1", b'{"status":"success","data":"foreign"}', str(uuid.uuid4()), None,
    batfish_version="bf-test",
)
mock.patch.object(service, "get_routes", side_effect=lambda: (service._ensure_initialized(), [])[1]).start()
record("foreign_scope", admin.get("/api/network/routes"))

record("admin_clear", admin.post("/api/snapshots/admin-snap/cache/clear"))
record("bob_after_admin_clear", bob.get("/api/network/nodes"))
parses_before = len(uploads)
record("admin_after_clear", admin.get("/api/network/nodes"))
results["admin_clear_parses"] = len(uploads) - parses_before

bob.delete("/api/snapshots/bob-snap")
create(bob, "bob-snap")
bob.post("/api/snapshots/bob-snap/activate")
record("bob_recreated", bob.get("/api/network/nodes"))
record("admin_still_hit", admin.get("/api/network/nodes"))

service._drop_loaded_state()
parses_before = len(uploads)
record("admin_traceroute_after_drop", admin.post("/api/path/traceroute", json={"startLocation": "r1"}))
results["drop_parses"] = len(uploads) - parses_before

service._drop_loaded_state()
service._session.fail_next = RuntimeError("Batfish is restarting")
record("admin_lazy_failure", admin.post("/api/path/traceroute", json={"startLocation": "r1"}))
results["active_after_lazy_failure"] = [
    item["name"] for item in admin.get("/api/snapshots").get_json()["data"] if item["active"]
]
results["process_after_lazy_failure"] = service.current_snapshot_name

record("anonymous_stats", app.test_client().get("/api/cache/stats"))
record("bob_stats", bob.get("/api/cache/stats"))
record("admin_stats", admin.get("/api/cache/stats"))
record("invalid_initialize", admin.post("/api/network/initialize", json={"snapshot_name": ".."}))
record("initialize", admin.post("/api/network/initialize", json={"snapshot_name": "admin-snap"}))
record("cors", admin.get("/api/health", headers={"Origin": "http://localhost:3000"}))

record("admin_before_owner_change", admin.get("/api/network/nodes"))
sidecar = os.path.join(os.environ["SNAPSHOTS_DIR"], "admin-snap", ".topologix-snapshot.json")
with open(sidecar, encoding="utf-8") as handle:
    metadata = json.load(handle)
metadata["owner_user_id"] = 2
with open(sidecar, "w", encoding="utf-8") as handle:
    json.dump(metadata, handle)
record("admin_after_owner_change", admin.get("/api/network/nodes"))
record("admin_after_session_cleared", admin.get("/api/network/nodes"))
print(json.dumps(results))
'''


class AuthOnCacheTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / 'snapshots').mkdir()
            (root / 'data').mkdir()
            env = os.environ.copy()
            env.update({
                'AUTH_ENABLED': 'true',
                'RESULT_CACHE_ENABLED': 'true',
                'SECRET_KEY': 'result-cache-test-secret-key',
                'JWT_SECRET_KEY': 'result-cache-test-jwt-secret-key',
                'CSRF_SECRET_KEY': 'result-cache-test-csrf-secret-key',
                'CSRF_MODE': 'session',
                'ALLOW_REGISTRATION': 'true',
                'AUTH_DEFAULT_ADMIN_USER': 'admin',
                'AUTH_DEFAULT_ADMIN_PASS': 'ResultCacheAdmin123!',
                'CORS_ORIGINS': 'http://localhost:3000',
                'DATABASE_URL': f"sqlite:///{root / 'result-cache.db'}",
                'SNAPSHOTS_DIR': str(root / 'snapshots'),
                'DATA_DIR': str(root / 'data'),
                'PYTHONPATH': str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, '-c', AUTH_CACHE_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def test_owners_with_identical_content_share_nothing(self):
        results = self.results
        self.assertEqual(results['create_user'], 201)
        self.assertEqual(results['admin_miss']['cache'], 'stored')
        self.assertEqual(results['admin_hit']['cache'], 'hit')
        self.assertEqual(results['bob_first']['cache'], 'stored')
        self.assertEqual(results['bob_first']['hash'], results['admin_miss']['hash'])
        self.assertEqual(results['foreign_scope']['cache'], 'stored')

    def test_cached_responses_keep_no_store_without_etags_or_304(self):
        for key in ('admin_miss', 'admin_hit', 'bob_first', 'session_hit'):
            with self.subTest(response=key):
                self.assertEqual(self.results[key]['status'], 200)
                self.assertIsNone(self.results[key]['etag'])
                self.assertIn('no-store', self.results[key]['cache_control'])

    def test_a_hit_skips_both_hooks_while_the_process_holds_another_snapshot(self):
        self.assertEqual(self.results['session_hit']['cache'], 'hit')
        self.assertEqual(self.results['session_hit_lock'], 0)
        self.assertEqual(self.results['session_hit_calls'], 0)
        self.assertEqual(self.results['process_snapshot'], 'admin-other')

    def test_clear_and_recreation_act_within_one_owner_scope(self):
        results = self.results
        self.assertEqual(results['admin_clear']['data'], {'cleared': True})
        self.assertEqual(results['bob_after_admin_clear']['cache'], 'hit')
        self.assertEqual(results['admin_after_clear']['cache'], 'stored')
        self.assertEqual(results['admin_clear_parses'], 1)
        self.assertEqual(results['bob_recreated']['cache'], 'stored')
        self.assertEqual(results['admin_still_hit']['cache'], 'hit')

    def test_non_cached_requests_re_parse_after_a_state_drop(self):
        self.assertEqual(self.results['admin_traceroute_after_drop']['status'], 200)
        self.assertEqual(self.results['drop_parses'], 1)

    def test_a_hash_driven_lazy_failure_keeps_the_session(self):
        self.assertEqual(self.results['admin_lazy_failure']['status'], 500)
        self.assertEqual(self.results['admin_lazy_failure']['code'], 'snapshot_activation_error')
        self.assertEqual(self.results['active_after_lazy_failure'], ['admin-snap'])
        self.assertEqual(self.results['process_after_lazy_failure'], 'admin-snap')

    def test_a_would_be_hit_still_enforces_the_owner(self):
        self.assertEqual(self.results['admin_before_owner_change']['cache'], 'hit')
        self.assertEqual(self.results['admin_after_owner_change']['status'], 403)
        self.assertEqual(self.results['admin_after_session_cleared']['status'], 400)
        self.assertEqual(self.results['admin_after_session_cleared']['code'], 'no_active_snapshot')

    def test_cache_stats_require_the_admin_role(self):
        self.assertEqual(self.results['anonymous_stats']['status'], 401)
        self.assertEqual(self.results['bob_stats']['status'], 403)
        self.assertEqual(self.results['admin_stats']['status'], 200)
        self.assertEqual(set(self.results['admin_stats']['data']), {'entries', 'bytes', 'max_bytes', 'max_entries'})

    def test_initialize_answers_400_for_an_invalid_name_and_carries_parsed(self):
        self.assertEqual(self.results['invalid_initialize']['status'], 400)
        self.assertEqual(self.results['initialize']['status'], 200)
        self.assertTrue(self.results['initialize']['data']['parsed'])

    def test_identity_headers_are_exposed_through_cors(self):
        exposed = self.results['cors']['expose'] or ''
        for header in ('X-Topologix-Snapshot-Id', 'X-Topologix-Content-Hash', 'X-Topologix-Cache'):
            self.assertIn(header, exposed)


if __name__ == '__main__':
    unittest.main()
