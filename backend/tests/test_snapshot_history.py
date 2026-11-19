import test_00_environment  # noqa: F401
import difflib
import errno
import hashlib
import io
import itertools
import os
import re
import shutil
import sqlite3
import stat
import threading
import time
import unittest
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from werkzeug.datastructures import FileStorage

import services.snapshot_history_service as history_module
import services.snapshot_state_service as state_module
from database.models import HistoryMeta, HistoryNamespace, HistoryObject, SnapshotState as SnapshotStateRow
from database.models import SnapshotVersion, SnapshotVersionFile
from database.session import DatabaseManager
from services.snapshot_history_service import VersionConflictError, VersionNotFoundError, VersionUnchangedError
from services.snapshot_history_service import PathClashError, RestoreFailedError
from services.result_cache import ResultCache, owner_scope_for
from services.snapshot_service import SnapshotService
from services.snapshot_state_service import (
    SnapshotEvaluationError,
    StateStoreError,
    TreeScan,
    VersioningUnavailableError,
    history_lock,
    is_canonical_uuid4,
)
from versioning_support import CONFIG_R1, CONFIG_R2, VersioningSandbox, set_times, sidecar_path, write_file

STATE_LOGGER = 'services.snapshot_state_service'
HISTORY_LOGGER = 'services.snapshot_history_service'
SECOND = 1_000_000_000


def config_text(hostname: str) -> str:
    return f"hostname {hostname}\ninterface Loopback0\n ip address 192.0.2.9 255.255.255.255\n"


def upload(sandbox: VersioningSandbox, name: str, filename: str, content: str, **context):
    storage = FileStorage(stream=io.BytesIO(content.encode('utf-8')), filename=filename, content_type='text/plain')
    return sandbox.snapshot_service.upload_file(name, storage, **context)


def failing_db_error() -> OperationalError:
    return OperationalError('SELECT 1', {}, Exception('database is unavailable'))


@contextmanager
def moving_fingerprint(state):
    """Make every stat walk report a new fingerprint so the tree never settles."""
    original = state.scan_tree
    counter = itertools.count()

    def moving(snapshot_dir):
        scan = original(snapshot_dir)
        fingerprint = hashlib.sha256(f"{scan.fingerprint}:{next(counter)}".encode()).hexdigest()
        return TreeScan(fingerprint=fingerprint, files=scan.files, timestamps=scan.timestamps)

    with mock.patch.object(state, 'scan_tree', side_effect=moving):
        yield


class SandboxTestCase(unittest.TestCase):
    def make_sandbox(self, **kwargs) -> VersioningSandbox:
        sandbox = VersioningSandbox(**kwargs)
        self.addCleanup(sandbox.cleanup)
        return sandbox

    def use_clock(self, sandbox: VersioningSandbox, start_ns: int | None = None) -> list:
        clock = [start_ns if start_ns is not None else time.time_ns()]
        sandbox.state._clock_ns = lambda: clock[0]
        return clock

    def rebase_clock(self, clock: list, snapshot: Path) -> None:
        """Move the fake clock to the newest change time (ctime) in the snapshot tree when that is later."""
        newest = max(os.lstat(path).st_ctime_ns for path in [snapshot, *snapshot.rglob('*')])
        clock[0] = max(clock[0], newest)

    def manifest_hash(self, sandbox: VersioningSandbox, name: str) -> str:
        return sandbox.state.compute_manifest(sandbox.snapshots_dir / name).content_hash


class EvaluationTest(SandboxTestCase):
    def test_first_evaluation_creates_a_baseline_with_objects(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('first', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2})

        state = sandbox.poll('first')

        self.assertEqual(state.content_hash, self.manifest_hash(sandbox, 'first'))
        self.assertFalse(state.uncommitted)
        self.assertFalse(state.pending_external)
        self.assertIsNone(state.restored_from)
        head = state.head
        self.assertTrue(is_canonical_uuid4(head['version_id']))
        self.assertEqual((head['seq'], head['kind'], head['message'], head['author']), (1, 'baseline', 'Initial state', None))
        self.assertEqual((head['file_count'], head['parent'], head['restored_from']), (2, None, None))
        self.assertEqual(sandbox.row(state.snapshot_id).next_seq, 2)
        detail = sandbox.history.get_version(state.snapshot_id, head['version_id'])
        for entry in detail['files']:
            object_path = sandbox.history.object_path(entry['sha256'])
            self.assertTrue(object_path.is_file())
            self.assertEqual(object_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sandbox.history.objects_dir.stat().st_mode & 0o777, 0o700)

    def test_empty_snapshot_baseline_references_no_objects(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('empty', {})

        state = sandbox.poll('empty')

        self.assertEqual(state.head['file_count'], 0)
        self.assertFalse(sandbox.history.objects_dir.exists())

    def test_fingerprint_only_change_creates_no_version(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('touch')
        first = sandbox.poll('touch')
        fingerprint = sandbox.row(first.snapshot_id).stat_fingerprint

        set_times(snapshot / 'configs' / 'r1.cfg', seconds_ago=7200)
        second = sandbox.poll('touch')

        self.assertEqual(len(sandbox.versions(first.snapshot_id)), 1)
        self.assertEqual(second.content_hash, first.content_hash)
        self.assertNotEqual(sandbox.row(first.snapshot_id).stat_fingerprint, fingerprint)

    def test_external_change_is_versioned_only_after_the_settle_window(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('settle')
        clock = self.use_clock(sandbox)
        baseline = sandbox.poll('settle')

        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.rebase_clock(clock, snapshot)
        settling = sandbox.poll('settle')

        self.assertTrue(settling.external_settling)
        self.assertEqual(settling.content_hash, baseline.content_hash)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

        clock[0] += 11 * SECOND
        with self.assertLogs(STATE_LOGGER, level='INFO') as logs:
            settled = sandbox.poll('settle')

        self.assertFalse(settled.external_settling)
        self.assertEqual(settled.content_hash, self.manifest_hash(sandbox, 'settle'))
        head = settled.head
        self.assertEqual((head['kind'], head['message'], head['author'], head['seq']),
                         ('external', 'External change detected', None, 2))
        self.assertEqual(head['parent'], {'version_id': baseline.head['version_id'], 'seq': 1})
        self.assertFalse(settled.uncommitted)
        self.assertTrue(any('External change versioned: snapshot=settle seq=2 files=1' in line for line in logs.output))

    def test_external_revert_to_head_inside_the_settle_window_keeps_settling(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('window-head')
        clock = self.use_clock(sandbox)
        baseline = sandbox.poll('window-head')
        upload(sandbox, 'window-head', 'r2.cfg', CONFIG_R2)
        uploaded = sandbox.poll('window-head')
        self.assertTrue(uploaded.uncommitted)

        (snapshot / 'configs' / 'r2.cfg').unlink()
        self.rebase_clock(clock, snapshot)
        clock[0] += 2 * SECOND
        settling = sandbox.poll('window-head')

        self.assertTrue(settling.external_settling)
        self.assertEqual(settling.content_hash, uploaded.content_hash)
        self.assertTrue(settling.uncommitted)

        clock[0] += 5 * SECOND
        copied = snapshot / 'configs' / 'r3.cfg'
        write_file(copied, config_text('r3'))
        os.utime(copied, ns=(clock[0], clock[0]))
        self.rebase_clock(clock, snapshot)
        clock[0] += 13 * SECOND
        after = sandbox.poll('window-head')

        self.assertFalse(after.external_settling)
        self.assertTrue(after.pending_external)
        self.assertTrue(after.uncommitted)
        self.assertEqual(after.content_hash, self.manifest_hash(sandbox, 'window-head'))
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_directory_times_hold_the_settle_window(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('dirs')
        clock = self.use_clock(sandbox)
        baseline = sandbox.poll('dirs')
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.rebase_clock(clock, snapshot)
        clock[0] += 11 * SECOND
        os.utime(snapshot / 'configs', ns=(clock[0], clock[0]))

        self.assertTrue(sandbox.poll('dirs').external_settling)
        clock[0] += 11 * SECOND
        self.assertEqual(sandbox.poll('dirs').head['kind'], 'external')
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 2)

    def test_future_mtime_is_ignored_with_one_warning(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('future')
        clock = self.use_clock(sandbox)
        baseline = sandbox.poll('future')
        future_file = snapshot / 'configs' / 'future.cfg'
        write_file(future_file, CONFIG_R2)
        one_year = 365 * 24 * 3600 * SECOND
        os.utime(future_file, ns=(clock[0] + one_year, clock[0] + one_year))
        self.rebase_clock(clock, snapshot)

        with self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            self.assertTrue(sandbox.poll('future').external_settling)
            clock[0] += 11 * SECOND
            versioned = sandbox.poll('future')
            self.assertFalse(versioned.external_settling)
            self.assertEqual(versioned.head['kind'], 'external')

            write_file(snapshot / 'configs' / 'r1.cfg', 'hostname r1-edited\n')
            os.utime(snapshot / 'configs' / 'r1.cfg', ns=(clock[0], clock[0]))
            self.rebase_clock(clock, snapshot)
            self.assertTrue(sandbox.poll('future').external_settling)
            clock[0] += 11 * SECOND
            self.assertEqual(sandbox.poll('future').head['seq'], 3)

        self.assertEqual(len([line for line in logs.output if 'timestamps in the future' in line]), 1)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 3)

    def test_no_external_version_while_an_api_write_is_in_progress(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('busy')
        baseline = sandbox.poll('busy')
        key = sandbox.state.id_key(baseline.snapshot_id)

        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        during = sandbox.poll('busy')
        sandbox.state.end_api_write(key, snapshot)
        after = sandbox.poll('busy')

        self.assertEqual(during.content_hash, baseline.content_hash)
        self.assertFalse(during.external_settling)
        self.assertEqual(after.content_hash, self.manifest_hash(sandbox, 'busy'))
        self.assertTrue(after.uncommitted)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)
        self.assertFalse(sandbox.state.write_in_progress(key))

    def test_pending_external_persists_on_an_uncommitted_tree_until_a_commit(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('pending')
        baseline = sandbox.poll('pending')
        snapshot_id = baseline.snapshot_id
        upload(sandbox, 'pending', 'r2.cfg', CONFIG_R2)

        write_file(snapshot / 'configs' / 'r3.cfg', 'hostname r3\n')
        flagged = sandbox.poll('pending')
        self.assertTrue(flagged.pending_external)
        self.assertTrue(flagged.uncommitted)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)

        sandbox.start()
        self.assertTrue(sandbox.poll('pending').pending_external)
        write_file(snapshot / 'configs' / 'r3.cfg', 'hostname r3-again\n')
        self.assertTrue(sandbox.poll('pending').pending_external)
        sandbox.snapshot_service.delete_snapshot_file('pending', 'r2.cfg')
        still = sandbox.poll('pending')
        self.assertTrue(still.pending_external)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)

        version = sandbox.history.commit(snapshot_id, snapshot, 'combined edits')
        committed = sandbox.poll('pending')

        self.assertEqual(version['kind'], 'manual')
        self.assertFalse(committed.pending_external)
        self.assertFalse(committed.uncommitted)

    def test_external_revert_to_head_clears_pending_external(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('revert')
        baseline = sandbox.poll('revert')
        upload(sandbox, 'revert', 'r2.cfg', CONFIG_R2)
        write_file(snapshot / 'configs' / 'r3.cfg', 'hostname r3\n')
        self.assertTrue(sandbox.poll('revert').pending_external)

        (snapshot / 'configs' / 'r2.cfg').unlink()
        (snapshot / 'configs' / 'r3.cfg').unlink()
        reverted = sandbox.poll('revert')

        self.assertEqual(reverted.content_hash, baseline.content_hash)
        self.assertFalse(reverted.pending_external)
        self.assertFalse(reverted.uncommitted)
        self.assertIsNone(reverted.restored_from)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_next_api_write_forces_an_external_change_into_a_version_on_a_clean_tree(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('force')
        self.use_clock(sandbox)
        baseline = sandbox.poll('force')
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.assertTrue(sandbox.poll('force').external_settling)

        upload(sandbox, 'force', 'r3.cfg', config_text('r3'))
        after = sandbox.poll('force')

        kinds = [version['kind'] for version in sandbox.versions(baseline.snapshot_id)]
        self.assertEqual(kinds, ['external', 'baseline'])
        self.assertTrue(after.uncommitted)
        self.assertFalse(after.pending_external)
        self.assertEqual(after.content_hash, self.manifest_hash(sandbox, 'force'))

    def test_concurrent_first_evaluations_create_exactly_one_baseline(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('race')
        errors = []

        def poll():
            try:
                sandbox.poll('race')
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=poll) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(20)

        self.assertEqual(errors, [])
        self.assertEqual(sandbox.version_count(), 1)
        with self.assertRaises(IntegrityError):
            with sandbox.db.get_db_session() as session:
                session.add(SnapshotStateRow(
                    namespace=sandbox.state.namespace, snapshot_id=sandbox.snapshot_id('race'),
                    snapshot_name='race', next_seq=1, pending_external=False,
                ))

    def test_poll_shares_an_in_flight_poll_while_end_api_write_runs_its_own_evaluation(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('share')
        baseline = sandbox.poll('share')
        key = sandbox.state.id_key(baseline.snapshot_id)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        entered = threading.Event()
        release = threading.Event()
        joined = threading.Event()
        writer_waiting = threading.Event()
        original_put = sandbox.history.put_files
        original_evaluation_lock = sandbox.state.evaluation_lock
        put_threads = []

        def blocking_put(files):
            put_threads.append(threading.current_thread().name)
            if len(put_threads) == 1:
                entered.set()
                release.wait(10)
            return original_put(files)

        @contextmanager
        def signalling_evaluation_lock(snapshot_id, snapshot_dir):
            if threading.current_thread().name == 'writer':
                writer_waiting.set()
            with original_evaluation_lock(snapshot_id, snapshot_dir):
                yield

        class JoinSignallingEvent(threading.Event):
            def wait(self, timeout=None):
                joined.set()
                return super().wait(timeout)

        results = {}
        with mock.patch.object(sandbox.history, 'put_files', side_effect=blocking_put), \
                mock.patch.object(sandbox.state, 'evaluation_lock', side_effect=signalling_evaluation_lock):
            poll_a = threading.Thread(target=lambda: results.__setitem__('a', sandbox.poll('share')), name='poll-a')
            poll_a.start()
            self.assertTrue(entered.wait(10))
            inflight = sandbox.state._inflight_polls[(sandbox.state.namespace, baseline.snapshot_id, 'share')]
            inflight.event = JoinSignallingEvent()
            poll_b = threading.Thread(target=lambda: results.__setitem__('b', sandbox.poll('share')), name='poll-b')
            poll_b.start()
            self.assertTrue(joined.wait(10))
            sandbox.state.begin_api_write(key)
            write_file(snapshot / 'configs' / 'r2.cfg', 'hostname r2-api\n')
            writer = threading.Thread(target=sandbox.state.end_api_write, args=(key, snapshot), name='writer')
            writer.start()
            self.assertTrue(writer_waiting.wait(10))
            release.set()
            for thread in (poll_a, poll_b, writer):
                thread.join(20)

        self.assertIs(results['b'], results['a'])
        self.assertNotIn('poll-b', put_threads)
        self.assertEqual(sandbox.version_count(), 1)
        final = sandbox.poll('share')
        self.assertEqual(final.content_hash, self.manifest_hash(sandbox, 'share'))
        self.assertTrue(final.uncommitted)
        self.assertFalse(final.pending_external)

    def test_hashing_and_object_copies_run_outside_history_lock(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('probe')
        observations = []
        original_hash = state_module.hash_files
        original_put = sandbox.history.put_files

        def probe_hash(files):
            observations.append(('hash', history_lock._is_owned()))
            return original_hash(files)

        def probe_put(files):
            observations.append(('put', history_lock._is_owned()))
            return original_put(files)

        with mock.patch.object(state_module, 'hash_files', side_effect=probe_hash), \
                mock.patch.object(sandbox.history, 'put_files', side_effect=probe_put):
            baseline = sandbox.poll('probe')
            write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
            sandbox.poll('probe')
            upload(sandbox, 'probe', 'r2.cfg', CONFIG_R2)
            sandbox.history.commit(baseline.snapshot_id, snapshot, 'probe commit')

        self.assertIn(('hash', False), observations)
        self.assertIn(('put', False), observations)
        self.assertFalse(any(owned for _, owned in observations))

    def test_entry_removed_during_hashing_is_a_moved_fingerprint(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('vanish', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2})
        baseline = sandbox.poll('vanish')
        write_file(snapshot / 'configs' / 'r1.cfg', 'hostname r1-edited\n')
        original_put = sandbox.history.put_files
        calls = []

        def vanishing_put(files):
            calls.append(1)
            if len(calls) == 1:
                (snapshot / 'configs' / 'r2.cfg').unlink()
            return original_put(files)

        with mock.patch.object(sandbox.history, 'put_files', side_effect=vanishing_put):
            state = sandbox.poll('vanish')

        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(state.content_hash, self.manifest_hash(sandbox, 'vanish'))
        detail = sandbox.history.get_version(baseline.snapshot_id, state.head['version_id'])
        self.assertEqual([entry['path'] for entry in detail['files']], ['configs/r1.cfg'])

    def test_entry_vanishing_during_the_stat_walk_is_a_moved_fingerprint(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('walk-vanish')
        baseline = sandbox.poll('walk-vanish')
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        original_scan = sandbox.state.scan_tree
        calls = []

        def vanishing_scan(snapshot_dir):
            calls.append(1)
            if len(calls) == 1:
                raise state_module.TreeMovedError('r1.cfg')
            return original_scan(snapshot_dir)

        with mock.patch.object(sandbox.state, 'scan_tree', side_effect=vanishing_scan):
            state = sandbox.poll('walk-vanish')

        self.assertGreater(len(calls), 1)
        self.assertEqual(state.content_hash, self.manifest_hash(sandbox, 'walk-vanish'))
        self.assertEqual(state.head['kind'], 'external')
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 2)

    def test_root_removed_between_hashing_and_step_three_creates_nothing(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('gone')
        snapshot_id = sandbox.snapshot_id('gone')
        original_put = sandbox.history.put_files

        def removing_put(files):
            manifest = original_put(files)
            shutil.rmtree(snapshot)
            return manifest

        with mock.patch.object(sandbox.history, 'put_files', side_effect=removing_put):
            with self.assertRaises(SnapshotEvaluationError) as raised:
                sandbox.state.evaluate_snapshot(snapshot)

        self.assertIsInstance(raised.exception.__cause__, FileNotFoundError)
        self.assertIsNone(sandbox.row(snapshot_id))
        self.assertEqual(sandbox.version_count(), 0)

    def test_snapshot_recreated_under_the_same_name_during_hashing_creates_nothing(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('reborn')
        old_id = sandbox.snapshot_id('reborn')
        original_put = sandbox.history.put_files

        def recreating_put(files):
            manifest = original_put(files)
            shutil.rmtree(snapshot)
            sandbox.create_snapshot('reborn')
            return manifest

        with mock.patch.object(sandbox.history, 'put_files', side_effect=recreating_put):
            with self.assertRaises(SnapshotEvaluationError):
                sandbox.state.evaluate_snapshot(snapshot)

        self.assertNotEqual(sandbox.snapshot_id('reborn'), old_id)
        self.assertIsNone(sandbox.row(old_id))
        self.assertEqual(sandbox.version_count(), 0)

    def test_marker_is_cleared_by_an_evaluation_that_finds_the_fingerprint_current(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('marker')
        baseline = sandbox.poll('marker')
        key = sandbox.state.id_key(baseline.snapshot_id)
        sandbox.state.set_marker(key)

        sandbox.poll('marker')
        self.assertIsNone(sandbox.state.get_marker(key))

        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        self.assertEqual(sandbox.poll('marker').head['kind'], 'external')


class WriterProtocolTest(SandboxTestCase):
    def test_api_writes_record_uncommitted_state_without_versions(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('writes')
        baseline = sandbox.poll('writes')
        snapshot_id = baseline.snapshot_id

        upload(sandbox, 'writes', 'r2.cfg', CONFIG_R2)
        self.assertEqual(sandbox.row(snapshot_id).content_hash, self.manifest_hash(sandbox, 'writes'))
        current = sandbox.snapshot_service.get_config_file_content('writes', 'r2.cfg')
        sandbox.snapshot_service.update_config_file_content('writes', 'r2.cfg', config_text('r2-new'), current['sha256'])
        self.assertEqual(sandbox.row(snapshot_id).content_hash, self.manifest_hash(sandbox, 'writes'))
        sandbox.snapshot_service.delete_snapshot_file('writes', 'r2.cfg')
        after_delete = sandbox.poll('writes')

        self.assertEqual(after_delete.content_hash, baseline.content_hash)
        self.assertFalse(after_delete.uncommitted)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)
        self.assertEqual(sandbox.state._in_progress, {})

        sandbox.snapshot_service.save_layer1_topology('writes', {'edges': []})
        self.assertTrue(sandbox.poll('writes').uncommitted)
        sandbox.snapshot_service.delete_layer1_topology('writes')
        self.assertFalse(sandbox.poll('writes').uncommitted)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)

    def test_writes_without_a_state_service_or_database_behave_as_today(self):
        for case in ('detached', 'no-database', 'temp-fallback'):
            with self.subTest(case=case):
                if case == 'detached':
                    sandbox = self.make_sandbox()
                    sandbox.snapshot_service.attach_state_service(None)
                elif case == 'no-database':
                    sandbox = self.make_sandbox(with_database=False)
                else:
                    sandbox = self.make_sandbox(DATA_DIR_FELL_BACK=True)
                sandbox.create_snapshot('plain')

                result = upload(sandbox, 'plain', 'r2.cfg', CONFIG_R2)
                sandbox.snapshot_service.delete_snapshot_file('plain', 'r2.cfg')

                self.assertTrue(result['requires_reinitialize'])
                self.assertFalse((sandbox.snapshots_dir / 'plain' / 'configs' / 'r2.cfg').exists())
                if sandbox.db is not None:
                    self.assertEqual(sandbox.version_count(), 0)

    def test_settle_failure_lets_the_write_proceed_and_the_write_is_recorded_later(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('settle-fail')
        baseline = sandbox.poll('settle-fail')

        with mock.patch.object(sandbox.state, 'settle_external_changes', side_effect=RuntimeError('boom')), \
                self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            result = upload(sandbox, 'settle-fail', 'r2.cfg', CONFIG_R2)

        self.assertTrue(result['requires_reinitialize'])
        self.assertTrue(any('settling external changes failed' in line for line in logs.output))
        after = sandbox.poll('settle-fail')
        self.assertEqual(after.content_hash, self.manifest_hash(sandbox, 'settle-fail'))
        self.assertTrue(after.uncommitted)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)
        self.assertEqual(sandbox.state._in_progress, {})

    def test_resolution_failure_while_writing_an_unopened_copy_leaves_the_original_untouched(self):
        sandbox = self.make_sandbox()
        original = sandbox.create_snapshot('origin')
        baseline = sandbox.poll('origin')
        snapshot_id = baseline.snapshot_id
        shutil.copytree(original, sandbox.snapshots_dir / 'copy')
        original_rows = sandbox.state._resolve_rows

        def failing_for_copy(resolved_id, snapshot_dir):
            if snapshot_dir.name == 'copy':
                raise failing_db_error()
            return original_rows(resolved_id, snapshot_dir)

        with mock.patch.object(sandbox.state, '_resolve_rows', side_effect=failing_for_copy):
            with self.assertLogs(STATE_LOGGER, level='WARNING'):
                upload(sandbox, 'copy', 'r2.cfg', CONFIG_R2)
            self.assertFalse(sandbox.state.write_in_progress(sandbox.state.id_key(snapshot_id)))
            self.assertIsNone(sandbox.state.get_marker(sandbox.state.id_key(snapshot_id)))
            self.assertIsNotNone(sandbox.state.get_marker(sandbox.state.dir_key(sandbox.snapshots_dir / 'copy')))

        row = sandbox.row(snapshot_id)
        self.assertEqual((row.snapshot_name, row.content_hash), ('origin', baseline.content_hash))
        write_file(original / 'configs' / 'r1.cfg', CONFIG_R2)
        self.assertEqual(sandbox.poll('origin').head['kind'], 'external')

    def test_write_to_an_unopened_copy_racing_the_original_first_evaluation(self):
        for settle_fails in (False, True):
            with self.subTest(settle_fails=settle_fails):
                sandbox = self.make_sandbox()
                original = sandbox.create_snapshot('origin')
                copy_dir = sandbox.snapshots_dir / 'copy'
                shutil.copytree(original, copy_dir)
                shared_id = sandbox.snapshot_id('origin')
                original_key = sandbox.state.id_key(shared_id)
                original_hashing = threading.Event()
                release_original = threading.Event()
                real_put = sandbox.history.put_files
                polled = []
                poller = threading.Thread(target=lambda: polled.append(sandbox.poll('origin')), name='original-poll')

                def finish_original_evaluation():
                    if not release_original.is_set():
                        release_original.set()
                        poller.join(20)

                def racing_put(files):
                    if threading.current_thread().name == 'original-poll' and not release_original.is_set():
                        original_hashing.set()
                        release_original.wait(10)
                    elif threading.current_thread().name != 'original-poll':
                        finish_original_evaluation()
                    return real_put(files)

                observed = {}

                class ObservingStorage(FileStorage):
                    def save(self, dst, buffer_size=16384):
                        copy_id = sandbox.snapshot_id('copy')
                        observed.update({
                            'copy_id': copy_id,
                            'original_in_progress': sandbox.state.write_in_progress(original_key),
                            'original_marker': sandbox.state.get_marker(original_key),
                            'copy_id_in_progress': sandbox.state.write_in_progress(sandbox.state.id_key(copy_id)),
                            'dir_in_progress': sandbox.state.write_in_progress(sandbox.state.dir_key(copy_dir)),
                            'dir_marker': sandbox.state.get_marker(sandbox.state.dir_key(copy_dir)),
                        })
                        finish_original_evaluation()
                        return super().save(dst, buffer_size)

                storage = ObservingStorage(
                    stream=io.BytesIO(CONFIG_R2.encode()), filename='r2.cfg', content_type='text/plain',
                )
                with mock.patch.object(sandbox.history, 'put_files', side_effect=racing_put):
                    poller.start()
                    self.assertTrue(original_hashing.wait(10))
                    if settle_fails:
                        with mock.patch.object(sandbox.state, 'settle_external_changes',
                                               side_effect=RuntimeError('boom')), \
                                self.assertLogs(STATE_LOGGER, level='WARNING'):
                            sandbox.snapshot_service.upload_file('copy', storage)
                    else:
                        sandbox.snapshot_service.upload_file('copy', storage)
                    finish_original_evaluation()

                self.assertEqual(polled[0].snapshot_id, shared_id)
                self.assertFalse(observed['original_in_progress'])
                self.assertIsNone(observed['original_marker'])
                if settle_fails:
                    self.assertEqual(observed['copy_id'], shared_id)
                    self.assertTrue(observed['dir_in_progress'])
                    self.assertIsNotNone(observed['dir_marker'])
                else:
                    self.assertNotEqual(observed['copy_id'], shared_id)
                    self.assertTrue(observed['copy_id_in_progress'])
                    self.assertFalse(observed['dir_in_progress'])

                fresh_id = sandbox.snapshot_id('copy')
                self.assertNotEqual(fresh_id, shared_id)
                original_row = sandbox.row(shared_id)
                copy_row = sandbox.row(fresh_id)
                self.assertEqual(original_row.snapshot_name, 'origin')
                self.assertEqual(original_row.content_hash, self.manifest_hash(sandbox, 'origin'))
                self.assertEqual(copy_row.snapshot_name, 'copy')
                self.assertEqual(copy_row.content_hash, self.manifest_hash(sandbox, 'copy'))
                self.assertNotEqual(copy_row.content_hash, original_row.content_hash)
                self.assertEqual(len(sandbox.versions(shared_id)), 1)
                self.assertFalse(sandbox.state.write_in_progress(original_key))
                self.assertIsNone(sandbox.state.get_marker(original_key))
                self.assertEqual(sandbox.state._in_progress, {})

    def test_rejected_writes_run_no_settle(self):
        sandbox = self.make_sandbox()
        sandbox.snapshot_service.create_snapshot('owned', owner_user_id=7, owner_username='alice', auth_enabled=True)
        write_file(sandbox.snapshots_dir / 'owned' / 'configs' / 'r1.cfg', CONFIG_R1)

        with mock.patch.object(sandbox.state, 'settle_external_changes') as settle:
            with self.assertRaises(PermissionError):
                upload(sandbox, 'owned', 'r2.cfg', CONFIG_R2, requester_user_id=8, auth_enabled=True)
            with self.assertRaises(ValueError):
                upload(sandbox, '../owned', 'r2.cfg', CONFIG_R2)

        settle.assert_not_called()
        self.assertEqual(sandbox.version_count(), 0)

    def test_held_resolution_failure_during_a_write_uses_the_directory_key(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('held')
        baseline = sandbox.poll('held')
        snapshot_id = baseline.snapshot_id
        failing = [True]
        original_rows = sandbox.state._resolve_rows

        def maybe_failing(resolved_id, snapshot_dir):
            if failing[0]:
                raise failing_db_error()
            return original_rows(resolved_id, snapshot_dir)

        with mock.patch.object(sandbox.state, '_resolve_rows', side_effect=maybe_failing):
            with self.assertLogs(STATE_LOGGER, level='WARNING'):
                scope = sandbox.state.open_write_scope(snapshot)
            self.assertEqual(scope.key[0], 'dir')
            write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

            failing[0] = False
            during = sandbox.poll('held')
            self.assertEqual(during.content_hash, baseline.content_hash)
            with self.assertRaises(VersionConflictError):
                sandbox.history.commit(snapshot_id, snapshot, 'blocked')

            failing[0] = True
            with self.assertLogs(STATE_LOGGER, level='WARNING'):
                sandbox.state.close_write_scope(scope)
            self.assertEqual(sandbox.row(snapshot_id).content_hash, baseline.content_hash)
            self.assertIsNotNone(sandbox.state.get_marker(scope.key))

            failing[0] = False
            after = sandbox.poll('held')

        self.assertEqual(after.content_hash, self.manifest_hash(sandbox, 'held'))
        self.assertTrue(after.uncommitted)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)
        self.assertIsNone(sandbox.state.get_marker(scope.key))

    def test_poll_during_a_write_before_any_baseline_answers_the_null_hash_object(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('no-row')
        with mock.patch.object(sandbox.state, 'settle_external_changes', side_effect=RuntimeError('boom')), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            scope = sandbox.state.open_write_scope(snapshot)

        during = sandbox.poll('no-row')

        self.assertIsNone(during.content_hash)
        self.assertIsNone(during.head)
        self.assertFalse(during.external_settling)
        self.assertFalse(during.uncommitted)
        self.assertEqual(sandbox.version_count(), 0)
        sandbox.state.close_write_scope(scope)
        self.assertEqual(sandbox.poll('no-row').head['kind'], 'baseline')

    def test_failed_end_api_write_leaves_a_marker_and_no_external_version(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('lost')
        baseline = sandbox.poll('lost')
        key = sandbox.state.id_key(baseline.snapshot_id)
        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        with mock.patch.object(sandbox.state, '_evaluate_locked', side_effect=failing_db_error()), \
                self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            sandbox.state.end_api_write(key, snapshot)

        self.assertTrue(any('could not be recorded' in line for line in logs.output))
        self.assertIsNotNone(sandbox.state.get_marker(key))
        self.assertFalse(sandbox.state.write_in_progress(key))
        after = sandbox.poll('lost')
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)
        self.assertTrue(after.uncommitted)
        self.assertIsNone(sandbox.state.get_marker(key))


class NeverSettlingTreeTest(SandboxTestCase):
    def test_end_api_write_stores_pending_external_and_restored_from(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('moving')
        baseline = sandbox.poll('moving')
        key = sandbox.state.id_key(baseline.snapshot_id)
        source = {'version_id': baseline.head['version_id'], 'seq': 1}
        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        with moving_fingerprint(sandbox.state):
            sandbox.state.end_api_write(key, snapshot, restored_from=source)

        row = sandbox.row(baseline.snapshot_id)
        self.assertTrue(row.pending_external)
        self.assertEqual((row.restored_from_version_id, row.restored_from_seq), (source['version_id'], 1))
        self.assertEqual(row.content_hash, self.manifest_hash(sandbox, 'moving'))
        self.assertNotEqual(row.stat_fingerprint, sandbox.state.compute_stat_fingerprint(snapshot))
        next_poll = sandbox.poll('moving')
        self.assertTrue(next_poll.pending_external)
        self.assertEqual(sandbox.row(baseline.snapshot_id).stat_fingerprint,
                         sandbox.state.compute_stat_fingerprint(snapshot))
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

        (snapshot / 'configs' / 'r1.cfg').write_text(CONFIG_R1, encoding='utf-8')
        sandbox.state.begin_api_write(key)
        with moving_fingerprint(sandbox.state):
            sandbox.state.end_api_write(key, snapshot, restored_from=source)
        cleared = sandbox.row(baseline.snapshot_id)
        self.assertFalse(cleared.pending_external)
        self.assertIsNone(cleared.restored_from_seq)

    def test_settle_stores_pending_external_without_a_version(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('moving-settle')
        baseline = sandbox.poll('moving-settle')
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        with moving_fingerprint(sandbox.state):
            sandbox.state.settle_external_changes(baseline.snapshot_id, snapshot)

        row = sandbox.row(baseline.snapshot_id)
        self.assertTrue(row.pending_external)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_marker_and_never_settling_forced_settle_sets_pending_external(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('marker-moving')
        baseline = sandbox.poll('marker-moving')
        sandbox.state.set_marker(sandbox.state.id_key(baseline.snapshot_id))
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        with moving_fingerprint(sandbox.state):
            sandbox.state.settle_external_changes(baseline.snapshot_id, snapshot)

        self.assertTrue(sandbox.row(baseline.snapshot_id).pending_external)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_without_a_row_the_writer_creates_the_baseline_and_a_poll_reports_no_hash(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('moving-new')
        snapshot_id = sandbox.snapshot_id('moving-new')

        with moving_fingerprint(sandbox.state):
            polled = sandbox.poll('moving-new')
            self.assertIsNone(polled.content_hash)
            self.assertTrue(polled.external_settling)
            self.assertIsNone(polled.head)
            self.assertFalse(polled.uncommitted)
            self.assertEqual(sandbox.version_count(), 0)
            sandbox.state.settle_external_changes(snapshot_id, snapshot)

        self.assertEqual(sandbox.versions(snapshot_id)[0]['kind'], 'baseline')
        self.assertEqual(sandbox.row(snapshot_id).next_seq, 2)

    def test_trashed_object_makes_the_never_settled_baseline_fail(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('trashed')
        snapshot_id = sandbox.snapshot_id('trashed')
        key = sandbox.state.id_key(snapshot_id)
        original_put = sandbox.history.put_files

        def trashing_put(files):
            manifest = original_put(files)
            for _, sha256, _ in manifest.files:
                sandbox.history.object_path(sha256).unlink(missing_ok=True)
            return manifest

        sandbox.state.begin_api_write(key)
        with moving_fingerprint(sandbox.state), \
                mock.patch.object(sandbox.history, 'put_files', side_effect=trashing_put), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            sandbox.state.end_api_write(key, snapshot)

        self.assertIsNone(sandbox.row(snapshot_id))
        self.assertIsNotNone(sandbox.state.get_marker(key))
        self.assertEqual(sandbox.object_count(), 0)
        self.assertEqual(sandbox.file_row_count(), 0)


class CommitTest(SandboxTestCase):
    def test_commit_creates_a_manual_version(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('commit')
        baseline = sandbox.poll('commit')
        upload(sandbox, 'commit', 'r2.cfg', CONFIG_R2)

        version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'add r2')
        state = sandbox.poll('commit')

        self.assertTrue(is_canonical_uuid4(version['version_id']))
        self.assertEqual((version['seq'], version['kind'], version['message'], version['author']),
                         (2, 'manual', 'add r2', None))
        self.assertEqual(version['parent'], {'version_id': baseline.head['version_id'], 'seq': 1})
        self.assertEqual((version['file_count'], version['total_bytes']), (2, len(CONFIG_R1) + len(CONFIG_R2)))
        self.assertEqual(state.head['version_id'], version['version_id'])
        self.assertFalse(state.uncommitted)
        self.assertEqual(sandbox.row(baseline.snapshot_id).next_seq, 3)

        upload(sandbox, 'commit', 'r3.cfg', config_text('r3'))
        third = sandbox.history.commit(
            baseline.snapshot_id, snapshot, 'add r3', author={'user_id': 7, 'username': 'alice'},
        )
        self.assertEqual((third['seq'], third['author']), (3, 'alice'))
        self.assertEqual(third['parent']['seq'], 2)

    def test_unchanged_and_conflicting_commits_log_no_error(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('noop')
        baseline = sandbox.poll('noop')
        head_id = baseline.head['version_id']

        with self.assertNoLogs('database.session', level='ERROR'):
            with self.assertRaises(VersionUnchangedError):
                sandbox.history.commit(baseline.snapshot_id, snapshot, 'nothing')
            upload(sandbox, 'noop', 'r2.cfg', CONFIG_R2)
            with self.assertRaises(VersionConflictError):
                sandbox.history.commit(baseline.snapshot_id, snapshot, 'stale', expected_head='other')
            with self.assertRaises(VersionConflictError):
                sandbox.history.commit(baseline.snapshot_id, snapshot, 'stale', expected_head=None)

        version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'fresh', expected_head=head_id)
        self.assertEqual(version['seq'], 2)

    def test_commit_without_a_row_creates_the_baseline_then_reports_unchanged(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('commit-first')
        snapshot_id = sandbox.snapshot_id('commit-first')

        with self.assertRaises(VersionUnchangedError):
            sandbox.history.commit(snapshot_id, snapshot, 'first')

        self.assertEqual([version['kind'] for version in sandbox.versions(snapshot_id)], ['baseline'])

    def test_external_change_on_a_clean_tree_becomes_its_own_version_first(self):
        sandbox = self.make_sandbox(EXTERNAL_CHANGE_SETTLE_SECONDS=10)
        snapshot = sandbox.create_snapshot('external-first')
        self.use_clock(sandbox)
        baseline = sandbox.poll('external-first')
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)

        with self.assertRaises(VersionUnchangedError):
            sandbox.history.commit(baseline.snapshot_id, snapshot, 'mine')

        self.assertEqual([v['kind'] for v in sandbox.versions(baseline.snapshot_id)], ['external', 'baseline'])

    def test_commit_honours_unrecorded_write_markers(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('marked')
        baseline = sandbox.poll('marked')
        key = sandbox.state.id_key(baseline.snapshot_id)

        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R2)
        sandbox.state.set_marker(key)
        manual = sandbox.history.commit(baseline.snapshot_id, snapshot, 'api edit')
        self.assertEqual(manual['kind'], 'manual')
        self.assertIsNone(sandbox.state.get_marker(key))

        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        source = {'version_id': baseline.head['version_id'], 'seq': 1}
        with mock.patch.object(sandbox.state, '_evaluate_locked', side_effect=failing_db_error()), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            sandbox.state.end_api_write(key, snapshot, restored_from=source)
        self.assertEqual(sandbox.state.get_marker(key).restored_from, source)

        restored = sandbox.history.commit(baseline.snapshot_id, snapshot, 'restored edit')

        self.assertEqual(restored['kind'], 'restore')
        self.assertEqual(restored['restored_from'], source)
        row = sandbox.row(baseline.snapshot_id)
        self.assertIsNone(row.restored_from_seq)
        self.assertFalse(row.pending_external)

    def test_end_api_write_without_restored_from_records_the_marker_value(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('carry')
        baseline = sandbox.poll('carry')
        key = sandbox.state.id_key(baseline.snapshot_id)
        source = {'version_id': baseline.head['version_id'], 'seq': 1}
        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        with mock.patch.object(sandbox.state, '_evaluate_locked', side_effect=failing_db_error()), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            sandbox.state.end_api_write(key, snapshot, restored_from=source)
        self.assertEqual(sandbox.state.get_marker(key).restored_from, source)

        with mock.patch.object(sandbox.state, 'settle_external_changes', side_effect=RuntimeError('boom')), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            upload(sandbox, 'carry', 'r3.cfg', config_text('r3'))

        self.assertIsNone(sandbox.state.get_marker(key))
        self.assertEqual(sandbox.poll('carry').restored_from, source)
        version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'restore after failures')
        self.assertEqual((version['kind'], version['restored_from']), ('restore', source))

    def test_snapshot_recreated_between_phase_one_and_phase_two(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('reborn-commit')
        baseline = sandbox.poll('reborn-commit')
        old_id = baseline.snapshot_id
        upload(sandbox, 'reborn-commit', 'r2.cfg', CONFIG_R2)
        stored_hash = sandbox.row(old_id).content_hash
        original_phase1 = sandbox.history._commit_phase1

        def phase1_then_recreate(snapshot_dir):
            prepared = original_phase1(snapshot_dir)
            shutil.rmtree(snapshot)
            sandbox.create_snapshot('reborn-commit')
            return prepared

        with mock.patch.object(sandbox.history, '_commit_phase1', side_effect=phase1_then_recreate):
            with self.assertRaises(FileNotFoundError):
                sandbox.history.commit(old_id, snapshot, 'stale')

        new_id = sandbox.snapshot_id('reborn-commit')
        self.assertNotEqual(new_id, old_id)
        self.assertIsNone(sandbox.row(new_id))
        row = sandbox.row(old_id)
        self.assertEqual((row.content_hash, row.next_seq), (stored_hash, 2))
        self.assertEqual(len(sandbox.versions(old_id)), 1)

    def test_restored_from_is_cleared_when_working_equals_head_and_drives_kind_restore(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('restore-kind')
        baseline = sandbox.poll('restore-kind')
        key = sandbox.state.id_key(baseline.snapshot_id)
        source = {'version_id': baseline.head['version_id'], 'seq': 1}

        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        sandbox.state.end_api_write(key, snapshot, restored_from=source)
        self.assertEqual(sandbox.poll('restore-kind').restored_from, source)

        (snapshot / 'configs' / 'r2.cfg').unlink()
        reverted = sandbox.poll('restore-kind')
        self.assertIsNone(reverted.restored_from)
        self.assertIsNone(sandbox.row(baseline.snapshot_id).restored_from_seq)

        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        sandbox.state.end_api_write(key, snapshot, restored_from=source)
        upload(sandbox, 'restore-kind', 'r3.cfg', config_text('r3'))
        self.assertEqual(sandbox.poll('restore-kind').restored_from, source)
        restore_version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'restore')
        self.assertEqual((restore_version['kind'], restore_version['restored_from']), ('restore', source))
        self.assertIsNone(sandbox.poll('restore-kind').restored_from)

        upload(sandbox, 'restore-kind', 'r4.cfg', config_text('r4'))
        self.assertEqual(sandbox.history.commit(baseline.snapshot_id, snapshot, 'next')['kind'], 'manual')

    def test_phase_one_restarts_when_the_fingerprint_moves_or_a_file_vanishes(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('restart', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2})
        baseline = sandbox.poll('restart')
        upload(sandbox, 'restart', 'r3.cfg', config_text('r3'))
        original_put = sandbox.history.put_files
        calls = []

        def changing_put(files):
            calls.append(1)
            manifest = original_put(files)
            if len(calls) == 1:
                write_file(snapshot / 'configs' / 'r3.cfg', 'hostname r3-moved\n')
            return manifest

        with mock.patch.object(sandbox.history, 'put_files', side_effect=changing_put):
            version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'moved')
        self.assertEqual(len(calls), 2)
        self.assertEqual(sandbox.poll('restart').head['version_id'], version['version_id'])
        self.assertFalse(sandbox.poll('restart').uncommitted)

        upload(sandbox, 'restart', 'r4.cfg', config_text('r4'))
        calls.clear()

        def vanishing_put(files):
            calls.append(1)
            if len(calls) == 1:
                (snapshot / 'configs' / 'r2.cfg').unlink()
            return original_put(files)

        with mock.patch.object(sandbox.history, 'put_files', side_effect=vanishing_put):
            vanished = sandbox.history.commit(baseline.snapshot_id, snapshot, 'vanished')
        detail = sandbox.history.get_version(baseline.snapshot_id, vanished['version_id'])
        self.assertNotIn('configs/r2.cfg', [entry['path'] for entry in detail['files']])

    def test_three_moving_attempts_answer_version_conflict(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('busy-commit')
        baseline = sandbox.poll('busy-commit')
        upload(sandbox, 'busy-commit', 'r2.cfg', CONFIG_R2)

        with moving_fingerprint(sandbox.state), self.assertRaises(VersionConflictError):
            sandbox.history.commit(baseline.snapshot_id, snapshot, 'never')

    def test_phase_two_restarts_when_gc_removed_a_manifest_object(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('gc-race')
        baseline = sandbox.poll('gc-race')
        upload(sandbox, 'gc-race', 'r2.cfg', CONFIG_R2)
        original_phase1 = sandbox.history._commit_phase1
        calls = []

        def phase1_then_gc(snapshot_dir):
            prepared = original_phase1(snapshot_dir)
            calls.append(1)
            if len(calls) == 1:
                sha256 = hashlib.sha256(CONFIG_R2.encode()).hexdigest()
                sandbox.history.object_path(sha256).unlink()
            return prepared

        with mock.patch.object(sandbox.history, '_commit_phase1', side_effect=phase1_then_gc):
            version = sandbox.history.commit(baseline.snapshot_id, snapshot, 'after gc')

        self.assertEqual(len(calls), 2)
        detail = sandbox.history.get_version(baseline.snapshot_id, version['version_id'])
        for entry in detail['files']:
            self.assertTrue(sandbox.history.object_path(entry['sha256']).exists())

    def test_commit_answers_conflict_while_an_upload_is_writing(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('upload-race')
        baseline = sandbox.poll('upload-race')
        observed = {}

        class ObservingStorage(FileStorage):
            def save(self, dst, buffer_size=16384):
                observed['poll'] = sandbox.poll('upload-race')
                try:
                    sandbox.history.commit(baseline.snapshot_id, snapshot, 'during upload')
                except VersionConflictError as exc:
                    observed['commit'] = exc
                return super().save(dst, buffer_size)

        storage = ObservingStorage(stream=io.BytesIO(CONFIG_R2.encode()), filename='r2.cfg', content_type='text/plain')
        sandbox.snapshot_service.upload_file('upload-race', storage)

        self.assertEqual(observed['poll'].content_hash, baseline.content_hash)
        self.assertIsInstance(observed['commit'], VersionConflictError)
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_root_removed_between_phase_one_and_phase_two(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('gone-commit')
        baseline = sandbox.poll('gone-commit')
        upload(sandbox, 'gone-commit', 'r2.cfg', CONFIG_R2)
        original_phase1 = sandbox.history._commit_phase1

        def phase1_then_remove(snapshot_dir):
            prepared = original_phase1(snapshot_dir)
            shutil.rmtree(snapshot)
            return prepared

        with mock.patch.object(sandbox.history, '_commit_phase1', side_effect=phase1_then_remove):
            with self.assertRaises(FileNotFoundError):
                sandbox.history.commit(baseline.snapshot_id, snapshot, 'gone')
        self.assertEqual(len(sandbox.versions(baseline.snapshot_id)), 1)

    def test_list_and_detail(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('listing')
        baseline = sandbox.poll('listing')
        snapshot_id = baseline.snapshot_id
        for index in (2, 3):
            upload(sandbox, 'listing', f'r{index}.cfg', config_text(f'r{index}'))
            sandbox.history.commit(snapshot_id, snapshot, f'v{index}')

        first_page = sandbox.history.list_versions(snapshot_id, limit=2, offset=0)
        second_page = sandbox.history.list_versions(snapshot_id, limit=2, offset=2)
        self.assertEqual(first_page['total'], 3)
        self.assertEqual([item['seq'] for item in first_page['items']], [3, 2])
        self.assertEqual([item['seq'] for item in second_page['items']], [1])

        detail = sandbox.history.get_version(snapshot_id, first_page['items'][0]['version_id'])
        self.assertEqual([entry['path'] for entry in detail['files']],
                         ['configs/r1.cfg', 'configs/r2.cfg', 'configs/r3.cfg'])
        self.assertEqual(detail['files'][0]['sha256'], hashlib.sha256(CONFIG_R1.encode()).hexdigest())

        other = sandbox.create_snapshot('other')
        other_state = sandbox.poll('other')
        with self.assertRaises(VersionNotFoundError):
            sandbox.history.get_version(other_state.snapshot_id, detail['version_id'])
        self.assertTrue(other.exists())


class ObjectStoreTest(SandboxTestCase):
    def test_object_store_is_scoped_by_the_database_identity(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('scoped')
        sandbox.poll('scoped')
        db_id = sandbox.history.db_id

        self.assertTrue(is_canonical_uuid4(db_id))
        self.assertEqual(sandbox.history.objects_dir, Path(sandbox.settings.SNAPSHOT_HISTORY_DIR) / db_id / 'objects')
        self.assertEqual(sandbox.start() and sandbox.history.db_id, db_id)
        other = self.make_sandbox()
        self.assertNotEqual(other.history.db_id, db_id)

    def test_dedup_refreshes_the_mtime_of_a_reused_object(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('dedup')
        baseline = sandbox.poll('dedup')
        r1_object = sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest())
        set_times(r1_object, seconds_ago=3600)
        old_mtime = r1_object.stat().st_mtime
        objects_before = sandbox.object_count()

        upload(sandbox, 'dedup', 'r2.cfg', CONFIG_R2)
        sandbox.history.commit(baseline.snapshot_id, snapshot, 'dedup')

        self.assertEqual(sandbox.object_count(), objects_before + 1)
        self.assertGreater(r1_object.stat().st_mtime, old_mtime + 1800)

    def test_put_object_installs_its_copy_for_a_truncated_or_vanished_object(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('install')
        source = snapshot / 'configs' / 'r1.cfg'
        sha256 = sandbox.history.put_object(source)
        object_path = sandbox.history.object_path(sha256)

        object_path.write_bytes(b'trunc')
        self.assertEqual(sandbox.history.put_object(source), sha256)
        self.assertEqual(object_path.read_text(encoding='utf-8'), CONFIG_R1)

        real_utime = os.utime

        def vanishing_utime(path, *args, **kwargs):
            if Path(path) == object_path:
                object_path.unlink()
                raise FileNotFoundError(path)
            return real_utime(path, *args, **kwargs)

        with mock.patch('services.snapshot_history_service.os.utime', side_effect=vanishing_utime):
            self.assertEqual(sandbox.history.put_object(source), sha256)
        self.assertEqual(object_path.read_text(encoding='utf-8'), CONFIG_R1)
        self.assertTrue(sandbox.history.verify_object(sha256))
        self.assertEqual(list(sandbox.history.tmp_dir.iterdir()), [])

    def test_commit_fsyncs_objects_and_store_directories_before_phase_two(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('fsync')
        baseline = sandbox.poll('fsync')
        upload(sandbox, 'fsync', 'r2.cfg', CONFIG_R2)
        events = []
        real_fsync = os.fsync
        original_fsync_directory = sandbox.history.fsync_directory
        original_phase2 = sandbox.history._commit_phase2

        def spy_fsync(fd):
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                events.append(('file', None))
            return real_fsync(fd)

        def spy_directory(path):
            events.append(('dir', Path(path)))
            return original_fsync_directory(path)

        def spy_phase2(*args, **kwargs):
            events.append(('phase2', None))
            return original_phase2(*args, **kwargs)

        with mock.patch('services.snapshot_history_service.os.fsync', side_effect=spy_fsync), \
                mock.patch.object(sandbox.history, 'fsync_directory', side_effect=spy_directory), \
                mock.patch.object(sandbox.history, '_commit_phase2', side_effect=spy_phase2):
            sandbox.history.commit(baseline.snapshot_id, snapshot, 'fsync')

        phase2_index = events.index(('phase2', None))
        before = events[:phase2_index]
        r1_dir = sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest()).parent
        r2_dir = sandbox.history.object_path(hashlib.sha256(CONFIG_R2.encode()).hexdigest()).parent
        self.assertEqual(len([event for event in before if event[0] == 'file']), 2)
        self.assertIn(('dir', r1_dir), before)
        self.assertIn(('dir', r2_dir), before)
        directories = [event[1] for event in before if event[0] == 'dir']
        self.assertEqual(
            directories[-3:],
            [sandbox.history.objects_dir, sandbox.history.store_dir, sandbox.history.history_dir],
        )


class GarbageCollectionTest(SandboxTestCase):
    def store_unreferenced(self, sandbox: VersioningSandbox, content: str, seconds_ago: float) -> Path:
        source = sandbox.root / f"loose-{hashlib.sha256(content.encode()).hexdigest()[:8]}"
        source.write_text(content, encoding='utf-8')
        object_path = sandbox.history.object_path(sandbox.history.put_object(source))
        set_times(object_path, seconds_ago=seconds_ago)
        return object_path

    def test_gc_moves_unreferenced_objects_past_grace_to_trash_and_empties_it(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('gc')
        sandbox.poll('gc')
        referenced = sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest())
        set_times(referenced, seconds_ago=7200)
        old = self.store_unreferenced(sandbox, 'old object\n', 7200)
        fresh = self.store_unreferenced(sandbox, 'fresh object\n', 0)
        lock_states = []
        real_rename = os.rename
        original_empty = sandbox.history._empty_trash

        def spy_rename(source, destination):
            lock_states.append(('rename', history_lock._is_owned()))
            return real_rename(source, destination)

        def spy_empty():
            lock_states.append(('unlink', history_lock._is_owned()))
            return original_empty()

        with mock.patch('services.snapshot_history_service.os.rename', side_effect=spy_rename), \
                mock.patch.object(sandbox.history, '_empty_trash', side_effect=spy_empty):
            collected = sandbox.history.gc_unreferenced()

        self.assertEqual(collected, 1)
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(referenced.exists())
        self.assertEqual(list(sandbox.history.trash_dir.iterdir()), [])
        self.assertEqual(lock_states, [('rename', True), ('unlink', False)])

        self.assertEqual(sandbox.history.gc_unreferenced(candidates=[fresh.name], skip_grace=True), 1)
        self.assertFalse(fresh.exists())

    def test_absent_candidate_counts_as_collected_and_drops_its_row(self):
        sandbox = self.make_sandbox()
        sha256 = hashlib.sha256(b'gone').hexdigest()
        with sandbox.db.get_db_session() as session:
            session.add(HistoryObject(sha256=sha256, size=4))

        self.assertEqual(sandbox.history.gc_unreferenced(), 1)
        self.assertEqual(sandbox.object_count(), 0)

    def test_startup_collects_aborted_commit_objects_and_empties_trash(self):
        sandbox = self.make_sandbox()
        aborted = self.store_unreferenced(sandbox, 'aborted commit\n', 7200)
        recent = self.store_unreferenced(sandbox, 'recent commit\n', 0)
        leftover = sandbox.history.trash_dir / 'leftover'
        write_file(leftover, 'credential text')

        sandbox.start()

        self.assertFalse(aborted.exists())
        self.assertTrue(recent.exists())
        self.assertFalse(leftover.exists())

    def test_gc_check_then_commit_then_gc_removal_keeps_referenced_objects(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('interleave')
        baseline = sandbox.poll('interleave')
        shared = self.store_unreferenced(sandbox, CONFIG_R2, 7200)
        write_file(snapshot / 'configs' / 'r2.cfg', CONFIG_R2)
        sandbox.state.set_marker(sandbox.state.id_key(baseline.snapshot_id))
        original_list = sandbox.history._list_store_objects
        versions = []

        def list_then_commit():
            listed = original_list()
            versions.append(sandbox.history.commit(baseline.snapshot_id, snapshot, 'race'))
            return listed

        with mock.patch.object(sandbox.history, '_list_store_objects', side_effect=list_then_commit):
            sandbox.history.gc_unreferenced()

        self.assertTrue(shared.exists())
        for version in sandbox.versions(baseline.snapshot_id):
            for entry in sandbox.history.get_version(baseline.snapshot_id, version['version_id'])['files']:
                self.assertTrue(sandbox.history.object_path(entry['sha256']).exists())
        self.assertEqual(versions[0]['kind'], 'manual')


class StartupObjectCheckTest(SandboxTestCase):
    def two_snapshots(self, sandbox: VersioningSandbox):
        sandbox.create_snapshot('alpha', {'configs/r1.cfg': CONFIG_R1})
        sandbox.create_snapshot('beta', {'configs/r2.cfg': CONFIG_R2})
        alpha = sandbox.poll('alpha')
        beta = sandbox.poll('beta')
        return alpha, beta

    def test_partially_missing_objects_mark_only_the_affected_snapshot(self):
        for damage in ('deleted', 'truncated'):
            with self.subTest(damage=damage):
                sandbox = self.make_sandbox()
                alpha, beta = self.two_snapshots(sandbox)
                alpha_object = sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest())
                beta_object = sandbox.history.object_path(hashlib.sha256(CONFIG_R2.encode()).hexdigest())
                if damage == 'deleted':
                    alpha_object.unlink()
                else:
                    alpha_object.write_bytes(b'x')

                with self.assertLogs(HISTORY_LOGGER, level='ERROR') as logs:
                    state = sandbox.start()

                self.assertEqual(len(logs.output), 1)
                self.assertIn(f"namespace={state.namespace}", logs.output[0])
                self.assertIn(f"snapshot_id={alpha.snapshot_id}", logs.output[0])
                self.assertIn("snapshot_name=alpha", logs.output[0])
                self.assertEqual(state.unavailable_reason(alpha.snapshot_id, 'alpha'), 'missing_objects')
                self.assertIsNone(state.unavailable_reason(beta.snapshot_id, 'beta'))
                self.assertIsNone(state.global_unavailable_reason())
                self.assertTrue(beta_object.exists())
                with self.assertRaises(VersioningUnavailableError) as raised:
                    sandbox.poll('alpha')
                self.assertEqual(raised.exception.reason, 'missing_objects')
                self.assertEqual(sandbox.poll('beta').content_hash, beta.content_hash)

    def test_absent_or_empty_store_is_a_global_storage_fault(self):
        for damage in ('absent', 'empty'):
            with self.subTest(damage=damage):
                sandbox = self.make_sandbox(RESULT_CACHE_ENABLED=True)
                self.two_snapshots(sandbox)
                objects_dir = sandbox.history.objects_dir
                shutil.rmtree(objects_dir)
                if damage == 'empty':
                    objects_dir.mkdir()
                sandbox.create_snapshot('newcomer')
                versions_before = sandbox.version_count()

                with self.assertLogs(HISTORY_LOGGER, level='ERROR') as logs:
                    state = sandbox.start()

                self.assertEqual(len(logs.output), 1)
                self.assertIn(str(objects_dir), logs.output[0])
                self.assertIn('HISTORY_ACCEPT_STORE_LOSS', logs.output[0])
                self.assertEqual(state.global_unavailable_reason(), 'storage')
                self.assertEqual(state.marked_snapshot_count('missing_objects'), 0)
                self.assertTrue(state.result_cache_enabled)
                with self.assertRaises(VersioningUnavailableError):
                    sandbox.poll('newcomer')
                self.assertEqual(sandbox.version_count(), versions_before)

    def test_accepting_the_store_loss_marks_snapshots_instead(self):
        sandbox = self.make_sandbox()
        alpha, beta = self.two_snapshots(sandbox)
        shutil.rmtree(sandbox.history.objects_dir)

        sandbox.settings.HISTORY_ACCEPT_STORE_LOSS = 'not-the-db-id'
        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            state = sandbox.start()
        self.assertEqual(state.global_unavailable_reason(), 'storage')
        self.assertTrue(any('does not match' in line for line in logs.output))

        sandbox.settings.HISTORY_ACCEPT_STORE_LOSS = sandbox.history.db_id
        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            state = sandbox.start()
        self.assertIsNone(state.global_unavailable_reason())
        self.assertEqual(state.unavailable_reason(alpha.snapshot_id, 'alpha'), 'missing_objects')
        self.assertEqual(state.unavailable_reason(beta.snapshot_id, 'beta'), 'missing_objects')
        warnings = [line for line in logs.output if 'loss guard is' in line]
        self.assertEqual(len(warnings), 1)
        self.assertIn('2 snapshots are marked missing_objects', warnings[0])

    def test_an_unreadable_object_store_is_a_storage_fault(self):
        for damage in ('not_a_directory', 'symlink_loop', 'permission_denied'):
            with self.subTest(damage=damage):
                sandbox = self.make_sandbox()
                self.two_snapshots(sandbox)
                fan_out = sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest()).parent
                real_stat = os.stat

                def denied_stat(path, *args, **kwargs):
                    if isinstance(path, (str, os.PathLike)) and Path(path).parent == fan_out:
                        raise PermissionError(errno.EACCES, 'Permission denied', str(path))
                    return real_stat(path, *args, **kwargs)

                if damage == 'permission_denied':
                    fault = mock.patch('os.stat', side_effect=denied_stat)
                else:
                    os.rename(fan_out, fan_out.with_name(f'{fan_out.name}-moved'))
                    if damage == 'not_a_directory':
                        fan_out.write_bytes(b'')
                    else:
                        os.symlink(fan_out.name, fan_out)
                    fault = nullcontext()

                with fault, self.assertLogs(HISTORY_LOGGER, level='ERROR') as logs:
                    state = sandbox.start()

                checks = [line for line in logs.output if 'object check' in line]
                self.assertEqual(len(checks), 1)
                self.assertIn('object check could not read the object store (', checks[0])
                self.assertEqual(state.global_unavailable_reason(), 'storage')

    def test_object_check_failures_are_database_faults_only_for_database_errors(self):
        cases = (
            (OperationalError('SELECT 1', {}, Exception('database is unavailable')), 'database',
             'could not query the database'),
            (sqlite3.OperationalError('database is locked'), 'database', 'could not query the database'),
            (RuntimeError('unexpected'), 'storage', 'failed'),
        )
        for failure, reason, wording in cases:
            with self.subTest(failure=f"{type(failure).__module__}.{type(failure).__name__}"):
                sandbox = self.make_sandbox()
                self.two_snapshots(sandbox)

                with mock.patch.object(history_module.SnapshotHistoryService, 'check_missing_objects',
                                       side_effect=failure), \
                        self.assertLogs(HISTORY_LOGGER, level='ERROR') as logs:
                    state = sandbox.start()

                self.assertEqual(len(logs.output), 1)
                self.assertIn(f"object check {wording} ({type(failure).__name__})", logs.output[0])
                self.assertNotIn(str(failure), logs.output[0])
                self.assertEqual(state.global_unavailable_reason(), reason)

    def test_zero_file_versions_never_count_as_missing(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('empty', {})
        sandbox.poll('empty')
        self.assertFalse(sandbox.history.objects_dir.exists())

        with self.assertNoLogs(HISTORY_LOGGER, level='ERROR'):
            state = sandbox.start()

        self.assertIsNone(state.global_unavailable_reason())
        self.assertEqual(sandbox.poll('empty').head['file_count'], 0)


class DatabaseSessionLogTest(SandboxTestCase):
    CONNECTION_TEXT = (
        'connection to server at "db.internal.example" (192.0.2.10), port 5432 failed: '
        'FATAL: password authentication failed for user "history_owner"'
    )

    def test_a_database_error_inside_a_session_logs_only_its_type(self):
        sandbox = self.make_sandbox()
        synthetic = OperationalError(
            "UPDATE snapshot_versions SET message = ? WHERE version_id = ?",
            ('bound-parameter-value', 'v1'),
            Exception(self.CONNECTION_TEXT),
        )

        def raise_synthetic(session):
            raise synthetic

        def insert_a_duplicate(session):
            session.execute(insert(HistoryMeta).values(id=1, db_id='bound-parameter-value', clear_counter=0))

        for statement in (raise_synthetic, insert_a_duplicate):
            with self.subTest(statement=statement.__name__):
                with self.assertLogs('database.session', level='ERROR') as logs, \
                        self.assertRaises((OperationalError, IntegrityError)) as raised:
                    with sandbox.db.get_db_session() as session:
                        statement(session)

                error_type = type(raised.exception).__name__
                self.assertEqual(logs.output, [f"ERROR:database.session:Database error, rolling back: {error_type}"])
                for fragment in ('UPDATE', 'INSERT', 'bound-parameter-value', 'db.internal.example', '5432',
                                 'history_owner'):
                    self.assertNotIn(fragment, logs.output[0])

    def test_a_session_rolls_back_for_any_exception(self):
        sandbox = self.make_sandbox()

        with self.assertLogs('database.session', level='ERROR') as logs, self.assertRaises(RuntimeError):
            with sandbox.db.get_db_session() as session:
                session.get(HistoryMeta, 1).clear_counter = 99
                session.flush()
                raise RuntimeError('text that is never logged')

        self.assertEqual(logs.output, ['ERROR:database.session:Database error, rolling back: RuntimeError'])
        with sandbox.db.get_db_session() as session:
            self.assertEqual(session.get(HistoryMeta, 1).clear_counter, 0)

    def test_a_lost_db_id_race_logs_no_error_and_reads_the_winner(self):
        sandbox = self.make_sandbox()
        winner = sandbox.history.db_id
        real_get = Session.get
        reads = []

        def read_before_the_winner_committed(session, entity, ident, *args, **kwargs):
            reads.append(entity)
            if entity is HistoryMeta and len(reads) == 1:
                return None
            return real_get(session, entity, ident, *args, **kwargs)

        with mock.patch.object(Session, 'get', autospec=True, side_effect=read_before_the_winner_committed), \
                self.assertNoLogs('database.session', level='ERROR'):
            db_id = sandbox.history._ensure_db_id()

        self.assertEqual(db_id, winner)
        self.assertEqual(reads, [HistoryMeta, HistoryMeta])
        with sandbox.db.get_db_session() as session:
            self.assertEqual(session.get(HistoryMeta, 1).db_id, winner)

    def test_errors_that_are_not_database_errors_are_raised_after_the_session_closes(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('meta')
        state = sandbox.poll('meta')
        with sandbox.db.get_db_session() as session:
            session.execute(delete(HistoryMeta))

        with self.assertNoLogs('database.session', level='ERROR'), self.assertRaises(StateStoreError):
            sandbox.state.record_cache_clear(state.snapshot_id)
        self.assertIsNone(sandbox.row(state.snapshot_id).clear_seq)

        sandbox.create_snapshot('unreadable')
        denied = PermissionError(errno.EACCES, 'Permission denied')
        with mock.patch.object(sandbox.history, 'objects_present', side_effect=denied), \
                self.assertNoLogs('database.session', level='ERROR'), \
                self.assertRaises(SnapshotEvaluationError) as raised:
            sandbox.poll('unreadable')
        self.assertIs(raised.exception.__cause__, denied)
        self.assertIsNone(sandbox.row(sandbox.snapshot_id('unreadable')))


def sha256_of(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


class HistoryDeletionTest(SandboxTestCase):
    def build_versions(self, sandbox: VersioningSandbox, name: str, count: int):
        snapshot = sandbox.create_snapshot(name)
        baseline = sandbox.poll(name)
        versions = [baseline.head]
        for index in range(2, count + 1):
            upload(sandbox, name, f'r{index}.cfg', config_text(f'{name}-r{index}'))
            versions.append(sandbox.history.commit(baseline.snapshot_id, snapshot, f'v{index}'))
        return snapshot, baseline.snapshot_id, versions

    def test_deletion_modes_move_head_and_never_reuse_seq(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'modes', 5)
        history = sandbox.history

        def ref(index):
            return {'version_id': versions[index]['version_id'], 'seq': index + 1}

        self.assertEqual(history.delete_versions(snapshot_id, snapshot, 'oldest', count=2),
                         {'deleted': 2, 'head': ref(4)})
        self.assertEqual([version['seq'] for version in sandbox.versions(snapshot_id)], [5, 4, 3])
        self.assertEqual(history.delete_versions(snapshot_id, snapshot, 'newest', count=1),
                         {'deleted': 1, 'head': ref(3)})
        moved = sandbox.poll('modes')
        self.assertEqual(moved.head['seq'], 4)
        self.assertTrue(moved.uncommitted)
        self.assertEqual(
            history.delete_versions(snapshot_id, snapshot, 'single', version_id=versions[2]['version_id']),
            {'deleted': 1, 'head': ref(3)},
        )
        with self.assertRaises(VersionNotFoundError):
            history.delete_versions(snapshot_id, snapshot, 'single', version_id=versions[2]['version_id'])
        self.assertEqual(history.delete_versions(snapshot_id, snapshot, 'newest', count=50),
                         {'deleted': 1, 'head': None})
        self.assertEqual(sandbox.versions(snapshot_id), [])
        self.assertEqual(sandbox.row(snapshot_id).next_seq, 6)

        upload(sandbox, 'modes', 'r6.cfg', config_text('modes-r6'))
        self.assertEqual(history.commit(snapshot_id, snapshot, 'after deletions')['seq'], 6)
        self.assertEqual(history.delete_versions(snapshot_id, snapshot, 'all'), {'deleted': 1, 'head': None})
        self.assertEqual(history.delete_versions(snapshot_id, snapshot, 'all'), {'deleted': 0, 'head': None})

    def test_head_deletion_rederives_uncommitted_and_pending_external(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'clean', 2)
        self.assertFalse(sandbox.poll('clean').uncommitted)

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=versions[1]['version_id'])

        moved = sandbox.poll('clean')
        self.assertEqual(moved.head['version_id'], versions[0]['version_id'])
        self.assertTrue(moved.uncommitted)
        self.assertFalse(moved.pending_external)

        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'pending', 2)
        upload(sandbox, 'pending', 'r3.cfg', config_text('pending-r3'))
        for name in ('r2.cfg', 'r3.cfg'):
            (snapshot / 'configs' / name).unlink()
        flagged = sandbox.poll('pending')
        self.assertTrue(flagged.pending_external)
        self.assertTrue(flagged.uncommitted)

        result = sandbox.history.delete_versions(snapshot_id, snapshot, 'newest', count=1)

        self.assertEqual(result['head'], {'version_id': versions[0]['version_id'], 'seq': 1})
        cleared = sandbox.poll('pending')
        self.assertFalse(cleared.pending_external)
        self.assertFalse(cleared.uncommitted)
        self.assertFalse(sandbox.row(snapshot_id).pending_external)

    def test_deletion_rederives_restored_from_against_the_new_head(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'restored', 3)
        key = sandbox.state.id_key(snapshot_id)
        source = {'version_id': versions[0]['version_id'], 'seq': 1}
        sandbox.state.begin_api_write(key)
        for name in ('r2.cfg', 'r3.cfg'):
            (snapshot / 'configs' / name).unlink()
        sandbox.state.end_api_write(key, snapshot, restored_from=source)
        self.assertEqual(sandbox.poll('restored').restored_from, source)

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=versions[1]['version_id'])
        self.assertEqual(sandbox.poll('restored').restored_from, source)

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=versions[2]['version_id'])
        back_at_source = sandbox.poll('restored')
        self.assertEqual(back_at_source.head['seq'], 1)
        self.assertIsNone(back_at_source.restored_from)
        self.assertFalse(back_at_source.uncommitted)
        row = sandbox.row(snapshot_id)
        self.assertIsNone(row.restored_from_version_id)
        self.assertIsNone(row.restored_from_seq)

        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'source-gone', 3)
        key = sandbox.state.id_key(snapshot_id)
        source = {'version_id': versions[1]['version_id'], 'seq': 2}
        sandbox.state.begin_api_write(key)
        (snapshot / 'configs' / 'r3.cfg').unlink()
        sandbox.state.end_api_write(key, snapshot, restored_from=source)

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=source['version_id'])

        orphaned_source = sandbox.poll('source-gone')
        self.assertEqual(orphaned_source.restored_from, {'version_id': None, 'seq': 2})
        self.assertTrue(orphaned_source.uncommitted)
        restore = sandbox.history.commit(snapshot_id, snapshot, 'restore after the source was deleted')
        self.assertEqual((restore['kind'], restore['restored_from']), ('restore', {'version_id': None, 'seq': 2}))
        self.assertEqual(restore['parent'], {'version_id': versions[2]['version_id'], 'seq': 3})

    def test_references_to_deleted_versions_keep_their_seq_and_reset_after_delete_all(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'refs', 2)
        key = sandbox.state.id_key(snapshot_id)
        first = {'version_id': versions[0]['version_id'], 'seq': 1}
        second = {'version_id': versions[1]['version_id'], 'seq': 2}
        sandbox.state.begin_api_write(key)
        (snapshot / 'configs' / 'r2.cfg').unlink()
        write_file(snapshot / 'configs' / 'r9.cfg', config_text('refs-r9'))
        sandbox.state.end_api_write(key, snapshot, restored_from=first)
        third = sandbox.history.commit(snapshot_id, snapshot, 'restore v1 with r9')
        self.assertEqual((third['kind'], third['parent'], third['restored_from']), ('restore', second, first))
        self.assertEqual(sandbox.poll('refs').head['restored_from'], first)

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=first['version_id'])

        listed = {item['seq']: item for item in sandbox.versions(snapshot_id)}
        self.assertEqual(listed[3]['restored_from'], {'version_id': None, 'seq': 1})
        self.assertEqual(listed[2]['parent'], {'version_id': None, 'seq': 1})
        self.assertEqual(sandbox.poll('refs').head['restored_from'], {'version_id': None, 'seq': 1})

        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=second['version_id'])

        self.assertEqual(sandbox.poll('refs').head['parent'], {'version_id': None, 'seq': 2})
        detail = sandbox.history.get_version(snapshot_id, third['version_id'])
        self.assertEqual((detail['parent'], detail['restored_from']),
                         ({'version_id': None, 'seq': 2}, {'version_id': None, 'seq': 1}))

        sandbox.history.delete_versions(snapshot_id, snapshot, 'all')

        emptied = sandbox.poll('refs')
        self.assertIsNone(emptied.head)
        self.assertTrue(emptied.uncommitted)
        write_file(snapshot / 'configs' / 'r10.cfg', config_text('refs-r10'))
        external = sandbox.poll('refs')
        self.assertTrue(external.pending_external)
        self.assertEqual(sandbox.versions(snapshot_id), [])

        fresh = sandbox.history.commit(snapshot_id, snapshot, 'after delete-all', expected_head=None)

        self.assertEqual((fresh['seq'], fresh['kind'], fresh['parent'], fresh['restored_from']),
                         (4, 'manual', None, None))
        after = sandbox.poll('refs')
        self.assertIsNone(after.restored_from)
        self.assertEqual((after.head['parent'], after.head['restored_from']), (None, None))
        self.assertFalse(after.pending_external)

    def test_marker_whose_restored_from_was_deleted_stores_a_null_id(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'marker-gone', 2)
        key = sandbox.state.id_key(snapshot_id)
        source = {'version_id': versions[0]['version_id'], 'seq': 1}
        sandbox.state.begin_api_write(key)
        write_file(snapshot / 'configs' / 'r9.cfg', config_text('marker-r9'))
        with mock.patch.object(sandbox.state, '_evaluate_locked', side_effect=failing_db_error()), \
                self.assertLogs(STATE_LOGGER, level='WARNING'):
            sandbox.state.end_api_write(key, snapshot, restored_from=source)
        sandbox.history.delete_versions(snapshot_id, snapshot, 'single', version_id=source['version_id'])

        with self.assertNoLogs('database.session', level='ERROR'):
            polled = sandbox.poll('marker-gone')
            version = sandbox.history.commit(snapshot_id, snapshot, 'after the source was deleted')

        self.assertEqual(polled.restored_from, {'version_id': None, 'seq': 1})
        self.assertEqual((version['kind'], version['restored_from']), ('restore', {'version_id': None, 'seq': 1}))

    def test_deletion_answers_conflict_while_an_api_write_is_in_progress(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'busy', 2)
        state = sandbox.state

        for key in (state.id_key(snapshot_id), state.dir_key(snapshot)):
            with self.subTest(key=key[0]):
                state.begin_api_write(key)
                try:
                    with self.assertRaises(VersionConflictError):
                        sandbox.history.delete_versions(snapshot_id, snapshot, 'all')
                    with self.assertRaises(VersionConflictError):
                        sandbox.history.delete_versions(
                            snapshot_id, snapshot, 'single', version_id=versions[0]['version_id'],
                        )
                finally:
                    state._finish_api_write(key)

        self.assertEqual(len(sandbox.versions(snapshot_id)), 2)

    def test_gc_after_deletion_honours_grace_and_references_of_any_namespace(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, _ = self.build_versions(sandbox, 'grace', 3)
        history = sandbox.history
        shared_sha = sha256_of(config_text('grace-r2'))
        fresh_sha = sha256_of(config_text('grace-r3'))
        with sandbox.db.get_db_session() as session:
            sibling = SnapshotVersion(
                version_id=str(uuid.uuid4()), snapshot_id=str(uuid.uuid4()), namespace='other-ns', seq=1,
                content_hash='0' * 64, kind='manual', message='sibling', file_count=1, total_bytes=1,
            )
            session.add(sibling)
            session.flush()
            session.add(SnapshotVersionFile(
                version_id=sibling.version_id, path='configs/r2.cfg', sha256=shared_sha, size=1,
            ))
        set_times(history.object_path(shared_sha), seconds_ago=7200)

        history.delete_versions(snapshot_id, snapshot, 'newest', count=2)

        self.assertTrue(history.object_path(shared_sha).exists())
        self.assertTrue(history.object_path(fresh_sha).exists())
        set_times(history.object_path(fresh_sha), seconds_ago=7200)
        history.gc_unreferenced()
        self.assertFalse(history.object_path(fresh_sha).exists())
        self.assertTrue(history.object_path(shared_sha).exists())
        self.assertTrue(history.object_path(sha256_of(CONFIG_R1)).exists())

    def test_deleting_a_working_file_keeps_it_in_earlier_versions(self):
        sandbox = self.make_sandbox(HISTORY_GC_GRACE_SECONDS=0)
        snapshot, snapshot_id, versions = self.build_versions(sandbox, 'keep-file', 2)
        removed_sha = sha256_of(config_text('keep-file-r2'))

        sandbox.snapshot_service.delete_snapshot_file('keep-file', 'r2.cfg')
        sandbox.history.commit(snapshot_id, snapshot, 'drop r2')
        sandbox.history.gc_unreferenced()

        detail = sandbox.history.get_version(snapshot_id, versions[1]['version_id'])
        self.assertIn(('configs/r2.cfg', removed_sha), [(entry['path'], entry['sha256']) for entry in detail['files']])
        self.assertTrue(sandbox.history.object_path(removed_sha).exists())

    def test_fk_restrict_protects_referenced_objects(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('restrict')
        sandbox.poll('restrict')

        with self.assertLogs('database.session', level='ERROR'), self.assertRaises(IntegrityError):
            with sandbox.db.get_db_session() as session:
                session.execute(delete(HistoryObject).where(HistoryObject.sha256 == sha256_of(CONFIG_R1)))

        self.assertEqual(sandbox.object_count(), 1)


class RestoreTest(SandboxTestCase):
    def build(self, sandbox: VersioningSandbox, name: str):
        snapshot = sandbox.create_snapshot(name)
        baseline = sandbox.poll(name)
        upload(sandbox, name, 'r2.cfg', CONFIG_R2)
        second = sandbox.history.commit(baseline.snapshot_id, snapshot, 'add r2')
        return snapshot, baseline.snapshot_id, baseline.head, second

    def test_begin_restore_write_reads_the_version_and_sets_the_flag(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, second = self.build(sandbox, 'begin')
        state = sandbox.state
        key = state.id_key(snapshot_id)

        manifest, paths, ref, noop = state.begin_restore_write(key, snapshot, first['version_id'], None)
        try:
            self.assertFalse(noop)
            self.assertEqual(ref, {'version_id': first['version_id'], 'seq': 1})
            self.assertEqual(manifest.files, (('configs/r1.cfg', sha256_of(CONFIG_R1), len(CONFIG_R1.encode('utf-8'))),))
            self.assertEqual(paths, ['configs/r1.cfg', 'configs/r2.cfg'])
            self.assertTrue(state.write_in_progress(key))
            for mode in ('single', 'all'):
                with self.subTest(mode=mode), self.assertRaises(VersionConflictError):
                    sandbox.history.delete_versions(snapshot_id, snapshot, mode, version_id=first['version_id'])
            with self.assertRaises(VersionConflictError):
                state.begin_restore_write(key, snapshot, first['version_id'], None)
        finally:
            state.end_api_write(key, snapshot)
        self.assertFalse(state.write_in_progress(key))

        _, _, head_ref, head_noop = state.begin_restore_write(key, snapshot, second['version_id'], None)
        self.assertTrue(head_noop)
        self.assertEqual(head_ref, {'version_id': second['version_id'], 'seq': 2})
        with self.assertRaises(VersionNotFoundError):
            state.begin_restore_write(key, snapshot, str(uuid.uuid4()), None)
        with self.assertRaises(VersionConflictError):
            state.begin_restore_write(key, snapshot, first['version_id'], '0' * 64)
        self.assertFalse(state.write_in_progress(key))
        self.assertEqual(len(sandbox.versions(snapshot_id)), 2)

    def test_restore_writes_outside_history_lock_and_records_restored_from(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, second = self.build(sandbox, 'written')
        history = sandbox.history
        observations = []
        original_write = history._write_version_tree

        def probe(*args):
            observations.append(history_lock._is_owned())
            return original_write(*args)

        with mock.patch.object(history, '_write_version_tree', side_effect=probe):
            result = history.restore(snapshot_id, snapshot, first['version_id'])

        self.assertEqual(observations, [False])
        self.assertEqual(result, {'requires_reinitialize': True,
                                  'restored_from': {'version_id': first['version_id'], 'seq': 1}})
        self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['r1.cfg'])
        row = sandbox.row(snapshot_id)
        self.assertEqual((row.restored_from_version_id, row.restored_from_seq), (first['version_id'], 1))
        self.assertEqual(row.content_hash, self.manifest_hash(sandbox, 'written'))
        self.assertEqual(row.head_version_id, second['version_id'])
        self.assertFalse(sandbox.state.write_in_progress(sandbox.state.id_key(snapshot_id)))
        self.assertEqual(len(sandbox.versions(snapshot_id)), 2)

    def test_tampered_manifest_paths_are_path_clashes_with_nothing_written(self):
        sandbox = self.make_sandbox()
        for index, tampered in enumerate(('../escape.cfg', '/absolute.cfg', 'configs//double.cfg',
                                          'configs/./dot.cfg', 'configs/../../escape.cfg')):
            with self.subTest(path=tampered):
                name = f'tampered-{index}'
                snapshot, snapshot_id, first, _ = self.build(sandbox, name)
                with sandbox.db.get_db_session() as session:
                    session.execute(
                        update(SnapshotVersionFile)
                        .where(SnapshotVersionFile.version_id == first['version_id'])
                        .values(path=tampered)
                    )

                with self.assertRaises(PathClashError) as raised:
                    sandbox.history.restore(snapshot_id, snapshot, first['version_id'])

                self.assertEqual(raised.exception.path, tampered)
                self.assertFalse((sandbox.snapshots_dir / 'escape.cfg').exists())
                self.assertFalse((sandbox.root / 'escape.cfg').exists())
                self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['r1.cfg', 'r2.cfg'])
                self.assertFalse(sandbox.state.write_in_progress(sandbox.state.id_key(snapshot_id)))
                self.assertIsNone(sandbox.row(snapshot_id).restored_from_seq)

    def test_resolver_value_error_is_a_path_clash(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, _ = self.build(sandbox, 'resolver')

        with mock.patch.object(sandbox.snapshot_service, '_resolve_snapshot_relative_path',
                               side_effect=ValueError('Artifact path escapes snapshot root')), \
                self.assertRaises(PathClashError) as raised:
            sandbox.history.restore(snapshot_id, snapshot, first['version_id'])

        self.assertEqual(raised.exception.path, 'configs/r1.cfg')
        self.assertTrue((snapshot / 'configs' / 'r2.cfg').exists())

    def test_corrupt_object_fails_before_the_first_write(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, _ = self.build(sandbox, 'corrupt')
        object_path = sandbox.history.object_path(sha256_of(CONFIG_R1))
        object_path.write_bytes(CONFIG_R1.replace('hostname', 'HOSTNAME').encode('utf-8'))
        stored_hash = sandbox.row(snapshot_id).content_hash

        with self.assertRaises(RestoreFailedError):
            sandbox.history.restore(snapshot_id, snapshot, first['version_id'])

        self.assertTrue((snapshot / 'configs' / 'r2.cfg').exists())
        self.assertEqual((snapshot / 'configs' / 'r1.cfg').read_text(encoding='utf-8'), CONFIG_R1)
        self.assertEqual(sandbox.row(snapshot_id).content_hash, stored_hash)
        self.assertFalse(sandbox.state.write_in_progress(sandbox.state.id_key(snapshot_id)))


def unified_diff_hunks(old_lines: list, new_lines: list) -> list:
    """Parse difflib.unified_diff output into the hunk structure of the diff/file route."""
    header = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$')
    hunks = []
    for line in list(difflib.unified_diff(old_lines, new_lines, n=3))[2:]:
        match = header.match(line.rstrip('\n'))
        if match:
            old_start, old_count, new_start, new_count = match.groups()
            hunks.append({
                'old_start': int(old_start), 'old_lines': 1 if old_count is None else int(old_count),
                'new_start': int(new_start), 'new_lines': 1 if new_count is None else int(new_count),
                'lines': [],
            })
        else:
            hunks[-1]['lines'].append({'type': line[0], 'text': line[1:].rstrip('\n')})
    return hunks


def cyclic_lines(count: int, order: int = 1, tokens: int = 110) -> list:
    """Lines cycling through tokens values, each value just under the matcher's popularity threshold."""
    return [f't{(index * order) % tokens:03d}\n' for index in range(count)]


def router_config_lines(interfaces: int) -> list:
    lines = ['version 17.3', 'hostname core-r1', '!']
    for number in range(interfaces):
        lines += [
            f'interface GigabitEthernet{number // 48}/0/{number % 48}',
            f' description access-port-{number:04d}',
            f' switchport access vlan {100 + number % 40}',
            ' switchport mode access',
            ' spanning-tree portfast',
            ' no shutdown',
            '!',
        ]
    lines.append('end')
    return [line + '\n' for line in lines]


def hunk_headers(hunks: list) -> list:
    return [(hunk['old_start'], hunk['old_lines'], hunk['new_start'], hunk['new_lines']) for hunk in hunks]


@contextmanager
def recorded_matchers():
    """Record every budgeted matcher a diff creates, including one that rejects its input up front."""
    created = []

    class Recording(history_module._BudgetedMatcher):
        def __init__(self, a, b, budget, strip):
            created.append(self)
            super().__init__(a, b, budget, strip)

    with mock.patch.object(history_module, '_BudgetedMatcher', Recording):
        yield created


class DiffTest(SandboxTestCase):
    def build(self, sandbox: VersioningSandbox, name: str):
        snapshot = sandbox.create_snapshot(name, {'configs/r1.cfg': CONFIG_R1})
        baseline = sandbox.poll(name)
        upload(sandbox, name, 'r1.cfg', CONFIG_R2)
        upload(sandbox, name, 'r3.cfg', config_text('r3'))
        second = sandbox.history.commit(baseline.snapshot_id, snapshot, 'v2')
        return snapshot, baseline.snapshot_id, baseline.head, second

    def test_hunks_follow_the_unified_diff_format(self):
        base = [f'line {index}\n' for index in range(1, 40)]
        pairs = {
            'replace-and-append': (base, base[:9] + ['line 10 changed\n'] + base[10:] + ['tail\n']),
            'delete-block': (base, base[:5] + base[15:]),
            'insert-at-start': (base, ['head\n'] + base),
            'changes-far-apart': (base, ['first\n'] + base[1:30] + ['middle\n'] + base[30:]),
            'added-file': ([], base[:4]),
            'removed-file': (base[:4], []),
            'missing-final-newline': (['a\n', 'b\n'], ['a\n', 'b']),
            'identical': (base, base),
        }
        for case, (old_lines, new_lines) in pairs.items():
            with self.subTest(case=case):
                hunks, truncated = history_module.build_diff_hunks(old_lines, new_lines, 2000)

                self.assertFalse(truncated)
                self.assertEqual(hunks, unified_diff_hunks(old_lines, new_lines))

    def test_hunks_are_cut_after_max_lines_with_consistent_counts(self):
        old_lines = [f'old {index}\n' for index in range(10)]
        new_lines = [f'new {index}\n' for index in range(10)]

        self.assertEqual(history_module.build_diff_hunks(old_lines, new_lines, 20),
                         (unified_diff_hunks(old_lines, new_lines), False))
        hunks, truncated = history_module.build_diff_hunks(old_lines, new_lines, 12)
        self.assertTrue(truncated)
        self.assertEqual(len(hunks), 1)
        self.assertEqual((hunks[0]['old_start'], hunks[0]['old_lines'], hunks[0]['new_start'], hunks[0]['new_lines']),
                         (1, 10, 1, 2))
        self.assertEqual([line['type'] for line in hunks[0]['lines']], ['-'] * 10 + ['+'] * 2)
        self.assertEqual(history_module.build_diff_hunks(old_lines, new_lines, 0), ([], True))

        base = [f'line {index}\n' for index in range(1, 40)]
        changed = ['first\n'] + base[1:30] + ['middle\n'] + base[30:]
        complete = unified_diff_hunks(base, changed)
        first_size = len(complete[0]['lines'])
        hunks, truncated = history_module.build_diff_hunks(base, changed, first_size)
        self.assertEqual((hunks, truncated), (complete[:1], True))

    def test_hunks_within_the_budget_are_identical_to_difflib(self):
        base = [f'line {index}\n' for index in range(1, 30)]
        config = router_config_lines(300)
        edited = list(config)
        for position in range(40, len(config) - 40, 97):
            edited[position] = edited[position].rstrip('\n') + ' changed\n'
        moved = config[:3] + config[73:-1] + config[3:73] + config[-1:]
        pairs = {
            'change-at-start': (base, ['first changed\n'] + base[1:]),
            'change-at-end': (base, base[:-1] + ['last changed\n']),
            'insert-at-start': (base, ['new first\n'] + base),
            'append-at-end': (base, base + ['new last\n']),
            'delete-first': (base, base[1:]),
            'delete-last': (base, base[:-1]),
            'old-side-empty': ([], base[:5]),
            'new-side-empty': (base[:5], []),
            'router-config-edits': (config, edited),
            'router-config-block-moved': (config, moved),
        }
        for case, (old_lines, new_lines) in pairs.items():
            with self.subTest(case=case):
                with recorded_matchers() as matchers:
                    hunks, truncated = history_module.build_diff_hunks(old_lines, new_lines, 10 ** 6)

                self.assertFalse(truncated)
                self.assertEqual(hunks, unified_diff_hunks(old_lines, new_lines))
                self.assertEqual([(matcher.budget, matcher.prefix, matcher.suffix) for matcher in matchers],
                                 [(history_module.DIFF_MATCH_BUDGET // 2, 0, 0)])

        stripped = history_module._BudgetedMatcher(config, moved, history_module.DIFF_MATCH_BUDGET, strip=True)
        self.assertNotEqual(list(stripped.get_grouped_opcodes(3)),
                            list(difflib.SequenceMatcher(None, config, moved).get_grouped_opcodes(3)))
        headers = {case: hunk_headers(history_module.build_diff_hunks(old, new, 10 ** 6)[0])
                   for case, (old, new) in pairs.items() if not case.startswith('router')}
        self.assertEqual(headers, {
            'change-at-start': [(1, 4, 1, 4)],
            'change-at-end': [(26, 4, 26, 4)],
            'insert-at-start': [(1, 3, 1, 4)],
            'append-at-end': [(27, 3, 27, 4)],
            'delete-first': [(1, 4, 1, 3)],
            'delete-last': [(26, 4, 26, 3)],
            'old-side-empty': [(0, 0, 1, 5)],
            'new-side-empty': [(1, 5, 0, 0)],
        })

    def test_stripped_matching_keeps_line_numbers_and_context(self):
        unique = [f'line {index}\n' for index in range(1, 30)]
        for case, (old_lines, new_lines) in {
            'change-at-start': (unique, ['x\n'] + unique[1:]),
            'change-at-end': (unique, unique[:-1] + ['x\n']),
            'change-in-the-middle': (unique, unique[:14] + ['x\n'] + unique[15:]),
            'old-side-empty': ([], unique),
            'new-side-empty': (unique, []),
            'identical': (unique, unique),
        }.items():
            with self.subTest(case=case):
                stripped = history_module._BudgetedMatcher(old_lines, new_lines, 10 ** 9, strip=True)
                self.assertEqual(list(stripped.get_grouped_opcodes(3)),
                                 list(difflib.SequenceMatcher(None, old_lines, new_lines).get_grouped_opcodes(3)))

        big = cyclic_lines(100_000)

        def text_of(index):
            return big[index].rstrip('\n')

        cases = {
            'change-at-start': (['x\n'] + big[1:], [(1, 4, 1, 4)],
                                [('-', text_of(0)), ('+', 'x')] + [(' ', text_of(index)) for index in (1, 2, 3)], True),
            'change-at-end': (big[:-1] + ['x\n'], [(99997, 4, 99997, 4)],
                              [(' ', text_of(index)) for index in (99996, 99997, 99998)]
                              + [('-', text_of(99999)), ('+', 'x')], True),
            'append-at-end': (big + ['x\n'], [(99998, 3, 99998, 4)],
                              [(' ', text_of(index)) for index in (99997, 99998, 99999)] + [('+', 'x')], False),
            'delete-first': (big[1:], [(1, 4, 1, 3)],
                             [('-', text_of(0))] + [(' ', text_of(index)) for index in (1, 2, 3)], False),
        }
        for case, (new_lines, headers, changes, matched) in cases.items():
            with self.subTest(case=case):
                with recorded_matchers() as matchers:
                    hunks, truncated = history_module.build_diff_hunks(big, new_lines, 2000)

                self.assertFalse(truncated)
                self.assertEqual(hunk_headers(hunks), headers)
                self.assertEqual([(line['type'], line['text']) for line in hunks[0]['lines']], changes)
                exact, stripped = matchers
                self.assertEqual((exact.work, exact.prefix + exact.suffix), (0, 0))
                self.assertGreater(stripped.prefix + stripped.suffix, 99_990)
                if matched:
                    self.assertLess(stripped.work, 10_000)
                else:
                    self.assertEqual(stripped.work, 0)

    def test_budget_stops_the_pathological_pair_within_the_budget(self):
        budget = history_module.DIFF_MATCH_BUDGET
        count = int((budget * 0.45 * 110) ** 0.5)
        old_lines, new_lines = cyclic_lines(count), cyclic_lines(count, order=7)
        self.assertLess(len(''.join(new_lines).encode('utf-8')), 512 * 1024)
        started = time.process_time()

        with recorded_matchers() as matchers, self.assertRaises(history_module._DiffBudgetExceededError):
            history_module.build_diff_hunks(old_lines, new_lines, 2000)

        elapsed = time.process_time() - started
        exact, stripped = matchers
        self.assertEqual(exact.budget, budget // 2)
        self.assertGreater(exact.work, 0)
        self.assertLessEqual(exact.work, exact.budget)
        self.assertEqual(stripped.budget, budget - exact.work)
        self.assertGreater(stripped.work, 0)
        self.assertLessEqual(exact.work + stripped.work, budget)
        self.assertLess(elapsed, 30)

    def test_hopeless_input_is_rejected_before_any_matching(self):
        old_lines, new_lines = cyclic_lines(100_000), cyclic_lines(100_000, order=7)
        self.assertLess(len(''.join(new_lines).encode('utf-8')), 512 * 1024)

        with self.assertRaises(history_module._DiffBudgetExceededError):
            history_module._BudgetedMatcher(old_lines, new_lines, history_module.DIFF_MATCH_BUDGET, strip=True)
        with recorded_matchers() as matchers, \
                mock.patch.object(difflib.SequenceMatcher, 'find_longest_match') as matching, \
                self.assertRaises(history_module._DiffBudgetExceededError):
            history_module.build_diff_hunks(old_lines, new_lines, 2000)

        matching.assert_not_called()
        self.assertEqual([matcher.work for matcher in matchers], [0, 0])

    def test_hunk_builds_share_two_slots_released_on_every_path(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, _ = self.build(sandbox, 'slots')
        write_file(snapshot / 'configs' / 'r1.cfg', config_text('slots-working'))
        history = sandbox.history
        slots = history_module.DIFF_JOB_SLOTS
        counters = {'active': 0, 'peak': 0, 'entered': 0}
        guard = threading.Lock()
        release = threading.Event()
        outcomes = []

        def blocking_job(*args):
            with guard:
                counters['active'] += 1
                counters['entered'] += 1
                counters['peak'] = max(counters['peak'], counters['active'])
            try:
                release.wait(10)
                return {'path': 'configs/r1.cfg', 'binary': False, 'too_large': False, 'truncated': False,
                        'hunks': []}
            finally:
                with guard:
                    counters['active'] -= 1

        def request():
            try:
                outcomes.append(history.diff_file(snapshot_id, snapshot, first['version_id'], 'working',
                                                  'configs/r1.cfg'))
            except Exception as exc:
                outcomes.append(exc)

        with mock.patch.object(history, '_build_file_diff', side_effect=blocking_job):
            workers = [threading.Thread(target=request, daemon=True) for _ in range(4)]
            for worker in workers:
                worker.start()
            deadline = time.monotonic() + 10
            while counters['entered'] < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            time.sleep(0.3)
            entered_while_saturated = counters['entered']
            lock_free = history_lock.acquire(timeout=5)
            if lock_free:
                history_lock.release()
            release.set()
            for worker in workers:
                worker.join(10)

        self.assertEqual(entered_while_saturated, 2)
        self.assertTrue(lock_free)
        self.assertEqual((counters['peak'], counters['entered'], counters['active']), (2, 4, 0))
        self.assertEqual([outcome['hunks'] for outcome in outcomes], [[], [], [], []])

        with mock.patch.object(history, '_build_file_diff', side_effect=RuntimeError('job failed')):
            for _ in range(3):
                with self.assertRaises(RuntimeError):
                    history.diff_file(snapshot_id, snapshot, first['version_id'], 'working', 'configs/r1.cfg')
        acquired = [slots.acquire(blocking=False) for _ in range(2)]
        for held in acquired:
            if held:
                slots.release()
        self.assertEqual(acquired, [True, True])

    def test_text_decoding_marks_nul_bytes_and_invalid_utf8_as_binary(self):
        self.assertEqual(history_module.decode_diff_text(None), [])
        self.assertEqual(history_module.decode_diff_text(b''), [])
        self.assertEqual(history_module.decode_diff_text('a\r\nb\nc'.encode('utf-8')), ['a\r\n', 'b\n', 'c'])
        self.assertEqual(history_module.decode_diff_text('é\n'.encode('utf-8')), ['é\n'])
        self.assertIsNone(history_module.decode_diff_text(b'a\x00b\n'))
        self.assertIsNone(history_module.decode_diff_text(b'caf\xe9\n'))

    def test_diff_hashes_reads_and_builds_hunks_outside_history_lock(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, second = self.build(sandbox, 'probe-diff')
        write_file(snapshot / 'configs' / 'r1.cfg', config_text('working'))
        history = sandbox.history
        observations = []
        inside_run_blocking = []
        original_hash = state_module.hash_files
        original_open = history.open_object
        original_working = history._read_working_side
        original_hunks = history_module.build_diff_hunks
        real_run_blocking = history_module.run_blocking

        def probe(label, original):
            def wrapper(*args, **kwargs):
                observations.append((label, history_lock._is_owned(), bool(inside_run_blocking)))
                return original(*args, **kwargs)
            return wrapper

        def probe_run_blocking(fn, *args, **kwargs):
            observations.append(('run_blocking:' + fn.__name__, history_lock._is_owned(), False))
            inside_run_blocking.append(fn)
            try:
                return real_run_blocking(fn, *args, **kwargs)
            finally:
                inside_run_blocking.pop()

        with mock.patch.object(state_module, 'hash_files', side_effect=probe('hash', original_hash)), \
                mock.patch.object(history, 'open_object', side_effect=probe('object', original_open)), \
                mock.patch.object(history, '_read_working_side', side_effect=probe('working', original_working)), \
                mock.patch.object(history_module, 'build_diff_hunks', side_effect=probe('hunks', original_hunks)), \
                mock.patch.object(history_module, 'run_blocking', side_effect=probe_run_blocking):
            summary = history.diff_summary(snapshot_id, snapshot, first['version_id'], 'working')
            working = history.diff_file(snapshot_id, snapshot, first['version_id'], 'working', 'configs/r1.cfg')
            between = history.diff_file(snapshot_id, snapshot, first['version_id'], second['version_id'],
                                        'configs/r1.cfg')

        self.assertEqual(summary['working_content_hash'], self.manifest_hash(sandbox, 'probe-diff'))
        self.assertTrue(working['hunks'])
        self.assertTrue(between['hunks'])
        labels = [label for label, _, _ in observations]
        self.assertIn('hash', labels)
        self.assertEqual(labels.count('run_blocking:_build_file_diff'), 2)
        self.assertEqual(labels.count('hunks'), 2)
        self.assertEqual(labels.count('object'), 3)
        self.assertEqual(labels.count('working'), 1)
        self.assertFalse(any(owned for _, owned, _ in observations))
        for label, _, inside in observations:
            if label in ('object', 'working', 'hunks'):
                self.assertTrue(inside, label)

    def test_tampered_manifest_paths_never_read_outside_the_snapshot(self):
        sandbox = self.make_sandbox()
        write_file(sandbox.snapshots_dir / 'escape.cfg', 'outside secret\n')
        write_file(sandbox.root / 'escape.cfg', 'outside secret\n')
        for index, tampered in enumerate(('../escape.cfg', 'configs/../../escape.cfg', '/escape.cfg',
                                          'configs//r1.cfg', 'configs/./r1.cfg')):
            with self.subTest(path=tampered):
                name = f'tampered-diff-{index}'
                snapshot, snapshot_id, first, _ = self.build(sandbox, name)
                with sandbox.db.get_db_session() as session:
                    session.execute(
                        update(SnapshotVersionFile)
                        .where(SnapshotVersionFile.version_id == first['version_id'])
                        .values(path=tampered)
                    )

                data = sandbox.history.diff_file(snapshot_id, snapshot, first['version_id'], 'working', tampered)

                self.assertEqual([(line['type'], line['text']) for hunk in data['hunks'] for line in hunk['lines']],
                                 [('-', line) for line in CONFIG_R1.splitlines()])

    def test_working_file_growing_after_its_size_check_is_too_large(self):
        sandbox = self.make_sandbox(SNAPSHOT_DIFF_MAX_BYTES=64)
        snapshot = sandbox.create_snapshot('growing', {'configs/r1.cfg': 'small\n'})
        state = sandbox.poll('growing')
        target = snapshot / 'configs' / 'r1.cfg'
        real_fstat = os.fstat
        calls = []

        def growing_fstat(fd):
            result = real_fstat(fd)
            calls.append(fd)
            if len(calls) == 2:
                with open(target, 'ab') as handle:
                    handle.write(b'g' * 100)
            return result

        with mock.patch('services.snapshot_history_service.os.fstat', side_effect=growing_fstat):
            data = sandbox.history.diff_file(state.snapshot_id, snapshot, state.head['version_id'], 'working',
                                             'configs/r1.cfg')

        self.assertEqual(len(calls), 2)
        self.assertEqual((data['too_large'], data['binary'], data['hunks']), (True, False, []))

    def test_diff_reads_no_rows_and_runs_no_evaluation(self):
        sandbox = self.make_sandbox()
        snapshot, snapshot_id, first, _ = self.build(sandbox, 'read-only')
        write_file(snapshot / 'configs' / 'r9.cfg', config_text('r9'))
        stored = sandbox.row(snapshot_id)
        state = sandbox.state

        with mock.patch.object(state, '_evaluate', wraps=state._evaluate) as evaluate:
            summary = sandbox.history.diff_summary(snapshot_id, snapshot, first['version_id'], 'working')
            sandbox.history.diff_file(snapshot_id, snapshot, first['version_id'], 'working', 'configs/r9.cfg')

        evaluate.assert_not_called()
        self.assertIn(('configs/r9.cfg', 'added'), [(entry['path'], entry['status']) for entry in summary['files']])
        after = sandbox.row(snapshot_id)
        self.assertEqual((after.content_hash, after.stat_fingerprint, after.head_version_id),
                         (stored.content_hash, stored.stat_fingerprint, stored.head_version_id))
        self.assertEqual(len(sandbox.versions(snapshot_id)), 2)


class OrphanScanTest(SandboxTestCase):
    def two_snapshots(self, sandbox: VersioningSandbox):
        alpha = sandbox.create_snapshot('alpha', {'configs/r1.cfg': config_text('alpha')})
        sandbox.create_snapshot('beta', {'configs/r1.cfg': config_text('beta')})
        return alpha, sandbox.poll('alpha').snapshot_id, sandbox.poll('beta').snapshot_id

    def namespace_row(self, sandbox: VersioningSandbox):
        with sandbox.db.get_db_session() as session:
            return session.get(HistoryNamespace, sandbox.state.namespace)

    def test_scan_sets_and_clears_missing_since_within_the_current_namespace(self):
        sandbox = self.make_sandbox()
        alpha, alpha_id, beta_id = self.two_snapshots(sandbox)
        with sandbox.db.get_db_session() as session:
            session.add(SnapshotStateRow(
                namespace='other-ns', snapshot_id=alpha_id, snapshot_name='elsewhere', next_seq=1,
                pending_external=False,
            ))
        away = sandbox.root / 'alpha-away'
        shutil.move(str(alpha), str(away))

        result = sandbox.history.scan_orphans()

        self.assertEqual((result['marked'], result['renamed'], result['cleared']), (1, 0, 0))
        self.assertIsNotNone(sandbox.row(alpha_id).missing_since)
        self.assertIsNone(sandbox.row(beta_id).missing_since)
        self.assertIsNone(sandbox.row(alpha_id, namespace='other-ns').missing_since)

        shutil.move(str(away), str(alpha))
        self.assertEqual(sandbox.history.scan_orphans()['cleared'], 1)
        self.assertIsNone(sandbox.row(alpha_id).missing_since)

    def test_moved_directory_is_renamed_without_missing_since(self):
        sandbox = self.make_sandbox()
        alpha, alpha_id, _ = self.two_snapshots(sandbox)
        alpha.rename(sandbox.snapshots_dir / 'alpha-moved')

        result = sandbox.history.scan_orphans()

        self.assertEqual((result['renamed'], result['marked']), (1, 0))
        row = sandbox.row(alpha_id)
        self.assertEqual(row.snapshot_name, 'alpha-moved')
        self.assertIsNone(row.missing_since)

    def test_unreadable_sidecar_holds_its_rows_and_a_copy_gets_a_fresh_id(self):
        sandbox = self.make_sandbox()
        origin = sandbox.create_snapshot('origin')
        origin_id = sandbox.poll('origin').snapshot_id
        shutil.copytree(origin, sandbox.snapshots_dir / 'clone')
        sidecar_path(origin).write_text('{corrupt', encoding='utf-8')

        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            result = sandbox.history.scan_orphans()

        self.assertEqual(len([line for line in logs.output if 'cannot be read or parsed' in line]), 1)
        self.assertEqual((result['renamed'], result['marked']), (0, 0))
        self.assertEqual(sandbox.row(origin_id).snapshot_name, 'origin')
        self.assertIsNone(sandbox.row(origin_id).missing_since)
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            clone_id = sandbox.state.resolve_snapshot_identity(sandbox.snapshots_dir / 'clone')
        self.assertNotEqual(clone_id, origin_id)

        with sandbox.db.get_db_session() as session:
            session.execute(
                update(SnapshotStateRow).where(SnapshotStateRow.snapshot_id == origin_id)
                .values(missing_since=datetime.now(timezone.utc) - timedelta(days=3))
            )
        with self.assertLogs(HISTORY_LOGGER, level='WARNING'):
            purge = sandbox.history.purge_orphans(0)

        self.assertEqual(purge, {'purged': 0, 'last_seen_at': None})
        self.assertIsNotNone(sandbox.row(origin_id))
        self.assertEqual(len(sandbox.versions(origin_id)), 1)

    def test_row_renamed_between_the_two_holds_is_left_for_the_next_run(self):
        sandbox = self.make_sandbox()
        alpha, alpha_id, _ = self.two_snapshots(sandbox)
        shutil.rmtree(alpha)
        original_view = sandbox.history.read_store_view

        def view_then_rename():
            view = original_view()
            with sandbox.db.get_db_session() as session:
                session.execute(
                    update(SnapshotStateRow).where(SnapshotStateRow.snapshot_id == alpha_id)
                    .values(snapshot_name='alpha-renamed')
                )
            return view

        with mock.patch.object(sandbox.history, 'read_store_view', side_effect=view_then_rename):
            first = sandbox.history.scan_orphans()

        self.assertEqual(first['marked'], 0)
        self.assertIsNone(sandbox.row(alpha_id).missing_since)
        second = sandbox.history.scan_orphans()
        self.assertEqual(second['marked'], 1)
        self.assertEqual(sandbox.row(alpha_id).snapshot_name, 'alpha-renamed')
        self.assertIsNotNone(sandbox.row(alpha_id).missing_since)

    def test_unmounted_store_is_skipped_while_the_namespace_row_is_upserted(self):
        sandbox = self.make_sandbox()
        alpha = sandbox.create_snapshot('alpha')
        alpha_id = sandbox.poll('alpha').snapshot_id
        shutil.rmtree(alpha)
        before = self.namespace_row(sandbox)

        sandbox.start()

        after_start = self.namespace_row(sandbox)
        self.assertIsNone(sandbox.row(alpha_id).missing_since)
        self.assertEqual(after_start.first_seen_at, before.first_seen_at)
        self.assertGreater(after_start.last_seen_at, before.last_seen_at)

        sandbox.history.run_periodic_tasks()

        self.assertGreater(self.namespace_row(sandbox).last_seen_at, after_start.last_seen_at)
        self.assertIsNone(sandbox.row(alpha_id).missing_since)

    def test_startup_lists_the_namespace_orphans_in_one_warning(self):
        sandbox = self.make_sandbox()
        alpha, alpha_id, beta_id = self.two_snapshots(sandbox)
        shutil.rmtree(alpha)

        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            sandbox.start()

        orphan_lines = [line for line in logs.output if 'orphaned' in line]
        self.assertEqual(len(orphan_lines), 1)
        self.assertIn(alpha_id, orphan_lines[0])
        self.assertNotIn(beta_id, orphan_lines[0])
        self.assertIsNotNone(sandbox.row(alpha_id).missing_since)


class NamespaceBookkeepingTest(SandboxTestCase):
    def namespace_rows(self, sandbox: VersioningSandbox) -> dict:
        with sandbox.db.get_db_session() as session:
            return {row.namespace: row for row in session.execute(select(HistoryNamespace)).scalars()}

    def test_startup_records_first_and_last_seen(self):
        sandbox = self.make_sandbox()
        first = self.namespace_rows(sandbox)[sandbox.state.namespace]
        self.assertEqual(first.first_seen_at, first.last_seen_at)

        sandbox.start()

        rows = self.namespace_rows(sandbox)
        self.assertEqual(list(rows), [sandbox.state.namespace])
        self.assertEqual(rows[sandbox.state.namespace].first_seen_at, first.first_seen_at)
        self.assertGreater(rows[sandbox.state.namespace].last_seen_at, first.last_seen_at)

    def test_first_startup_under_a_new_namespace_warns_once_without_names(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('secret-alpha')
        sandbox.poll('secret-alpha')
        marker_namespace = sandbox.state.namespace

        sandbox.settings.DEPLOYMENT_ID = 'explicit'
        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            sandbox.start()

        warnings = [line for line in logs.output if 'other namespaces' in line]
        self.assertEqual(len(warnings), 1)
        self.assertIn(f'namespace={marker_namespace}', warnings[0])
        self.assertIn('rows=1', warnings[0])
        self.assertIn('last_seen_at=20', warnings[0])
        self.assertIn('DEPLOYMENT_ID', warnings[0])
        self.assertNotIn('secret-alpha', warnings[0])

        with self.assertNoLogs(HISTORY_LOGGER, level='WARNING'):
            sandbox.start()

    def test_first_startup_without_history_elsewhere_logs_no_warning(self):
        with self.assertNoLogs(HISTORY_LOGGER, level='WARNING'):
            sandbox = self.make_sandbox()
        sandbox.create_snapshot('fresh')
        (sandbox.snapshots_dir / state_module.STORE_MARKER_FILENAME).unlink()

        with self.assertNoLogs(HISTORY_LOGGER, level='WARNING'):
            sandbox.start()

        self.assertEqual(len(self.namespace_rows(sandbox)), 2)


class PeriodicMaintenanceTest(SandboxTestCase):
    def make_due(self, sandbox: VersioningSandbox) -> None:
        sandbox.history._last_periodic_run -= history_module.PERIODIC_MAINTENANCE_INTERVAL_SECONDS + 1

    def test_trigger_runs_once_per_interval(self):
        sandbox = self.make_sandbox()
        self.assertFalse(sandbox.history.schedule_periodic_gc())
        self.make_due(sandbox)

        with mock.patch.object(sandbox.history, 'run_periodic_tasks') as tasks:
            self.assertTrue(sandbox.history.schedule_periodic_gc())
            sandbox.history.periodic_worker.join(10)
            self.assertFalse(sandbox.history.schedule_periodic_gc())

        tasks.assert_called_once()
        self.assertIsNot(tasks.call_args.args[0], sandbox.db)

    def test_gevent_spawns_a_greenlet_on_the_shared_engine(self):
        sandbox = self.make_sandbox()
        self.make_due(sandbox)
        spawned = []

        def fake_spawn(function, **kwargs):
            spawned.append((function, kwargs))
            return 'greenlet'

        with mock.patch.object(history_module, '_gevent_threading_patched', return_value=True), \
                mock.patch('gevent.spawn', side_effect=fake_spawn), \
                mock.patch.object(sandbox.history, 'run_periodic_tasks') as tasks:
            self.assertTrue(sandbox.history.schedule_periodic_gc())
            self.assertEqual(sandbox.history.periodic_worker, 'greenlet')
            function, kwargs = spawned[0]
            function(**kwargs)

        tasks.assert_called_once_with(sandbox.db)

    def test_in_memory_sqlite_runs_inline(self):
        sandbox = self.make_sandbox(with_database=False)
        sandbox.db = DatabaseManager('sqlite://')
        sandbox.db.create_all()
        sandbox.start()
        alpha = sandbox.create_snapshot('alpha')
        sandbox.create_snapshot('beta')
        alpha_id = sandbox.poll('alpha').snapshot_id
        shutil.rmtree(alpha)
        self.make_due(sandbox)

        self.assertTrue(sandbox.history.schedule_periodic_gc())

        self.assertIsNone(sandbox.history.periodic_worker)
        self.assertIsNotNone(sandbox.row(alpha_id).missing_since)

    def test_in_memory_sqlite_detection(self):
        for url, expected in (
            ('sqlite://', True),
            ('sqlite:///:memory:', True),
            ('sqlite:///file::memory:?cache=shared', True),
            ('sqlite:////tmp/topologix.db', False),
            ('postgresql://user@localhost/topologix', False),
        ):
            with self.subTest(url=url):
                self.assertEqual(history_module.is_in_memory_sqlite(url), expected)


class UnavailableVersioningTest(SandboxTestCase):
    def test_database_unavailable_reports_database(self):
        sandbox = self.make_sandbox(with_database=False)
        sandbox.create_snapshot('no-db')

        with self.assertRaises(VersioningUnavailableError) as raised:
            sandbox.poll('no-db')
        self.assertEqual(raised.exception.reason, 'database')

    def test_detached_service_class_is_plain(self):
        service = SnapshotService()
        self.assertIsNone(service._state_service)


class ResultCacheReferenceTest(SandboxTestCase):
    """History deletion evictions and maintenance sweeps of the result cache."""

    BODY = b'{"data":[],"message":"Success","status":"success"}'

    def make_cache(self, sandbox: VersioningSandbox, clock=None) -> ResultCache:
        cache = ResultCache(
            sandbox.settings.RESULT_CACHE_DIR, max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=900,
            build_id='build', pybatfish_version='pyb', schema_version=1,
            clock=clock or (lambda: 1_000.0),
        )
        sandbox.history.attach_result_cache(cache)
        return cache

    def store(self, cache: ResultCache, content_hash: str, scope: str = '', db_id: str | None = None,
              sandbox: VersioningSandbox | None = None) -> None:
        cache.store(content_hash, 'get_nodes', scope, self.BODY, db_id or sandbox.history.db_id, None,
                    batfish_version='bf')

    def present(self, cache: ResultCache, content_hash: str, scope: str = '', db_id: str | None = None) -> bool:
        return cache.lookup(content_hash, 'get_nodes', scope, db_id, None, batfish_version='bf') is not None

    def entry_files(self, sandbox: VersioningSandbox) -> set:
        root = Path(sandbox.settings.RESULT_CACHE_DIR)
        return {path.parent.name for path in root.glob('*/*.json.gz')}

    def test_history_deletion_evicts_unreferenced_own_scope_entries(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('alpha', {'configs/r1.cfg': config_text('a1')})
        alpha_id = sandbox.poll('alpha').snapshot_id
        sandbox.create_snapshot('beta', {'configs/r1.cfg': config_text('a1')})
        sandbox.poll('beta')
        sandbox.create_snapshot('gamma', {'configs/r1.cfg': config_text('g1')})
        sandbox.poll('gamma')
        cache = self.make_cache(sandbox)
        h1 = self.manifest_hash(sandbox, 'alpha')
        self.store(cache, h1, sandbox=sandbox)

        upload(sandbox, 'alpha', 'r1.cfg', config_text('viewed-once'))
        viewed_once = sandbox.poll('alpha').content_hash
        self.store(cache, viewed_once, sandbox=sandbox)
        upload(sandbox, 'alpha', 'r1.cfg', config_text('viewed-shared'))
        viewed_shared = sandbox.poll('alpha').content_hash
        self.store(cache, viewed_shared, sandbox=sandbox)
        upload(sandbox, 'gamma', 'r1.cfg', config_text('viewed-shared'))
        self.assertEqual(sandbox.poll('gamma').content_hash, viewed_shared)
        upload(sandbox, 'alpha', 'r1.cfg', config_text('a3'))
        sandbox.history.commit(alpha_id, sandbox.snapshots_dir / 'alpha', 'v2')
        h3 = sandbox.poll('alpha').content_hash
        self.store(cache, h3, sandbox=sandbox)
        upload(sandbox, 'alpha', 'r1.cfg', config_text('a4'))
        h4 = sandbox.poll('alpha').content_hash
        self.store(cache, h4, sandbox=sandbox)
        baseline = [v for v in sandbox.versions(alpha_id) if v['kind'] == 'baseline'][0]

        sandbox.history.delete_versions(
            alpha_id, sandbox.snapshots_dir / 'alpha', 'single', version_id=baseline['version_id'], owner_scope='',
        )

        self.assertFalse(self.present(cache, viewed_once, db_id=sandbox.history.db_id))
        for kept in (h1, viewed_shared, h3, h4):
            self.assertTrue(self.present(cache, kept, db_id=sandbox.history.db_id), kept)

        sandbox.history.delete_versions(alpha_id, sandbox.snapshots_dir / 'alpha', 'all', owner_scope='')

        self.assertFalse(self.present(cache, h3, db_id=sandbox.history.db_id))
        for kept in (h1, viewed_shared, h4):
            self.assertTrue(self.present(cache, kept, db_id=sandbox.history.db_id), kept)

    def test_history_deletion_under_auth_on_keeps_other_scopes(self):
        sandbox = self.make_sandbox(AUTH_ENABLED=True)
        sandbox.snapshot_service.create_snapshot('owned', owner_user_id=1, auth_enabled=True)
        write_file(sandbox.snapshots_dir / 'owned' / 'configs' / 'r1.cfg', config_text('owned'))
        context = {'requester_user_id': 1, 'auth_enabled': True}
        owned_id = sandbox.state.get_state('owned', context).snapshot_id
        cache = self.make_cache(sandbox)
        db_id = sandbox.history.db_id
        stale = hashlib.sha256(b'stale state').hexdigest()
        scope_a = owner_scope_for(True, db_id, 1)
        scope_b = owner_scope_for(True, db_id, 2)
        self.store(cache, stale, scope_a, sandbox=sandbox)
        self.store(cache, stale, scope_b, sandbox=sandbox)

        sandbox.history.delete_versions(owned_id, sandbox.snapshots_dir / 'owned', 'all', owner_scope=scope_a)

        self.assertFalse(self.present(cache, stale, scope_a, db_id))
        self.assertTrue(self.present(cache, stale, scope_b, db_id))

    def test_startup_and_hourly_runs_sweep_unreferenced_groups_of_the_current_db_id(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('alpha', {'configs/r1.cfg': config_text('alpha')})
        sandbox.poll('alpha')
        referenced = self.manifest_hash(sandbox, 'alpha')
        db_id = sandbox.history.db_id
        other_db = str(uuid.uuid4())
        clock = [1_000.0]
        writer = self.make_cache(sandbox, clock=lambda: clock[0])
        orphan = hashlib.sha256(b'orphan').hexdigest()
        foreign = hashlib.sha256(b'foreign').hexdigest()
        protected = hashlib.sha256(b'protected').hexdigest()
        for content_hash in (referenced, orphan, protected):
            self.store(writer, content_hash, sandbox=sandbox)
        self.store(writer, foreign, db_id=other_db)

        sweeper = self.make_cache(sandbox, clock=lambda: clock[0])
        clock[0] = 100_000.0
        sandbox.history.run_startup_tasks()

        self.assertEqual(self.entry_files(sandbox), {referenced, foreign})

        cache = self.make_cache(sandbox, clock=lambda: clock[0])
        for content_hash in (orphan, protected):
            self.store(cache, content_hash, sandbox=sandbox)
        clock[0] = 200_000.0
        self.assertTrue(self.present(cache, protected, db_id=db_id))
        sandbox.history.run_periodic_tasks()

        self.assertEqual(self.entry_files(sandbox), {referenced, foreign, protected})
        self.assertEqual(sweeper.stats()['entries'], 2)

    def test_hourly_sweep_runs_on_the_given_database_manager(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('alpha')
        sandbox.poll('alpha')
        cache = self.make_cache(sandbox, clock=lambda: 50_000.0)
        manager = sandbox.db.create_null_pool_manager()
        self.addCleanup(manager.engine.dispose)

        with mock.patch.object(cache, 'sweep_unreferenced', wraps=cache.sweep_unreferenced) as sweep, \
                mock.patch.object(sandbox.history, 'referenced_hashes_by_scope',
                                  wraps=sandbox.history.referenced_hashes_by_scope) as references:
            sandbox.history.run_periodic_tasks(manager)

        sweep.assert_called_once()
        self.assertIs(references.call_args.args[0], manager)

    def test_admin_purges_sweep_entries_of_purged_history(self):
        sandbox = self.make_sandbox()
        alpha = sandbox.create_snapshot('alpha', {'configs/r1.cfg': config_text('alpha')})
        alpha_id = sandbox.poll('alpha').snapshot_id
        sandbox.create_snapshot('beta', {'configs/r1.cfg': config_text('beta')})
        sandbox.poll('beta')
        alpha_hash = self.manifest_hash(sandbox, 'alpha')
        detached = hashlib.sha256(b'detached namespace').hexdigest()
        with sandbox.db.get_db_session() as session:
            session.add(SnapshotStateRow(
                namespace='detached-ns', snapshot_id=str(uuid.uuid4()), snapshot_name='elsewhere', next_seq=1,
                pending_external=False, content_hash=detached,
            ))
        cache = self.make_cache(sandbox, clock=lambda: 50_000.0)
        writer = ResultCache(
            sandbox.settings.RESULT_CACHE_DIR, max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=900,
            build_id='build', pybatfish_version='pyb', schema_version=1, clock=lambda: 1_000.0,
        )
        for content_hash in (alpha_hash, detached):
            self.store(writer, content_hash, sandbox=sandbox)

        shutil.rmtree(alpha)
        sandbox.history.scan_orphans()
        with sandbox.db.get_db_session() as session:
            session.execute(
                update(SnapshotStateRow).where(SnapshotStateRow.snapshot_id == alpha_id)
                .values(missing_since=datetime.now(timezone.utc) - timedelta(days=3))
            )
        sandbox.history.run_periodic_tasks()
        self.assertEqual(self.entry_files(sandbox), {alpha_hash, detached})

        self.assertEqual(sandbox.history.purge_orphans(1)['purged'], 1)
        self.assertEqual(self.entry_files(sandbox), {detached})

        sandbox.history.purge_namespace('detached-ns')
        self.assertEqual(self.entry_files(sandbox), set())
        self.assertEqual(cache.stats()['entries'], 0)

    def test_auth_on_sweep_judges_each_owner_scope_by_its_own_rows(self):
        sandbox = self.make_sandbox(AUTH_ENABLED=True)
        sandbox.snapshot_service.create_snapshot('owned', owner_user_id=1, auth_enabled=True)
        write_file(sandbox.snapshots_dir / 'owned' / 'configs' / 'r1.cfg', config_text('owned'))
        sandbox.state.get_state('owned', {'requester_user_id': 1, 'auth_enabled': True})
        owned_hash = self.manifest_hash(sandbox, 'owned')
        other_namespace_hash = hashlib.sha256(b'other namespace').hexdigest()
        with sandbox.db.get_db_session() as session:
            session.add(SnapshotStateRow(
                namespace='sibling-ns', snapshot_id=str(uuid.uuid4()), snapshot_name='owned', next_seq=1,
                pending_external=False, content_hash=other_namespace_hash,
            ))
        db_id = sandbox.history.db_id
        scope_a = owner_scope_for(True, db_id, 1)
        scope_b = owner_scope_for(True, db_id, 2)
        writer = self.make_cache(sandbox)
        self.store(writer, owned_hash, scope_a, sandbox=sandbox)
        self.store(writer, owned_hash, scope_b, sandbox=sandbox)
        self.store(writer, other_namespace_hash, scope_a, sandbox=sandbox)
        cache = self.make_cache(sandbox, clock=lambda: 50_000.0)

        sandbox.history.run_periodic_tasks()

        self.assertTrue(self.present(cache, owned_hash, scope_a, db_id))
        self.assertFalse(self.present(cache, owned_hash, scope_b, db_id))
        self.assertFalse(self.present(cache, other_namespace_hash, scope_a, db_id))

    def test_auth_off_sweep_keeps_a_hash_only_another_namespace_references(self):
        sandbox = self.make_sandbox()
        sibling = hashlib.sha256(b'sibling stack').hexdigest()
        with sandbox.db.get_db_session() as session:
            session.add(SnapshotStateRow(
                namespace='sibling-ns', snapshot_id=str(uuid.uuid4()), snapshot_name='elsewhere', next_seq=1,
                pending_external=False, content_hash=sibling,
            ))
        writer = self.make_cache(sandbox)
        self.store(writer, sibling, sandbox=sandbox)
        cache = self.make_cache(sandbox, clock=lambda: 50_000.0)

        sandbox.history.run_periodic_tasks()

        self.assertTrue(self.present(cache, sibling, db_id=sandbox.history.db_id))

    def test_forced_off_cache_is_never_swept(self):
        sandbox = self.make_sandbox()
        writer = self.make_cache(sandbox)
        orphan = hashlib.sha256(b'orphan').hexdigest()
        self.store(writer, orphan, sandbox=sandbox)
        forced = ResultCache(
            sandbox.settings.RESULT_CACHE_DIR, max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=0,
            build_id='build', pybatfish_version='pyb', schema_version=1, forced_off=True,
        )
        sandbox.history.attach_result_cache(forced)

        sandbox.history.run_periodic_tasks()

        self.assertEqual(self.entry_files(sandbox), {orphan})
        self.assertEqual(forced.stats()['entries'], 0)


if __name__ == '__main__':
    unittest.main()
