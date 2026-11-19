import test_00_environment  # noqa: F401
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from sqlalchemy import update

import config as config_module
from database.models import SnapshotState as SnapshotStateRow
from services.snapshot_state_service import (
    STORE_MARKER_FILENAME,
    Manifest,
    VersioningUnavailableError,
    assert_under_root,
    canonical_manifest_text,
    content_hash,
    history_lock,
    is_canonical_uuid4,
)
from versioning_support import CONFIG_R1, CONFIG_R2, VersioningSandbox, sidecar_path, write_file

R1_SHA = '7e139a0aa1a336cce684b8df0254bc33a2d77a34707e2520117b7c098225b97d'
R2_SHA = '8e093a0d830291de5fe2574ce5bae64df84a7537b67ab4e0d3c341261ac4621e'
LAYER1_SHA = '86f5a972bb33130de425edeadd3bbecae4a2cc17e6ea33c4f15ce683d635b3cc'
X_SHA = '2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881'
VECTOR_TEXT = (
    '{"v":1,"files":[["batfish/layer1_topology.json","' + LAYER1_SHA + '",13],'
    '["configs/R2.cfg","' + R2_SHA + '",12],'
    '["configs/r1.cfg","' + R1_SHA + '",12],'
    '["configs/é.cfg","' + X_SHA + '",1]]}'
)
VECTOR_HASH = 'b31a17d231ad56605086e938aab55f940c48de788e083ed61cb833b35c853222'
EMPTY_MANIFEST_HASH = '3841f5d116d08677319220724fa385618aa782520670ce84b7abc2c51f90fe6b'
IS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0


class SandboxTestCase(unittest.TestCase):
    def make_sandbox(self, **kwargs) -> VersioningSandbox:
        sandbox = VersioningSandbox(**kwargs)
        self.addCleanup(sandbox.cleanup)
        return sandbox


class CanonicalManifestTest(unittest.TestCase):
    def test_fixed_test_vector(self):
        entries = [
            ('configs/r1.cfg', R1_SHA, 12),
            ('configs/é.cfg', X_SHA, 1),
            ('batfish/layer1_topology.json', LAYER1_SHA, 13),
            ('configs/R2.cfg', R2_SHA, 12),
        ]

        self.assertEqual(canonical_manifest_text(entries), VECTOR_TEXT.encode('utf-8'))
        self.assertEqual(content_hash(entries), VECTOR_HASH)
        self.assertEqual(Manifest.from_entries(entries).content_hash, VECTOR_HASH)
        self.assertEqual(content_hash([]), EMPTY_MANIFEST_HASH)

    def test_manifest_of_a_snapshot_matches_the_vector(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = VersioningSandbox(snapshots_dir=Path(temp_dir) / 'snapshots')
            self.addCleanup(sandbox.cleanup)
            snapshot = sandbox.create_snapshot('vector', {
                'configs/r1.cfg': 'hostname r1\n',
                'configs/R2.cfg': 'hostname r2\n',
                'configs/é.cfg': 'x',
                'batfish/layer1_topology.json': '{"edges": []}',
            })

            manifest = sandbox.state.compute_manifest(snapshot)

            self.assertEqual(manifest.text, VECTOR_TEXT.encode('utf-8'))
            self.assertEqual(manifest.content_hash, VECTOR_HASH)


class ConsumableFileSetTest(SandboxTestCase):
    def test_exclusions(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('rules', {
            'configs/r1.cfg': CONFIG_R1,
            'configs/.hidden.cfg': 'hidden',
            'configs/.r1.cfg.1234.tmp': 'temp',
            'configs/r1.cfg~': 'backup',
            'configs/.r1.cfg.swp': 'swap',
            'configs/r1.swp': 'swap',
            'configs/r1.swo': 'swap',
            'configs/#r1.cfg#': 'autosave',
            '.git/config': 'dot dir',
            'configs/.cache/r9.cfg': 'inside dot dir',
            'batfish/layer1_topology.json': '{"edges": []}',
        })
        (snapshot / f"{sidecar_path(snapshot).name}.lock").write_text('', encoding='utf-8')
        os.mkfifo(snapshot / 'configs' / 'pipe.cfg')

        files = [path for path, _ in sandbox.state.iter_consumable_files(snapshot)]

        self.assertEqual(files, ['batfish/layer1_topology.json', 'configs/r1.cfg'])

    def test_non_utf8_name_is_excluded_with_one_warning(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('non-utf8')
        bad_name = os.fsdecode(b'bad-\xff.cfg')
        (snapshot / 'configs' / bad_name).write_text('x', encoding='utf-8')

        with self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            first = [path for path, _ in sandbox.state.iter_consumable_files(snapshot)]
            second = [path for path, _ in sandbox.state.iter_consumable_files(snapshot)]

        self.assertEqual(first, ['configs/r1.cfg'])
        self.assertEqual(second, first)
        self.assertEqual(len([line for line in logs.output if 'not valid UTF-8' in line]), 1)
        self.assertNotIn('bad-', '\n'.join(logs.output))

    def test_every_symlink_kind_is_excluded_with_one_warning(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('links')
        outside = sandbox.root / 'outside'
        outside.mkdir()
        (outside / 'secret.cfg').write_text('secret', encoding='utf-8')
        os.symlink(outside / 'secret.cfg', snapshot / 'configs' / 'file-link.cfg')
        os.symlink(outside, snapshot / 'configs' / 'dir-link')
        os.symlink(snapshot / 'configs' / 'missing.cfg', snapshot / 'configs' / 'dangling.cfg')
        os.symlink('r1.cfg', snapshot / 'configs' / 'relative.cfg')

        with self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            first = [path for path, _ in sandbox.state.iter_consumable_files(snapshot)]
            sandbox.state.iter_consumable_files(snapshot)
            list(sandbox.state.iter_consumable_files(snapshot))

        self.assertEqual(first, ['configs/r1.cfg'])
        self.assertEqual(len([line for line in logs.output if 'symlinks' in line]), 1)


class FingerprintTest(SandboxTestCase):
    def test_fingerprint_is_stable_and_covers_deletion_rename_and_directories(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('fp', {'configs/r1.cfg': CONFIG_R1, 'configs/r2.cfg': CONFIG_R2})
        state = sandbox.state

        first = state.compute_stat_fingerprint(snapshot)
        self.assertEqual(state.compute_stat_fingerprint(snapshot), first)
        state.compute_manifest(snapshot)
        self.assertEqual(state.compute_stat_fingerprint(snapshot), first)

        (snapshot / 'configs' / 'r2.cfg').rename(snapshot / 'configs' / 'r3.cfg')
        renamed = state.compute_stat_fingerprint(snapshot)
        self.assertNotEqual(renamed, first)

        (snapshot / 'configs' / 'r3.cfg').unlink()
        deleted = state.compute_stat_fingerprint(snapshot)
        self.assertNotEqual(deleted, renamed)

        (snapshot / 'extra').mkdir()
        with_directory = state.compute_stat_fingerprint(snapshot)
        self.assertNotEqual(with_directory, deleted)
        self.assertEqual(
            [path for path, _ in state.iter_consumable_files(snapshot)],
            ['configs/r1.cfg'],
        )


class DataDirAndDatabaseUrlResolutionTest(unittest.TestCase):
    def test_resolve_data_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            existing = os.path.join(temp_dir, 'data')
            os.mkdir(existing)
            missing = os.path.join(temp_dir, 'missing')

            self.assertEqual(config_module.resolve_data_dir({}, existing), (existing, False))
            self.assertEqual(
                config_module.resolve_data_dir({'DATA_DIR': '/srv/topologix'}, missing), ('/srv/topologix', False),
            )
            path, fell_back = config_module.resolve_data_dir({'DATA_DIR': ''}, missing)
            self.assertTrue(fell_back)
            self.assertEqual(path, os.path.join(tempfile.gettempdir(), 'topologix-data'))

    def test_resolve_database_url(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir) / 'base'
            base_dir.mkdir()
            data_dir = Path(temp_dir) / 'data'

            self.assertEqual(
                config_module.resolve_database_url({'DATABASE_URL': 'sqlite:///x.db'}, base_dir, data_dir, True),
                'sqlite:///x.db',
            )
            self.assertEqual(
                config_module.resolve_database_url({}, base_dir, data_dir, False),
                f'sqlite:///{base_dir}/topologix.db',
            )
            self.assertEqual(
                config_module.resolve_database_url({}, base_dir, data_dir, True),
                f'sqlite:///{data_dir / "topologix.db"}',
            )

            (base_dir / 'topologix.db').write_bytes(b'')
            with self.assertLogs('config', level='WARNING') as logs:
                url = config_module.resolve_database_url({}, base_dir, data_dir, True)
            self.assertEqual(url, f'sqlite:///{base_dir / "topologix.db"}')
            self.assertIn('legacy database', logs.output[0])

    def test_temp_fallback_forces_the_cache_off_and_versioning_unavailable(self):
        sandbox = VersioningSandbox(DATA_DIR_FELL_BACK=True, RESULT_CACHE_ENABLED=True)
        self.addCleanup(sandbox.cleanup)

        self.assertEqual(sandbox.state.global_unavailable_reason(), 'storage')
        self.assertFalse(sandbox.state.result_cache_enabled)


class ExternalChangeSettleSecondsConfigTest(unittest.TestCase):
    def import_config(self, value: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env['FLASK_ENV'] = 'development'
        env['EXTERNAL_CHANGE_SETTLE_SECONDS'] = value
        return subprocess.run(
            [sys.executable, '-c', 'import config; print(config.config.EXTERNAL_CHANGE_SETTLE_SECONDS)'],
            cwd=str(test_00_environment.BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_non_finite_values_stop_config_import(self):
        for value in ('inf', '-inf', 'nan'):
            with self.subTest(value=value):
                result = self.import_config(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ValueError: EXTERNAL_CHANGE_SETTLE_SECONDS must be a finite number', result.stderr)

    def test_a_decimal_value_is_accepted(self):
        result = self.import_config('2.5')

        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertEqual(result.stdout.strip().splitlines()[-1], '2.5')


class SnapshotIdentityTest(SandboxTestCase):
    def test_create_snapshot_assigns_a_canonical_id(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('created')

        metadata = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))

        self.assertTrue(is_canonical_uuid4(metadata['snapshot_id']))
        self.assertEqual(metadata['schema_version'], 2)

    def test_legacy_sidecar_gets_an_id_and_keeps_every_field(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.snapshots_dir / 'legacy-sidecar'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        original = {
            'schema_version': 1,
            'snapshot_name': 'legacy-sidecar',
            'folder_name': 'lab',
            'owner_user_id': None,
            'owner_username': None,
            'access_scope': 'open',
            'created_at': '2026-01-01T00:00:00',
            'updated_at': '2026-01-02T00:00:00',
            'custom_field': 'kept',
        }
        sidecar_path(snapshot).write_text(json.dumps(original), encoding='utf-8')

        snapshot_id = sandbox.state.ensure_snapshot_id(snapshot)

        metadata = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        self.assertTrue(is_canonical_uuid4(snapshot_id))
        self.assertEqual(metadata['snapshot_id'], snapshot_id)
        self.assertEqual(metadata['schema_version'], 2)
        for name, value in original.items():
            if name != 'schema_version':
                self.assertEqual(metadata[name], value)
        self.assertEqual(sandbox.state.ensure_snapshot_id(snapshot), snapshot_id)

    def test_legacy_id_assignment_runs_under_the_metadata_locks(self):
        for case in ('legacy-sidecar', 'no-sidecar'):
            with self.subTest(case=case):
                sandbox = self.make_sandbox()
                service = sandbox.snapshot_service
                snapshot = sandbox.snapshots_dir / case
                write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
                if case == 'legacy-sidecar':
                    sidecar_path(snapshot).write_text(
                        json.dumps({'schema_version': 1, 'snapshot_name': case, 'access_scope': 'open'}),
                        encoding='utf-8',
                    )
                real_file_lock = service._snapshot_metadata_file_lock
                real_write = service._write_metadata
                file_lock_depth = [0]
                writes = []

                @contextmanager
                def tracking_file_lock(path):
                    with real_file_lock(path):
                        file_lock_depth[0] += 1
                        try:
                            yield
                        finally:
                            file_lock_depth[0] -= 1

                def tracking_write(path, metadata):
                    writes.append((service._metadata_lock._is_owned(), file_lock_depth[0] > 0,
                                   history_lock._is_owned()))
                    return real_write(path, metadata)

                barrier = threading.Barrier(2, timeout=10)
                results = []

                def assign():
                    barrier.wait()
                    results.append(sandbox.state.ensure_snapshot_id(snapshot))

                with mock.patch.object(service, '_snapshot_metadata_file_lock', side_effect=tracking_file_lock), \
                        mock.patch.object(service, '_write_metadata', side_effect=tracking_write):
                    threads = [threading.Thread(target=assign) for _ in range(2)]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(20)

                self.assertEqual(writes, [(True, True, False)])
                self.assertEqual(len(results), 2)
                self.assertEqual(len(set(results)), 1)
                self.assertEqual(sandbox.state.read_sidecar_id(snapshot), results[0])

    def test_sidecar_less_snapshot_keeps_legacy_fields_until_an_owner_is_assigned(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.snapshots_dir / 'no-sidecar'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)

        snapshot_id = sandbox.state.ensure_snapshot_id(snapshot)

        stored = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        self.assertEqual(stored['access_scope'], 'legacy')
        self.assertTrue(stored['legacy_unowned'])
        loaded = sandbox.snapshot_service._load_metadata(snapshot)
        self.assertTrue(loaded['legacy_unowned'])
        self.assertEqual(loaded['access_scope'], 'legacy')
        self.assertEqual(
            [item['name'] for item in sandbox.snapshot_service.list_unowned_snapshots()], ['no-sidecar'],
        )
        self.assertEqual(sandbox.snapshot_service.list_snapshots(requester_user_id=7, auth_enabled=True), [])

        sandbox.snapshot_service.update_snapshot_metadata('no-sidecar', folder_name='lab')
        self.assertEqual(sandbox.state.read_sidecar_id(snapshot), snapshot_id)
        self.assertTrue(sandbox.snapshot_service._load_metadata(snapshot)['legacy_unowned'])

        sandbox.snapshot_service.assign_snapshot_owner('no-sidecar', 7, 'alice')
        assigned = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        self.assertEqual(assigned['snapshot_id'], snapshot_id)
        self.assertEqual(assigned['access_scope'], 'private')
        self.assertNotIn('legacy_unowned', assigned)
        self.assertFalse(sandbox.snapshot_service._load_metadata(snapshot)['legacy_unowned'])
        self.assertEqual(sandbox.snapshot_service.list_unowned_snapshots(), [])

    def test_update_snapshot_metadata_preserves_the_id(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('folder-move')
        snapshot_id = sandbox.snapshot_id('folder-move')

        sandbox.snapshot_service.update_snapshot_metadata('folder-move', folder_name='site/a')

        metadata = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        self.assertEqual(metadata['snapshot_id'], snapshot_id)
        self.assertEqual(metadata['folder_name'], 'site/a')

    def test_non_canonical_id_is_reassigned_with_a_warning(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('bad-id')
        metadata = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        metadata['snapshot_id'] = '../../escape'
        sidecar_path(snapshot).write_text(json.dumps(metadata), encoding='utf-8')

        with self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            snapshot_id = sandbox.state.ensure_snapshot_id(snapshot)

        self.assertTrue(is_canonical_uuid4(snapshot_id))
        self.assertIn('non-canonical snapshot_id', logs.output[0])

    @unittest.skipIf(IS_ROOT, "directory permissions are not enforced for root")
    def test_read_only_directory_marks_the_snapshot_until_it_is_writable(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.snapshots_dir / 'read-only'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        os.chmod(snapshot, 0o555)
        self.addCleanup(os.chmod, snapshot, 0o755)

        with self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            with self.assertRaises(VersioningUnavailableError) as raised:
                sandbox.state.resolve_snapshot_identity(snapshot)
            with self.assertRaises(VersioningUnavailableError):
                sandbox.state.resolve_snapshot_identity(snapshot)
        self.assertEqual(raised.exception.reason, 'sidecar')
        self.assertEqual(sandbox.state.unavailable_reason(snapshot_name='read-only'), 'sidecar')
        self.assertEqual(len([line for line in logs.output if 'metadata sidecar' in line]), 1)

        os.chmod(snapshot, 0o755)
        snapshot_id = sandbox.state.resolve_snapshot_identity(snapshot)

        self.assertTrue(is_canonical_uuid4(snapshot_id))
        self.assertIsNone(sandbox.state.unavailable_reason(snapshot_id, 'read-only'))

    @unittest.skipIf(IS_ROOT, "file permissions are not enforced for root")
    def test_read_only_sidecar_in_a_writable_directory_is_replaced(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('ro-sidecar')
        metadata = json.loads(sidecar_path(snapshot).read_text(encoding='utf-8'))
        del metadata['snapshot_id']
        sidecar_path(snapshot).write_text(json.dumps(metadata), encoding='utf-8')
        os.chmod(sidecar_path(snapshot), 0o444)

        snapshot_id = sandbox.state.resolve_snapshot_identity(snapshot)

        self.assertEqual(sandbox.state.read_sidecar_id(snapshot), snapshot_id)
        self.assertIsNone(sandbox.state.unavailable_reason(snapshot_id, 'ro-sidecar'))


class CopyAndMoveDetectionTest(SandboxTestCase):
    def test_move_renames_the_row_and_a_later_copy_gets_a_fresh_id(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('original')
        snapshot_id = sandbox.snapshot_id('original')
        sandbox.poll('original')

        (sandbox.snapshots_dir / 'original').rename(sandbox.snapshots_dir / 'moved')
        moved = sandbox.poll('moved')

        self.assertEqual(moved.snapshot_id, snapshot_id)
        self.assertEqual(sandbox.row(snapshot_id).snapshot_name, 'moved')
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)

        shutil.copytree(sandbox.snapshots_dir / 'moved', sandbox.snapshots_dir / 'copied')
        copied = sandbox.poll('copied')

        self.assertNotEqual(copied.snapshot_id, snapshot_id)
        self.assertEqual(sandbox.snapshot_id('copied'), copied.snapshot_id)
        self.assertEqual(sandbox.row(snapshot_id).snapshot_name, 'moved')
        self.assertEqual(sandbox.row(copied.snapshot_id).snapshot_name, 'copied')
        self.assertEqual(sandbox.versions(copied.snapshot_id)[0]['kind'], 'baseline')

    def test_copy_of_a_snapshot_with_an_unreadable_sidecar_gets_a_fresh_id(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('origin')
        snapshot_id = sandbox.snapshot_id('origin')
        sandbox.poll('origin')
        shutil.copytree(sandbox.snapshots_dir / 'origin', sandbox.snapshots_dir / 'clone')
        sidecar_path(sandbox.snapshots_dir / 'origin').write_text('{corrupt', encoding='utf-8')

        with self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            clone_id = sandbox.state.resolve_snapshot_identity(sandbox.snapshots_dir / 'clone')

        self.assertNotEqual(clone_id, snapshot_id)
        self.assertEqual(sandbox.row(snapshot_id).snapshot_name, 'origin')
        self.assertTrue(any('cannot be read or parsed' in line for line in logs.output))

    def test_a_read_only_copy_warns_once_and_gets_its_fresh_id_once_writable(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('original')
        original_id = sandbox.snapshot_id('original')
        sandbox.poll('original')
        copy = sandbox.snapshots_dir / 'read-only-copy'
        shutil.copytree(sandbox.snapshots_dir / 'original', copy)
        service = sandbox.snapshot_service
        real_write = service._write_metadata

        def read_only_copy(path, metadata):
            if Path(path) == copy:
                raise PermissionError(errno.EACCES, 'Permission denied')
            return real_write(path, metadata)

        with mock.patch.object(service, '_write_metadata', side_effect=read_only_copy), \
                self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            for _ in range(3):
                with self.assertRaises(VersioningUnavailableError) as raised:
                    sandbox.poll('read-only-copy')
                self.assertEqual(raised.exception.reason, 'sidecar')
                self.assertEqual(sandbox.state.unavailable_reason(snapshot_name='read-only-copy'), 'sidecar')
                self.assertEqual(sandbox.poll('original').snapshot_id, original_id)

        self.assertEqual(len([line for line in logs.output if 'cannot store its snapshot_id' in line]), 1)
        self.assertEqual(sandbox.snapshot_id('read-only-copy'), original_id)
        self.assertEqual(sandbox.state.marked_snapshot_count('sidecar'), 1)
        self.assertIsNone(sandbox.state.unavailable_reason(original_id, 'original'))

        writable = sandbox.poll('read-only-copy')

        self.assertNotEqual(writable.snapshot_id, original_id)
        self.assertEqual(sandbox.snapshot_id('read-only-copy'), writable.snapshot_id)
        self.assertEqual(sandbox.state.marked_snapshot_count('sidecar'), 0)
        self.assertIsNone(sandbox.state.unavailable_reason(writable.snapshot_id, 'read-only-copy'))
        self.assertEqual(sandbox.versions(writable.snapshot_id)[0]['kind'], 'baseline')
        self.assertEqual(sandbox.row(original_id).snapshot_name, 'original')

    def test_concurrent_first_evaluations_of_a_directory_and_its_unopened_copy(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('first', {'configs/r1.cfg': CONFIG_R1})
        shutil.copytree(sandbox.snapshots_dir / 'first', sandbox.snapshots_dir / 'second')
        write_file(sandbox.snapshots_dir / 'second' / 'configs' / 'r1.cfg', CONFIG_R2)
        shared_id = sandbox.snapshot_id('first')
        self.assertEqual(sandbox.snapshot_id('second'), shared_id)

        barrier = threading.Barrier(2, timeout=10)
        calls = []

        def synchronized_put_files(files):
            calls.append(1)
            if len(calls) <= 2:
                barrier.wait()
            return sandbox.history.__class__.put_files(sandbox.history, files)

        results = {}
        errors = []

        def poll(name):
            try:
                results[name] = sandbox.poll(name)
            except Exception as exc:
                errors.append(exc)

        with mock.patch.object(sandbox.history, 'put_files', side_effect=synchronized_put_files):
            threads = [threading.Thread(target=poll, args=(name,)) for name in ('first', 'second')]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(20)

        self.assertEqual(errors, [])
        first_id, second_id = results['first'].snapshot_id, results['second'].snapshot_id
        self.assertNotEqual(first_id, second_id)
        self.assertEqual({first_id, second_id} & {shared_id}, {shared_id})
        first_manifest = sandbox.state.compute_manifest(sandbox.snapshots_dir / 'first')
        second_manifest = sandbox.state.compute_manifest(sandbox.snapshots_dir / 'second')
        self.assertEqual(sandbox.row(first_id).content_hash, first_manifest.content_hash)
        self.assertEqual(sandbox.row(second_id).content_hash, second_manifest.content_hash)
        self.assertEqual(sandbox.row(first_id).snapshot_name, 'first')
        self.assertEqual(sandbox.row(second_id).snapshot_name, 'second')

    def test_two_concurrent_resolutions_of_one_copy_return_the_same_fresh_id(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('base')
        shared_id = sandbox.snapshot_id('base')
        sandbox.poll('base')
        shutil.copytree(sandbox.snapshots_dir / 'base', sandbox.snapshots_dir / 'dup')

        barrier = threading.Barrier(2, timeout=10)
        original = sandbox.state._compare_and_set_fresh_id

        def synchronized(snapshot_dir, expected_id):
            barrier.wait()
            return original(snapshot_dir, expected_id)

        results = []
        errors = []

        def resolve():
            try:
                results.append(sandbox.state.resolve_snapshot_identity(sandbox.snapshots_dir / 'dup'))
            except Exception as exc:
                errors.append(exc)

        with mock.patch.object(sandbox.state, '_compare_and_set_fresh_id', side_effect=synchronized):
            threads = [threading.Thread(target=resolve) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(20)

        self.assertEqual(errors, [])
        self.assertEqual(len(set(results)), 1)
        self.assertNotEqual(results[0], shared_id)
        self.assertEqual(sandbox.snapshot_id('dup'), results[0])

    def test_rename_between_the_two_row_holds_restarts_exactly_once(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('alpha')
        snapshot_id = sandbox.snapshot_id('alpha')
        sandbox.poll('alpha')
        (sandbox.snapshots_dir / 'alpha').rename(sandbox.snapshots_dir / 'beta')

        original_holds = sandbox.state._directory_holds_id
        original_rows = sandbox.state._resolve_rows
        row_calls = []

        def concurrent_rename(directory, expected_id):
            result = original_holds(directory, expected_id)
            with sandbox.db.get_db_session() as session:
                session.execute(
                    update(SnapshotStateRow)
                    .where(SnapshotStateRow.snapshot_id == snapshot_id)
                    .values(snapshot_name='beta')
                )
            return result

        def counted_rows(*args):
            row_calls.append(1)
            return original_rows(*args)

        with mock.patch.object(sandbox.state, '_directory_holds_id', side_effect=concurrent_rename), \
                mock.patch.object(sandbox.state, '_resolve_rows', side_effect=counted_rows):
            resolved = sandbox.state.resolve_snapshot_identity(sandbox.snapshots_dir / 'beta')

        self.assertEqual(resolved, snapshot_id)
        self.assertEqual(len(row_calls), 2)
        self.assertEqual(sandbox.row(snapshot_id).snapshot_name, 'beta')


class NamespaceTest(SandboxTestCase):
    def test_marker_is_published_with_a_hard_link_and_reused(self):
        sandbox = self.make_sandbox()
        marker = sandbox.snapshots_dir / STORE_MARKER_FILENAME
        namespace = sandbox.state.namespace

        self.assertTrue(sandbox.state.namespace_valid)
        self.assertTrue(is_canonical_uuid4(namespace))
        self.assertEqual(json.loads(marker.read_text(encoding='utf-8'))['namespace'], namespace)
        self.assertEqual([path.name for path in sandbox.snapshots_dir.iterdir()], [STORE_MARKER_FILENAME])
        self.assertEqual(sandbox.start().namespace, namespace)

    def test_a_reader_never_sees_a_partial_marker_and_a_concurrent_creator_wins(self):
        sandbox = self.make_sandbox()
        marker = sandbox.snapshots_dir / STORE_MARKER_FILENAME
        marker.unlink()
        observed = []
        competitor = 'competitor-namespace'
        real_link = os.link

        def racing_link(source, destination):
            observed.append(Path(destination).exists())
            observed.append(json.loads(Path(source).read_text(encoding='utf-8'))['namespace'])
            Path(destination).write_text(json.dumps({'namespace': competitor}), encoding='utf-8')
            return real_link(source, destination)

        with mock.patch('services.snapshot_state_service.os.link', side_effect=racing_link):
            state = sandbox.start()

        self.assertFalse(observed[0])
        self.assertTrue(is_canonical_uuid4(observed[1]))
        self.assertEqual(state.namespace, competitor)
        self.assertEqual(sorted(path.name for path in sandbox.snapshots_dir.iterdir()), [STORE_MARKER_FILENAME])

    def test_missing_hard_link_support_names_deployment_id(self):
        for code in (errno.EPERM, errno.EOPNOTSUPP):
            with self.subTest(code=errno.errorcode[code]):
                sandbox = self.make_sandbox()
                (sandbox.snapshots_dir / STORE_MARKER_FILENAME).unlink()
                with mock.patch(
                    'services.snapshot_state_service.os.link', side_effect=OSError(code, os.strerror(code)),
                ), self.assertLogs('services.snapshot_state_service', level='ERROR') as logs:
                    state = sandbox.start()

                self.assertFalse(state.namespace_valid)
                self.assertEqual(state.global_unavailable_reason(), 'namespace')
                self.assertEqual(len(logs.output), 1)
                self.assertIn('DEPLOYMENT_ID', logs.output[0])

    def test_unreadable_corrupt_or_uncreatable_marker_yields_namespace(self):
        cases = ['corrupt', 'no-namespace']
        if not IS_ROOT:
            cases += ['unreadable', 'read-only-root']
        for case in cases:
            with self.subTest(case=case):
                sandbox = self.make_sandbox()
                marker = sandbox.snapshots_dir / STORE_MARKER_FILENAME
                if case == 'corrupt':
                    marker.write_text('{not json', encoding='utf-8')
                elif case == 'no-namespace':
                    marker.write_text('{}', encoding='utf-8')
                elif case == 'unreadable':
                    os.chmod(marker, 0o000)
                else:
                    marker.unlink()
                    os.chmod(sandbox.snapshots_dir, 0o555)
                    self.addCleanup(os.chmod, sandbox.snapshots_dir, 0o755)

                with self.assertLogs('services.snapshot_state_service', level='ERROR') as logs:
                    state = sandbox.start()

                self.assertEqual(state.global_unavailable_reason(), 'namespace')
                self.assertEqual(len(logs.output), 1)

    def test_deployment_id_leaves_the_marker_untouched(self):
        sandbox = self.make_sandbox()
        marker = sandbox.snapshots_dir / STORE_MARKER_FILENAME
        marker.unlink()
        sandbox.settings.DEPLOYMENT_ID = 'stack-a'

        state = sandbox.start()

        self.assertEqual(state.namespace, 'stack-a')
        self.assertFalse(marker.exists())

    def test_invalid_deployment_ids(self):
        for value in ('bad/name', 'x' * 65, 'result_cache', 'snapshots'):
            with self.subTest(value=value):
                sandbox = self.make_sandbox()
                sandbox.settings.DEPLOYMENT_ID = value
                if value == 'snapshots':
                    store = sandbox.data_dir / 'snapshots'
                    store.mkdir()
                    sandbox.snapshot_service.snapshots_dir = store
                with self.assertLogs('services.snapshot_state_service', level='ERROR'):
                    state = sandbox.start()

                self.assertFalse(state.namespace_valid)
                self.assertEqual(state.global_unavailable_reason(), 'namespace')

    def test_introducing_and_reverting_deployment_id_reattaches_history(self):
        sandbox = self.make_sandbox()
        sandbox.create_snapshot('kept')
        snapshot_id = sandbox.snapshot_id('kept')
        sandbox.poll('kept')
        marker_namespace = sandbox.state.namespace

        sandbox.settings.DEPLOYMENT_ID = 'explicit'
        sandbox.start()
        detached = sandbox.poll('kept')
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)
        self.assertEqual(detached.head['kind'], 'baseline')
        self.assertIsNotNone(sandbox.row(snapshot_id, namespace='explicit'))

        sandbox.settings.DEPLOYMENT_ID = ''
        sandbox.start()
        reattached = sandbox.poll('kept')

        self.assertEqual(sandbox.state.namespace, marker_namespace)
        self.assertEqual(reattached.head['seq'], 1)
        self.assertEqual(len(sandbox.versions(snapshot_id)), 1)

    def test_folder_copied_from_another_namespace_keeps_its_id(self):
        sibling = self.make_sandbox()
        sibling.create_snapshot('shared')
        snapshot_id = sibling.snapshot_id('shared')
        sibling.poll('shared')
        sibling_namespace = sibling.state.namespace

        other_store = sibling.root / 'other-store'
        other_store.mkdir()
        shutil.copytree(sibling.snapshots_dir / 'shared', other_store / 'shared')
        sibling.snapshot_service.snapshots_dir = other_store
        state = sibling.start()
        self.assertNotEqual(state.namespace, sibling_namespace)

        copied = sibling.poll('shared')

        self.assertEqual(copied.snapshot_id, snapshot_id)
        self.assertEqual(copied.head['kind'], 'baseline')
        self.assertIsNotNone(sibling.row(snapshot_id, namespace=sibling_namespace))
        self.assertIsNotNone(sibling.row(snapshot_id, namespace=state.namespace))


class StorageOverlapTest(unittest.TestCase):
    def make(self, **kwargs) -> VersioningSandbox:
        sandbox = VersioningSandbox(**kwargs)
        self.addCleanup(sandbox.cleanup)
        return sandbox

    def test_history_or_cache_directory_inside_the_store_is_a_storage_fault(self):
        sandbox = self.make()
        for overrides in (
            {'SNAPSHOT_HISTORY_DIR': str(sandbox.snapshots_dir / 'history')},
            {'RESULT_CACHE_DIR': str(sandbox.snapshots_dir / 'cache')},
            {'RESULT_CACHE_DIR': str(sandbox.data_dir / 'shared'), 'SNAPSHOT_HISTORY_DIR': str(sandbox.data_dir / 'shared')},
        ):
            with self.subTest(overrides=overrides):
                for name, value in overrides.items():
                    setattr(sandbox.settings, name, value)
                sandbox.settings.RESULT_CACHE_ENABLED = True
                with self.assertLogs('services.snapshot_state_service', level='ERROR') as logs:
                    state = sandbox.start()

                self.assertEqual(state.global_unavailable_reason(), 'storage')
                self.assertFalse(state.result_cache_enabled)
                self.assertFalse(sandbox.settings.RESULT_CACHE_ENABLED)
                self.assertEqual(len([line for line in logs.output if 'overlap' in line]), 1)
                sandbox.settings.RESULT_CACHE_DIR = str(sandbox.data_dir / 'result_cache')
                sandbox.settings.SNAPSHOT_HISTORY_DIR = str(sandbox.data_dir / 'snapshot_history')

    def test_storage_is_reported_before_namespace(self):
        sandbox = self.make()
        sandbox.settings.SNAPSHOT_HISTORY_DIR = str(sandbox.snapshots_dir / 'history')
        sandbox.settings.DEPLOYMENT_ID = 'result_cache'
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            state = sandbox.start()

        self.assertFalse(state.namespace_valid)
        self.assertEqual(state.global_unavailable_reason(), 'storage')

    def test_data_dir_inside_the_store_stages_under_a_system_temp_root(self):
        sandbox = self.make()
        snapshot = sandbox.create_snapshot('inner')
        sandbox.settings.DATA_DIR = str(sandbox.snapshots_dir / 'data')
        sandbox.settings.RESULT_CACHE_DIR = str(sandbox.root / 'cache')
        sandbox.settings.SNAPSHOT_HISTORY_DIR = str(sandbox.root / 'history')
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            state = sandbox.start()

        self.assertEqual(state.global_unavailable_reason(), 'storage')
        staged_dir, staged_hash = state.stage_for_upload(snapshot)
        self.addCleanup(shutil.rmtree, state.staging_root(), True)

        self.assertFalse(staged_dir.resolve().is_relative_to(sandbox.snapshots_dir.resolve()))
        self.assertTrue(staged_dir.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.assertEqual(staged_hash, state.compute_manifest(snapshot).content_hash)
        leftover = state.staging_root() / 'leftover'
        leftover.mkdir()
        state.cleanup_all_staging(sandbox.history.db_id)
        self.assertTrue(leftover.exists())
        self.assertEqual(
            [path.name for path in sandbox.snapshots_dir.iterdir() if not path.name.startswith('.')], ['inner'],
        )

    def test_invalid_namespace_root_as_the_store_keeps_a_snapshot_named_staging(self):
        sandbox = self.make()
        store = sandbox.data_dir / '_invalid-namespace'
        store.mkdir()
        sandbox.snapshot_service.snapshots_dir = store
        write_file(store / 'staging' / 'configs' / 'r1.cfg', CONFIG_R1)
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            state = sandbox.start()

        self.assertEqual(state.global_unavailable_reason(), 'storage')
        self.assertTrue((store / 'staging' / 'configs' / 'r1.cfg').exists())

    def test_result_cache_dir_equal_to_the_store_keeps_a_snapshot_named_tmp(self):
        sandbox = self.make()
        write_file(sandbox.snapshots_dir / 'tmp' / 'configs' / 'r1.cfg', CONFIG_R1)
        sandbox.settings.RESULT_CACHE_DIR = str(sandbox.snapshots_dir)
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            state = sandbox.start()

        self.assertEqual(state.global_unavailable_reason(), 'storage')
        self.assertTrue((sandbox.snapshots_dir / 'tmp' / 'configs' / 'r1.cfg').exists())


class StagingTest(SandboxTestCase):
    def test_staged_copy_holds_exactly_the_consumable_set(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('stage', {
            'configs/r1.cfg': CONFIG_R1,
            'configs/.hidden': 'hidden',
            'configs/r1.cfg~': 'backup',
            'batfish/layer1_topology.json': '{"edges": []}',
        })
        os.symlink(snapshot / 'configs' / 'r1.cfg', snapshot / 'configs' / 'link.cfg')
        snapshot_id = sandbox.snapshot_id('stage')

        staged_dir, staged_hash = sandbox.state.stage_for_upload(snapshot)

        root = sandbox.data_dir / sandbox.state.namespace / 'staging'
        self.assertEqual(staged_dir, root / snapshot_id / 'stage')
        staged_files = sorted(
            path.relative_to(staged_dir).as_posix() for path in staged_dir.rglob('*') if path.is_file()
        )
        self.assertEqual(staged_files, ['batfish/layer1_topology.json', 'configs/r1.cfg'])
        self.assertEqual(staged_hash, sandbox.state.compute_manifest(snapshot).content_hash)
        self.assertEqual(oct(staged_dir.parent.stat().st_mode & 0o777), '0o700')

        sandbox.state.cleanup_staging(staged_dir)
        self.assertFalse((root / snapshot_id).exists())

    def test_staging_without_a_sidecar_id_uses_a_temporary_directory(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.snapshots_dir / 'no-id'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)

        staged_dir, _ = sandbox.state.stage_for_upload(snapshot)

        self.assertEqual(staged_dir.name, 'no-id')
        self.assertTrue(staged_dir.parent.parent == sandbox.state.staging_root())
        sandbox.state.cleanup_staging(staged_dir)
        self.assertFalse(staged_dir.parent.exists())

    def test_a_staging_path_that_escapes_its_root_is_refused(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('escape')
        snapshot_id = sandbox.snapshot_id('escape')
        root = sandbox.state.staging_root()
        root.mkdir(parents=True, exist_ok=True)
        outside = sandbox.root / 'outside'
        outside.mkdir()
        os.symlink(outside, root / snapshot_id)

        with self.assertRaises(ValueError):
            sandbox.state.stage_for_upload(snapshot)
        with self.assertRaises(ValueError):
            assert_under_root(root / '..' / '..' / 'x', root)
        self.assertEqual(list(outside.iterdir()), [])

    def test_startup_sweeps_leftover_staging_and_temporary_directories(self):
        sandbox = self.make_sandbox()
        namespace_leftover = sandbox.data_dir / sandbox.state.namespace / 'staging' / 'old' / 'snap'
        invalid_leftover = sandbox.data_dir / '_invalid-namespace' / 'staging' / 'old'
        history_leftover = sandbox.history.tmp_dir / 'object-partial'
        cache_leftover = sandbox.data_dir / 'result_cache' / 'tmp' / 'partial.gz'
        for path in (namespace_leftover, invalid_leftover):
            path.mkdir(parents=True)
        for path in (history_leftover, cache_leftover):
            write_file(path, 'partial')
        store_snapshot = sandbox.create_snapshot('staging')

        sandbox.start()

        for path in (namespace_leftover, invalid_leftover, history_leftover, cache_leftover):
            self.assertFalse(path.exists(), path)
        self.assertTrue((store_snapshot / 'configs' / 'r1.cfg').exists())

    def test_invalid_namespace_stages_under_the_invalid_namespace_root(self):
        sandbox = self.make_sandbox()
        snapshot = sandbox.create_snapshot('ns-invalid')
        sandbox.settings.DEPLOYMENT_ID = 'bad/value'
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            state = sandbox.start()

        staged_dir, _ = state.stage_for_upload(snapshot)

        self.assertTrue(staged_dir.is_relative_to(sandbox.data_dir / '_invalid-namespace' / 'staging'))


if __name__ == '__main__':
    unittest.main()
