import test_00_environment  # noqa: F401
import errno
import hashlib
import io
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from flask import request as flask_request
from sqlalchemy import func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import NullPool

import app as app_module
import services.snapshot_history_service as history_module
from database.models import HistoryNamespace, HistoryObject, SnapshotState as SnapshotStateRow, SnapshotVersion
from database.models import SnapshotVersionFile
from database.session import DatabaseManager
from services.batfish_service import ActivationFailureCache
from services.result_cache import ResultCache
from services.snapshot_state_service import STORE_MARKER_FILENAME, is_canonical_uuid4
from versioning_support import CONFIG_R1, CONFIG_R2, VersioningSandbox, sidecar_path, write_file

BACKEND_DIR = Path(__file__).resolve().parents[1]
IS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0
STATE_LOGGER = 'services.snapshot_state_service'
HISTORY_LOGGER = 'services.snapshot_history_service'
UNKNOWN_VERSION_ID = '00000000-0000-4000-8000-000000000000'


def config_for(label: str) -> str:
    return f"hostname {label}\ninterface Loopback0\n ip address 192.0.2.9 255.255.255.255\n"
VERSION_STATE_KEYS = {
    'snapshot_id', 'content_hash', 'loaded_content_hash', 'loaded_batfish_version', 'loaded_live',
    'result_cache_enabled', 'head', 'uncommitted', 'pending_external', 'external_settling', 'restored_from',
}
LOADED_ATTRIBUTES = ('loaded_content_hash', 'loaded_batfish_version', 'live_loaded')
VERSION_KEYS = {
    'version_id', 'seq', 'message', 'kind', 'created_at', 'author', 'file_count', 'total_bytes', 'parent',
    'restored_from',
}
DIFF_KEYS = {'from', 'against', 'files'}
FILE_DIFF_KEYS = {'path', 'binary', 'too_large', 'truncated', 'hunks'}
OUTSIDE_SECRET = 'outside secret\n'


class VersionRouteTestCase(unittest.TestCase):
    sandbox_options: dict = {}

    def setUp(self):
        self.originals = (app_module.snapshot_state_service, app_module.snapshot_history_service)
        self.sandbox = VersioningSandbox(snapshot_service=app_module.snapshot_service, **self.sandbox_options)
        self.install()
        self.batfish_service = app_module.batfish_service
        self.batfish_state = (
            self.batfish_service.network_name,
            self.batfish_service.current_snapshot_name,
            self.batfish_service._initialized,
        )
        self.batfish_loaded_attributes = {
            name: self.batfish_service.__dict__[name]
            for name in LOADED_ATTRIBUTES if name in self.batfish_service.__dict__
        }
        self.client = app_module.app.test_client()

    def tearDown(self):
        (
            self.batfish_service.network_name,
            self.batfish_service.current_snapshot_name,
            self.batfish_service._initialized,
        ) = self.batfish_state
        for name in LOADED_ATTRIBUTES:
            if name in self.batfish_loaded_attributes:
                setattr(self.batfish_service, name, self.batfish_loaded_attributes[name])
            else:
                self.batfish_service.__dict__.pop(name, None)
        app_module.snapshot_state_service, app_module.snapshot_history_service = self.originals
        self.sandbox.cleanup()

    def install(self):
        app_module.snapshot_state_service = self.sandbox.state
        app_module.snapshot_history_service = self.sandbox.history

    def restart(self):
        self.sandbox.start()
        self.install()

    def version_state(self, name: str):
        return self.client.get(f'/api/snapshots/{name}/version-state')

    def commit(self, name: str, body):
        return self.client.post(f'/api/snapshots/{name}/versions', json=body)

    def upload(self, name: str, filename: str, content: str):
        return self.client.post(
            f'/api/snapshots/{name}/files',
            data={'file': (io.BytesIO(content.encode('utf-8')), filename)},
            content_type='multipart/form-data',
        )


class VersionStateRouteTest(VersionRouteTestCase):
    def test_version_state_reports_the_full_object(self):
        self.sandbox.create_snapshot('web')

        response = self.version_state('web')

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        data = response.get_json()['data']
        self.assertEqual(set(data), VERSION_STATE_KEYS)
        self.assertTrue(is_canonical_uuid4(data['snapshot_id']))
        self.assertEqual(data['content_hash'], self.sandbox.state.compute_manifest(self.sandbox.snapshots_dir / 'web').content_hash)
        self.assertIsNone(data['loaded_content_hash'])
        self.assertIsNone(data['loaded_batfish_version'])
        self.assertFalse(data['loaded_live'])
        self.assertFalse(data['result_cache_enabled'])
        self.assertEqual(set(data['head']), VERSION_KEYS)
        self.assertEqual((data['head']['kind'], data['head']['author']), ('baseline', None))
        self.assertFalse(data['uncommitted'])
        self.assertFalse(data['pending_external'])
        self.assertFalse(data['external_settling'])
        self.assertIsNone(data['restored_from'])

    def test_missing_directory_is_snapshot_not_found_and_writes_nothing(self):
        response = self.version_state('missing')

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()['code'], 'snapshot_not_found')
        self.assertEqual(self.sandbox.count(SnapshotStateRow), 0)
        self.assertEqual(self.version_state('bad%20name').status_code, 400)

    def test_non_utf8_file_name_keeps_answering_200(self):
        snapshot = self.sandbox.create_snapshot('odd-names')
        (snapshot / 'configs' / os.fsdecode(b'odd-\xfe.cfg')).write_text('x', encoding='utf-8')

        response = self.version_state('odd-names')

        self.assertEqual(response.status_code, 200)

    def test_loaded_fields_follow_the_batfish_context(self):
        self.sandbox.create_snapshot('loaded')
        working_hash = self.version_state('loaded').get_json()['data']['content_hash']
        service = self.batfish_service
        service.network_name = app_module.config.BATFISH_NETWORK
        service.current_snapshot_name = 'loaded'
        service._initialized = True
        service.loaded_content_hash = 'loaded-hash'
        service.loaded_batfish_version = '2025.07.07'

        data = self.version_state('loaded').get_json()['data']
        self.assertEqual((data['loaded_content_hash'], data['loaded_batfish_version']), ('loaded-hash', '2025.07.07'))

        for change in ('name', 'network', 'initialized'):
            with self.subTest(change=change):
                service.network_name = 'other_network' if change == 'network' else app_module.config.BATFISH_NETWORK
                service.current_snapshot_name = 'other' if change == 'name' else 'loaded'
                service._initialized = change != 'initialized'
                data = self.version_state('loaded').get_json()['data']
                self.assertIsNone(data['loaded_content_hash'])
                self.assertIsNone(data['loaded_batfish_version'])

        service.network_name = app_module.config.BATFISH_NETWORK
        service.current_snapshot_name = 'loaded'
        service._initialized = True
        service.live_loaded = (app_module.config.BATFISH_NETWORK, 'loaded', working_hash, 0.0)
        self.assertTrue(self.version_state('loaded').get_json()['data']['loaded_live'])
        service.live_loaded = (app_module.config.BATFISH_NETWORK, 'loaded', 'stale-hash', 0.0)
        self.assertFalse(self.version_state('loaded').get_json()['data']['loaded_live'])

    def test_never_settled_first_observation_answers_the_null_hash_object(self):
        self.sandbox.create_snapshot('unsettled')
        state = self.sandbox.state
        original_scan = state.scan_tree
        counter = iter(range(1000))

        def moving(snapshot_dir):
            scan = original_scan(snapshot_dir)
            scan.fingerprint = hashlib.sha256(f"{scan.fingerprint}:{next(counter)}".encode()).hexdigest()
            return scan

        with mock.patch.object(state, 'scan_tree', side_effect=moving):
            response = self.version_state('unsettled')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()['data']
        self.assertEqual(set(data), VERSION_STATE_KEYS)
        self.assertIsNone(data['content_hash'])
        self.assertIsNone(data['head'])
        self.assertTrue(data['external_settling'])
        self.assertFalse(data['uncommitted'])
        self.assertFalse(data['pending_external'])
        self.assertIsNone(data['restored_from'])
        self.assertEqual(self.sandbox.version_count(), 0)

    def test_runtime_database_failure_answers_database(self):
        self.sandbox.create_snapshot('db-fail')
        failure = OperationalError('SELECT 1', {}, Exception('database is unavailable'))

        with mock.patch.object(self.sandbox.state, '_resolve_rows', side_effect=failure):
            response = self.version_state('db-fail')

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()['code'], 'versioning_unavailable')
        self.assertEqual(response.get_json()['details'], {'reason': 'database'})

    @unittest.skipIf(IS_ROOT, "file permissions are not enforced for root")
    def test_unreadable_files_answer_500_while_an_unreadable_sidecar_is_403(self):
        snapshot = self.sandbox.create_snapshot('unreadable')
        config_file = snapshot / 'configs' / 'r1.cfg'
        os.chmod(config_file, 0o000)

        self.assertEqual(self.version_state('unreadable').status_code, 500)
        self.assertEqual(self.commit('unreadable', {'message': 'x'}).status_code, 500)

        os.chmod(config_file, 0o644)
        os.chmod(sidecar_path(snapshot), 0o000)
        self.assertEqual(self.version_state('unreadable').status_code, 403)


class UnavailableVersioningRouteTest(VersionRouteTestCase):
    def assert_unavailable(self, name: str, reason: str):
        version_id = '00000000-0000-4000-8000-000000000000'
        responses = {
            'version-state': self.version_state(name),
            'list': self.client.get(f'/api/snapshots/{name}/versions'),
            'detail': self.client.get(f'/api/snapshots/{name}/versions/{version_id}'),
            'commit': self.commit(name, {'message': 'blocked'}),
        }
        for route, response in responses.items():
            with self.subTest(route=route, reason=reason):
                self.assertEqual(response.status_code, 503, response.get_data(as_text=True)[:300])
                payload = response.get_json()
                self.assertEqual(payload['code'], 'versioning_unavailable')
                self.assertEqual(payload['details'], {'reason': reason})

    def test_database_namespace_and_storage_reasons(self):
        self.sandbox.create_snapshot('blocked')
        self.sandbox.settings.DEPLOYMENT_ID = 'result_cache'
        with self.assertLogs('services.snapshot_state_service', level='ERROR'):
            self.restart()
        self.assert_unavailable('blocked', 'namespace')

        self.sandbox.settings.DEPLOYMENT_ID = ''
        self.sandbox.settings.DATA_DIR_FELL_BACK = True
        self.restart()
        self.assert_unavailable('blocked', 'storage')

        self.sandbox.settings.DATA_DIR_FELL_BACK = False
        database = self.sandbox.db
        self.sandbox.db = None
        try:
            self.restart()
            self.assert_unavailable('blocked', 'database')
        finally:
            self.sandbox.db = database

    def test_missing_objects_reason_for_the_affected_snapshot_only(self):
        self.sandbox.create_snapshot('lost', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('kept', {'configs/r2.cfg': CONFIG_R2})
        self.version_state('lost')
        self.version_state('kept')
        self.sandbox.history.object_path(hashlib.sha256(CONFIG_R1.encode()).hexdigest()).unlink()
        with self.assertLogs('services.snapshot_history_service', level='ERROR'):
            self.restart()

        self.assert_unavailable('lost', 'missing_objects')
        self.assertEqual(self.version_state('kept').status_code, 200)

    @unittest.skipIf(IS_ROOT, "directory permissions are not enforced for root")
    def test_read_only_directory_is_sidecar_until_writable_and_delete_drops_the_mark(self):
        snapshot = self.sandbox.snapshots_dir / 'frozen'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        os.chmod(snapshot, 0o555)

        with self.assertLogs('services.snapshot_state_service', level='WARNING'):
            self.assert_unavailable('frozen', 'sidecar')
        os.chmod(snapshot, 0o755)
        self.assertEqual(self.version_state('frozen').status_code, 200)

        other = self.sandbox.snapshots_dir / 'frozen-delete'
        write_file(other / 'configs' / 'r1.cfg', CONFIG_R1)
        os.chmod(other, 0o555)
        with self.assertLogs('services.snapshot_state_service', level='WARNING'):
            self.assertEqual(self.version_state('frozen-delete').status_code, 503)
        os.chmod(other, 0o755)

        delete = self.client.delete('/api/snapshots/frozen-delete')

        self.assertEqual(delete.status_code, 200, delete.get_data(as_text=True)[:300])
        self.assertIsNone(self.sandbox.state.unavailable_reason(snapshot_name='frozen-delete'))
        self.assertEqual(self.client.post('/api/snapshots', json={'name': 'frozen-delete'}).status_code, 200)
        self.assertEqual(self.upload('frozen-delete', 'r1.cfg', CONFIG_R1).status_code, 200)
        self.assertEqual(self.version_state('frozen-delete').status_code, 200)
        self.assertEqual(self.commit('frozen-delete', {'message': 'after re-create'}).status_code, 201)


class WritesWithoutVersioningRouteTest(VersionRouteTestCase):
    def exercise_writes(self, name: str):
        self.assertEqual(self.client.post('/api/snapshots', json={'name': name}).status_code, 200)
        upload = self.upload(name, 'r1.cfg', CONFIG_R1)
        self.assertEqual(upload.status_code, 200, upload.get_data(as_text=True)[:300])
        self.assertEqual(upload.get_json()['message'], 'File uploaded successfully')
        self.assertTrue(upload.get_json()['data']['requires_reinitialize'])

        content = self.client.get(f'/api/snapshots/{name}/files/r1.cfg/content').get_json()['data']
        put = self.client.put(
            f'/api/snapshots/{name}/files/r1.cfg/content',
            json={'content': CONFIG_R2, 'expected_sha256': content['sha256']},
        )
        self.assertEqual(put.status_code, 200, put.get_data(as_text=True)[:300])
        self.assertEqual(put.get_json()['message'], 'Snapshot file content updated successfully')

        delete_file = self.client.delete(f'/api/snapshots/{name}/files/r1.cfg')
        self.assertEqual(delete_file.status_code, 200)
        self.assertEqual(delete_file.get_json()['data'], {'name': 'r1.cfg', 'requires_reinitialize': True})

        delete_snapshot = self.client.delete(f'/api/snapshots/{name}')
        self.assertEqual(delete_snapshot.status_code, 200)
        self.assertEqual(delete_snapshot.get_json()['message'], 'Snapshot deleted successfully')

    def test_writes_keep_todays_responses_when_versioning_is_unavailable(self):
        self.sandbox.settings.DATA_DIR_FELL_BACK = True
        self.restart()
        self.exercise_writes('temp-fallback')
        self.assertEqual(self.sandbox.version_count(), 0)

        self.sandbox.settings.DATA_DIR_FELL_BACK = False
        database = self.sandbox.db
        self.sandbox.db = None
        try:
            self.restart()
            self.exercise_writes('no-database')
        finally:
            self.sandbox.db = database

        self.restart()
        app_module.snapshot_service.attach_state_service(None)
        self.exercise_writes('detached')
        self.assertEqual(self.sandbox.version_count(), 0)

    def test_writes_succeed_when_settle_or_resolution_fails(self):
        failure = OperationalError('SELECT 1', {}, Exception('database is unavailable'))
        with mock.patch.object(self.sandbox.state, 'settle_external_changes', side_effect=RuntimeError('boom')), \
                self.assertLogs('services.snapshot_state_service', level='WARNING'):
            self.exercise_writes('settle-failure')
        with mock.patch.object(self.sandbox.state, '_resolve_rows', side_effect=failure), \
                self.assertLogs('services.snapshot_state_service', level='WARNING'):
            self.exercise_writes('resolution-failure')

        original_evaluate = self.sandbox.state._evaluate_locked

        def failing_end_write(snapshot_id, snapshot_dir, mode, restored_from):
            if mode == 'end_write':
                raise failure
            return original_evaluate(snapshot_id, snapshot_dir, mode, restored_from)

        with mock.patch.object(self.sandbox.state, '_evaluate_locked', side_effect=failing_end_write), \
                self.assertLogs('services.snapshot_state_service', level='WARNING') as logs:
            self.exercise_writes('end-write-failure')
        self.assertTrue(any('could not be recorded' in line for line in logs.output))
        self.assertEqual(self.sandbox.state._in_progress, {})


class VersionListAndCommitRouteTest(VersionRouteTestCase):
    def test_commit_list_and_detail(self):
        self.sandbox.create_snapshot('history')
        baseline = self.version_state('history').get_json()['data']
        self.upload('history', 'r2.cfg', CONFIG_R2)

        created = self.commit('history', {'message': '  add r2  ', 'expected_head': baseline['head']['version_id']})

        self.assertEqual(created.status_code, 201, created.get_data(as_text=True)[:300])
        version = created.get_json()['data']
        self.assertEqual(set(version), VERSION_KEYS)
        self.assertEqual((version['seq'], version['kind'], version['message'], version['author']),
                         (2, 'manual', 'add r2', None))
        self.assertEqual(version['parent'], {'version_id': baseline['head']['version_id'], 'seq': 1})

        unchanged = self.commit('history', {'message': 'again'})
        self.assertEqual(unchanged.status_code, 409)
        self.assertEqual(unchanged.get_json()['code'], 'version_unchanged')

        listing = self.client.get('/api/snapshots/history/versions').get_json()['data']
        self.assertEqual(listing['total'], 2)
        self.assertEqual([item['seq'] for item in listing['items']], [2, 1])
        paged = self.client.get('/api/snapshots/history/versions?limit=1&offset=1').get_json()['data']
        self.assertEqual(([item['seq'] for item in paged['items']], paged['total']), ([1], 2))

        detail = self.client.get(f"/api/snapshots/history/versions/{version['version_id']}")
        self.assertEqual(detail.status_code, 200)
        detail_data = detail.get_json()['data']
        self.assertEqual(set(detail_data), VERSION_KEYS | {'files'})
        self.assertEqual([entry['path'] for entry in detail_data['files']], ['configs/r1.cfg', 'configs/r2.cfg'])
        self.assertEqual(set(detail_data['files'][0]), {'path', 'sha256', 'size'})

        missing = self.client.get('/api/snapshots/history/versions/00000000-0000-4000-8000-000000000000')
        self.assertEqual((missing.status_code, missing.get_json()['code']), (404, 'version_not_found'))
        self.sandbox.create_snapshot('elsewhere')
        self.version_state('elsewhere')
        foreign = self.client.get(f"/api/snapshots/elsewhere/versions/{version['version_id']}")
        self.assertEqual((foreign.status_code, foreign.get_json()['code']), (404, 'version_not_found'))
        gone = self.client.get(f"/api/snapshots/nowhere/versions/{version['version_id']}")
        self.assertEqual((gone.status_code, gone.get_json()['code']), (404, 'snapshot_not_found'))

    def test_expected_head_guards_the_commit(self):
        self.sandbox.create_snapshot('guarded')
        head_id = self.version_state('guarded').get_json()['data']['head']['version_id']
        self.upload('guarded', 'r2.cfg', CONFIG_R2)

        for expected in ('another-version', None):
            with self.subTest(expected=expected):
                response = self.commit('guarded', {'message': 'stale', 'expected_head': expected})
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.get_json()['code'], 'version_conflict')
        self.assertEqual(self.commit('guarded', {'message': 'ok', 'expected_head': head_id}).status_code, 201)

    def test_request_validation(self):
        self.sandbox.create_snapshot('validate')
        self.version_state('validate')
        self.upload('validate', 'r2.cfg', CONFIG_R2)

        for body in (
            {},
            {'message': 5},
            {'message': ''},
            {'message': '   '},
            {'message': 'x' * 501},
            {'message': 'ok', 'expected_head': 5},
            {'message': 'ok', 'expected_head': ['list']},
        ):
            with self.subTest(body=body):
                response = self.commit('validate', body)
                self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()['code'], 'validation_error')
        for raw, content_type in (
            ('[1]', 'application/json'), ('{bad', 'application/json'), ('', None), ('null', 'application/json'),
            ('"text"', 'application/json'), ('5', 'application/json'),
        ):
            with self.subTest(raw=raw):
                response = self.client.post(
                    '/api/snapshots/validate/versions', data=raw, content_type=content_type,
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()['code'], 'invalid_json')
        self.assertEqual(self.sandbox.version_count(), 1)

        for query in ('limit=0', 'limit=201', 'limit=abc', 'limit=-1', 'limit=', 'limit=1.5',
                      'offset=-1', 'offset=x', 'offset=+1'):
            with self.subTest(query=query):
                response = self.client.get(f'/api/snapshots/validate/versions?{query}')
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.get_json()['code'], 'validation_error')
        self.assertEqual(self.client.get('/api/snapshots/validate/versions?limit=200&offset=0').status_code, 200)

        accepted = self.commit('validate', {'message': 'x' * 500})
        self.assertEqual(accepted.status_code, 201)

    def test_database_failures_of_a_version_route_never_log_their_text(self):
        self.sandbox.create_snapshot('db-text')
        self.version_state('db-text')
        self.upload('db-text', 'r2.cfg', CONFIG_R2)
        text = 'SELECT snapshot_versions.seq FROM snapshot_versions; host "db.internal.example" port 5432'
        wrapped = RuntimeError('commit failed')
        wrapped.__cause__ = OperationalError(text, ('bound-parameter-value',), Exception(text))
        history = app_module.snapshot_history_service

        with mock.patch.object(history, 'commit', side_effect=sqlite3.OperationalError(text)), \
                self.assertNoLogs('app', level='ERROR'):
            unavailable = self.commit('db-text', {'message': 'driver error'})
        with mock.patch.object(history, 'commit', side_effect=wrapped), self.assertLogs('app', level='ERROR') as logs:
            failed = self.commit('db-text', {'message': 'wrapped database error'})

        self.assertEqual(unavailable.status_code, 503)
        self.assertEqual(unavailable.get_json()['code'], 'versioning_unavailable')
        self.assertEqual(unavailable.get_json()['details'], {'reason': 'database'})
        self.assertEqual(failed.status_code, 500)
        logged = '\n'.join(logs.output)
        self.assertIn('Failed to commit snapshot version: OperationalError', logged)
        for fragment in ('SELECT', 'bound-parameter-value', 'db.internal.example', '5432'):
            self.assertNotIn(fragment, logged)
            self.assertNotIn(fragment, unavailable.get_data(as_text=True))
            self.assertNotIn(fragment, failed.get_data(as_text=True))

    def test_huge_offset_is_clamped_to_an_empty_page(self):
        self.sandbox.create_snapshot('far')
        self.version_state('far')

        with self.assertNoLogs('app', level='ERROR'), self.assertNoLogs('database.session', level='ERROR'):
            for offset in ('9223372036854775807', '9223372036854775808', '99999999999999999999',
                           '9' * 5000, '0' * 30 + '1'):
                with self.subTest(offset=offset[:24]):
                    response = self.client.get(f'/api/snapshots/far/versions?offset={offset}')
                    self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                    self.assertEqual(response.get_json()['data'], {'items': [], 'total': 1})
            too_large_limit = self.client.get(f"/api/snapshots/far/versions?limit={'9' * 5000}")
            self.assertEqual(too_large_limit.status_code, 400)
            self.assertEqual(too_large_limit.get_json()['code'], 'validation_error')

    def test_snapshot_recreated_between_commit_phases_answers_500_without_rows(self):
        snapshot = self.sandbox.create_snapshot('reborn')
        purged_id = self.sandbox.snapshot_id('reborn')
        original_phase1 = self.sandbox.history._commit_phase1

        def phase1_then_recreate(snapshot_dir):
            prepared = original_phase1(snapshot_dir)
            shutil.rmtree(snapshot)
            self.sandbox.create_snapshot('reborn')
            return prepared

        with mock.patch.object(self.sandbox.history, '_commit_phase1', side_effect=phase1_then_recreate), \
                self.assertLogs('app', level='ERROR'):
            response = self.commit('reborn', {'message': 'stale'})

        self.assertEqual(response.status_code, 500)
        recreated_id = self.sandbox.snapshot_id('reborn')
        self.assertNotEqual(recreated_id, purged_id)
        self.assertIsNone(self.sandbox.row(purged_id))
        self.assertIsNone(self.sandbox.row(recreated_id))
        self.assertEqual(self.sandbox.version_count(), 0)

    def test_version_routes_are_matched_by_endpoint_and_never_take_the_batfish_lock(self):
        for name in ('files-x', 'artifacts-x'):
            for method, path in (
                ('GET', f'/api/snapshots/{name}/version-state'),
                ('GET', f'/api/snapshots/{name}/versions'),
                ('POST', f'/api/snapshots/{name}/versions'),
                ('GET', f'/api/snapshots/{name}/versions/00000000-0000-4000-8000-000000000000'),
            ):
                with self.subTest(method=method, path=path):
                    with app_module.app.test_request_context(path, method=method):
                        self.assertFalse(app_module.request_uses_batfish())
        with app_module.app.test_request_context('/api/snapshots/files-x/files', method='POST'):
            self.assertTrue(app_module.request_uses_batfish())

        self.sandbox.create_snapshot('files-x')
        self.version_state('files-x')
        self.assertEqual(self.upload('files-x', 'r2.cfg', CONFIG_R2).status_code, 200)
        lock = mock.MagicMock()
        with mock.patch.object(app_module, 'batfish_request_lock', lock):
            response = self.commit('files-x', {'message': 'unlocked'})
        self.assertEqual(response.status_code, 201)
        lock.acquire.assert_not_called()


class HistoryRouteTestCase(VersionRouteTestCase):
    sandbox_options = {'HISTORY_GC_GRACE_SECONDS': 0}

    def build_history(self, name: str, count: int, rewrite: bool = False) -> list:
        self.sandbox.create_snapshot(name, {'configs/r1.cfg': config_for(f'{name}-v1')})
        versions = [self.version_state(name).get_json()['data']['head']]
        for index in range(2, count + 1):
            filename = 'r1.cfg' if rewrite else f'r{index}.cfg'
            uploaded = self.upload(name, filename, config_for(f'{name}-v{index}'))
            self.assertEqual(uploaded.status_code, 200, uploaded.get_data(as_text=True)[:300])
            created = self.commit(name, {'message': f'v{index}'})
            self.assertEqual(created.status_code, 201, created.get_data(as_text=True)[:300])
            versions.append(created.get_json()['data'])
        return versions

    def delete_versions(self, name: str, body):
        return self.client.delete(f'/api/snapshots/{name}/versions', json=body)

    def delete_version(self, name: str, version_id: str, body=None):
        return self.client.delete(f'/api/snapshots/{name}/versions/{version_id}', json=body)

    def purge(self, body):
        return self.client.delete('/api/admin/snapshot-history/orphans', json=body)

    def object_path(self, content: str) -> Path:
        return self.sandbox.history.object_path(hashlib.sha256(content.encode('utf-8')).hexdigest())

    def assert_code(self, response, status: int, code: str | None):
        self.assertEqual(response.status_code, status, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json().get('code'), code)

    def age_orphan(self, snapshot_id: str, days: int = 3) -> None:
        with self.sandbox.db.get_db_session() as session:
            session.execute(
                update(SnapshotStateRow)
                .where(SnapshotStateRow.namespace == self.sandbox.state.namespace,
                       SnapshotStateRow.snapshot_id == snapshot_id)
                .values(missing_since=datetime.now(timezone.utc) - timedelta(days=days))
            )

    def gc_failure(self, failure: str):
        """Inject a non-ENOENT failure into the trash move, the trash unlink or the GC DB step."""
        trash_dir = self.sandbox.history.trash_dir
        if failure == 'move':
            real_rename = os.rename

            def failing_rename(source, destination):
                if Path(destination).parent == trash_dir:
                    raise PermissionError(errno.EACCES, 'Permission denied')
                return real_rename(source, destination)

            return mock.patch('services.snapshot_history_service.os.rename', side_effect=failing_rename)
        if failure == 'unlink':
            real_unlink = os.unlink

            def failing_unlink(path, *args, **kwargs):
                if Path(path).parent == trash_dir:
                    raise OSError(errno.EIO, 'Input/output error')
                return real_unlink(path, *args, **kwargs)

            return mock.patch('services.snapshot_history_service.os.unlink', side_effect=failing_unlink)
        real_delete = history_module.delete

        def failing_delete(target, *args, **kwargs):
            if target is HistoryObject:
                raise OperationalError('DELETE FROM history_objects', {}, Exception('disk I/O error'))
            return real_delete(target, *args, **kwargs)

        return mock.patch('services.snapshot_history_service.delete', side_effect=failing_delete)


class VersionDeletionRouteTest(HistoryRouteTestCase):
    def test_delete_routes_answer_the_contract_and_clamp_count(self):
        ids = [version['version_id'] for version in self.build_history('contract', 4)]

        oldest = self.delete_versions(
            'contract', {'mode': 'oldest', 'count': 1, 'expected_head': ids[3], 'expected_total': 4},
        )
        self.assertEqual(oldest.status_code, 200, oldest.get_data(as_text=True)[:300])
        self.assertEqual(oldest.get_json()['data'], {'deleted': 1, 'head': {'version_id': ids[3], 'seq': 4}})

        single = self.delete_version('contract', ids[3], {'expected_head': ids[3]})
        self.assertEqual(single.get_json()['data'], {'deleted': 1, 'head': {'version_id': ids[2], 'seq': 3}})
        bodyless = self.client.delete(f'/api/snapshots/contract/versions/{ids[1]}')
        self.assertEqual(bodyless.get_json()['data'], {'deleted': 1, 'head': {'version_id': ids[2], 'seq': 3}})

        clamped = self.delete_versions('contract', {'mode': 'newest', 'count': 99})
        self.assertEqual(clamped.get_json()['data'], {'deleted': 1, 'head': None})
        self.assertEqual(self.sandbox.version_count(), 0)
        self.assertEqual(self.sandbox.object_count(), 0)

        empty = self.delete_versions('contract', {'mode': 'all'})
        self.assertEqual(empty.get_json()['data'], {'deleted': 0, 'head': None})
        listing = self.client.get('/api/snapshots/contract/versions').get_json()['data']
        self.assertEqual(listing, {'items': [], 'total': 0})

    def test_request_validation_deletes_nothing(self):
        versions = self.build_history('validate', 3)

        for body in (
            {}, {'count': 1}, {'mode': 'bogus'}, {'mode': None}, {'mode': 5}, {'mode': ['all']},
            {'mode': 'oldest'}, {'mode': 'newest', 'count': None},
            {'mode': 'oldest', 'count': 0}, {'mode': 'oldest', 'count': -1}, {'mode': 'oldest', 'count': '1'},
            {'mode': 'oldest', 'count': True}, {'mode': 'oldest', 'count': 1.0},
            {'mode': 'oldest', 'count': 1, 'expected_total': None},
            {'mode': 'oldest', 'count': 1, 'expected_total': '3'},
            {'mode': 'newest', 'count': 1, 'expected_total': False},
            {'mode': 'newest', 'count': 1, 'expected_total': -1},
            {'mode': 'newest', 'count': 1, 'expected_total': 3.0},
            {'mode': 'all', 'count': 'x'}, {'mode': 'all', 'count': 0}, {'mode': 'all', 'expected_total': None},
            {'mode': 'all', 'expected_head': 5}, {'mode': 'all', 'expected_head': ['x']},
            {'mode': 'all', 'expected_unavailable': 5}, {'mode': 'all', 'expected_unavailable': None},
        ):
            with self.subTest(body=body):
                self.assert_code(self.delete_versions('validate', body), 400, 'validation_error')
        for raw, content_type in (
            ('', None), ('[1]', 'application/json'), ('{bad', 'application/json'), ('"all"', 'application/json'),
            ('null', 'application/json'), ('mode=all', 'application/x-www-form-urlencoded'),
        ):
            with self.subTest(raw=raw):
                response = self.client.delete('/api/snapshots/validate/versions', data=raw, content_type=content_type)
                self.assert_code(response, 400, 'invalid_json')
        single = f"/api/snapshots/validate/versions/{versions[0]['version_id']}"
        for raw in ('[1]', '{bad', '"x"'):
            with self.subTest(single=raw):
                response = self.client.delete(single, data=raw, content_type='application/json')
                self.assert_code(response, 400, 'invalid_json')
        for body in ({'expected_head': 5}, {'expected_head': True}, {'expected_head': {}}):
            with self.subTest(single=body):
                self.assert_code(self.client.delete(single, json=body), 400, 'validation_error')
        self.assertEqual(self.sandbox.version_count(), 3)

        accepted = self.delete_versions('validate', {'mode': 'all', 'count': 1, 'expected_total': 99})
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.get_json()['data'], {'deleted': 3, 'head': None})

    def test_expected_head_guards_both_delete_routes(self):
        ids = [version['version_id'] for version in self.build_history('heads', 3)]

        with self.assertNoLogs('app', level='ERROR'), self.assertNoLogs('database.session', level='ERROR'):
            for expected in ('another-version', None):
                with self.subTest(expected=expected):
                    self.assert_code(self.delete_version('heads', ids[0], {'expected_head': expected}), 409,
                                     'version_conflict')
                    self.assert_code(
                        self.delete_versions('heads', {'mode': 'oldest', 'count': 1, 'expected_head': expected}),
                        409, 'version_conflict',
                    )
                    self.assert_code(self.delete_versions('heads', {'mode': 'all', 'expected_head': expected}), 409,
                                     'version_conflict')
        self.assertEqual(self.sandbox.version_count(), 3)

        self.assertEqual(self.delete_version('heads', ids[0], {'expected_head': ids[2]}).status_code, 200)
        self.assertEqual(
            self.delete_versions('heads', {'mode': 'oldest', 'count': 1, 'expected_head': ids[2]}).status_code, 200,
        )
        self.assertEqual(self.delete_versions('heads', {'mode': 'all'}).status_code, 200)
        self.assertEqual(self.sandbox.version_count(), 0)

        self.assertEqual(self.delete_versions('heads', {'mode': 'all', 'expected_head': None}).get_json()['data'],
                         {'deleted': 0, 'head': None})
        self.assert_code(self.delete_versions('heads', {'mode': 'all', 'expected_head': ids[2]}), 409,
                         'version_conflict')
        self.assert_code(self.delete_version('heads', ids[2], {'expected_head': None}), 404, 'version_not_found')

    def test_expected_total_guards_oldest_and_newest(self):
        self.build_history('totals', 3)

        for body in ({'mode': 'oldest', 'count': 1, 'expected_total': 2},
                     {'mode': 'newest', 'count': 1, 'expected_total': 4}):
            with self.subTest(body=body):
                self.assert_code(self.delete_versions('totals', body), 409, 'version_conflict')
        self.assertEqual(self.sandbox.version_count(), 3)

        matched = self.delete_versions('totals', {'mode': 'newest', 'count': 1, 'expected_total': 3})
        self.assertEqual(matched.get_json()['data']['deleted'], 1)
        omitted = self.delete_versions('totals', {'mode': 'oldest', 'count': 1})
        self.assertEqual(omitted.get_json()['data']['deleted'], 1)
        self.assertEqual(self.sandbox.version_count(), 1)

    def test_commit_with_expected_head_null_succeeds_only_without_a_head(self):
        self.build_history('headless', 2)
        self.upload('headless', 'r9.cfg', config_for('headless-r9'))
        self.assert_code(self.commit('headless', {'message': 'stale', 'expected_head': None}), 409, 'version_conflict')

        self.assertEqual(self.delete_versions('headless', {'mode': 'all'}).status_code, 200)
        state = self.version_state('headless').get_json()['data']
        self.assertIsNone(state['head'])
        self.assertTrue(state['uncommitted'])
        self.assert_code(self.commit('headless', {'message': 'stale', 'expected_head': 'gone'}), 409,
                         'version_conflict')

        created = self.commit('headless', {'message': 'fresh start', 'expected_head': None})

        self.assertEqual(created.status_code, 201, created.get_data(as_text=True)[:300])
        version = created.get_json()['data']
        self.assertEqual((version['seq'], version['kind'], version['parent'], version['restored_from']),
                         (3, 'manual', None, None))

    def test_unknown_versions_and_snapshots_are_distinct_404s(self):
        versions = self.build_history('one', 2)
        self.build_history('two', 1)

        self.assert_code(self.delete_version('one', UNKNOWN_VERSION_ID), 404, 'version_not_found')
        self.assert_code(self.delete_version('two', versions[1]['version_id']), 404, 'version_not_found')
        self.assert_code(self.delete_version('nowhere', UNKNOWN_VERSION_ID), 404, 'snapshot_not_found')
        self.assert_code(self.delete_versions('nowhere', {'mode': 'all'}), 404, 'snapshot_not_found')
        self.assertEqual(self.delete_versions('bad%20name', {'mode': 'all'}).status_code, 400)
        self.assertEqual(self.sandbox.version_count(), 3)

    def test_delete_and_admin_routes_are_matched_by_endpoint_without_the_batfish_lock(self):
        for name in ('files-x', 'artifacts-x'):
            for path in (f'/api/snapshots/{name}/versions', f'/api/snapshots/{name}/versions/{UNKNOWN_VERSION_ID}'):
                with self.subTest(path=path):
                    with app_module.app.test_request_context(path, method='DELETE'):
                        self.assertFalse(app_module.request_uses_batfish())
        for method, path in (('DELETE', '/api/admin/snapshot-history/orphans'),
                             ('GET', '/api/admin/snapshot-history/namespaces')):
            with self.subTest(path=path):
                with app_module.app.test_request_context(path, method=method):
                    self.assertFalse(app_module.request_uses_batfish())

        versions = self.build_history('files-x', 3)
        lock = mock.MagicMock()
        with mock.patch.object(app_module, 'batfish_request_lock', lock):
            single = self.delete_version('files-x', versions[0]['version_id'])
            multi = self.delete_versions('files-x', {'mode': 'all'})
            namespaces = self.client.get('/api/admin/snapshot-history/namespaces')
            orphans = self.purge({'older_than_days': 0})
        self.assertEqual([response.status_code for response in (single, multi, namespaces, orphans)],
                         [200, 200, 200, 200])
        lock.acquire.assert_not_called()

    def test_api_write_in_progress_answers_conflict_on_both_routes(self):
        versions = self.build_history('busy', 2)
        state = self.sandbox.state
        snapshot_id = self.sandbox.snapshot_id('busy')

        for key in (state.id_key(snapshot_id), state.dir_key(self.sandbox.snapshots_dir / 'busy')):
            with self.subTest(key=key[0]):
                state.begin_api_write(key)
                try:
                    self.assert_code(self.delete_version('busy', versions[0]['version_id']), 409, 'version_conflict')
                    self.assert_code(self.delete_versions('busy', {'mode': 'all'}), 409, 'version_conflict')
                finally:
                    state._finish_api_write(key)

        self.assertEqual(self.sandbox.version_count(), 2)

    def test_gc_failure_after_a_committed_oldest_deletion_still_answers_200(self):
        history = self.sandbox.history
        for failure in ('move', 'unlink', 'database'):
            with self.subTest(failure=failure):
                name = f'gc-{failure}'
                self.build_history(name, 3, rewrite=True)
                freed = [self.object_path(config_for(f'{name}-v{index}')) for index in (1, 2)]

                with self.gc_failure(failure), self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
                    response = self.delete_versions(name, {'mode': 'oldest', 'count': 2})

                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()['data']['deleted'], 2)
                self.assertEqual(len(self.sandbox.versions(self.sandbox.snapshot_id(name))), 1)
                self.assertEqual(len(logs.output), 1, logs.output)
                history.gc_unreferenced()
                self.assertEqual([path.exists() for path in freed], [False, False])
                self.assertEqual(list(history.trash_dir.iterdir()), [])
                self.assertTrue(self.object_path(config_for(f'{name}-v3')).exists())
        self.assertEqual(self.sandbox.object_count(), 3)

    def test_snapshot_recreated_before_the_deletion_hold_answers_500_without_writing(self):
        state = self.sandbox.state
        original_resolve = state.resolve_available_snapshot
        for route in ('single', 'all'):
            with self.subTest(route=route):
                name = f'reborn-{route}'
                versions = self.build_history(name, 2)
                old_id = self.sandbox.snapshot_id(name)

                def resolve_then_recreate(snapshot_dir, allowed_reason=None):
                    resolved = original_resolve(snapshot_dir, allowed_reason)
                    shutil.rmtree(snapshot_dir)
                    self.sandbox.create_snapshot(name)
                    return resolved

                with mock.patch.object(state, 'resolve_available_snapshot', side_effect=resolve_then_recreate), \
                        self.assertLogs('app', level='ERROR'):
                    if route == 'single':
                        response = self.delete_version(name, versions[0]['version_id'])
                    else:
                        response = self.delete_versions(name, {'mode': 'all'})

                self.assertEqual(response.status_code, 500)
                self.assertEqual(len(self.sandbox.versions(old_id)), 2)
                new_id = self.sandbox.snapshot_id(name)
                self.assertNotEqual(new_id, old_id)
                self.assertIsNone(self.sandbox.row(new_id))


class MissingObjectsDeletionRouteTest(HistoryRouteTestCase):
    LOST_EXTRA = 'hostname lost-extra\n'

    def mark_lost(self) -> str:
        self.sandbox.create_snapshot('lost', {'configs/r1.cfg': CONFIG_R1, 'configs/extra.cfg': self.LOST_EXTRA})
        self.sandbox.create_snapshot('kept', {'configs/r2.cfg': CONFIG_R2})
        self.version_state('lost')
        self.version_state('kept')
        for content in (CONFIG_R1, self.LOST_EXTRA):
            self.object_path(content).unlink()
        with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()
        return self.sandbox.snapshot_id('lost')

    def reset(self, name: str):
        return self.delete_versions(name, {'mode': 'all', 'expected_unavailable': 'missing_objects'})

    def test_delete_all_clears_the_mark_although_every_object_is_absent(self):
        snapshot_id = self.mark_lost()
        version_id = self.sandbox.versions(snapshot_id)[0]['version_id']
        for response in (
            self.delete_version('lost', version_id),
            self.delete_versions('lost', {'mode': 'oldest', 'count': 1}),
            self.delete_versions('lost', {'mode': 'newest', 'count': 1, 'expected_unavailable': 'missing_objects'}),
        ):
            self.assert_code(response, 503, 'versioning_unavailable')
            self.assertEqual(response.get_json()['details'], {'reason': 'missing_objects'})
        self.assert_code(self.delete_versions('lost', {'mode': 'all', 'expected_unavailable': 5}), 400,
                         'validation_error')
        self.assertEqual(self.sandbox.version_count(), 2)

        with self.assertNoLogs(HISTORY_LOGGER, level='ERROR'), self.assertNoLogs('database.session', level='ERROR'):
            reset = self.reset('lost')

        self.assertEqual(reset.status_code, 200, reset.get_data(as_text=True)[:300])
        self.assertEqual(reset.get_json()['data'], {'deleted': 1, 'head': None})
        self.assertIsNone(self.sandbox.state.unavailable_reason(snapshot_id, 'lost'))
        state = self.version_state('lost').get_json()['data']
        self.assertIsNone(state['head'])
        self.assertTrue(state['uncommitted'])
        self.assert_code(self.reset('lost'), 409, 'version_conflict')
        self.assertTrue(self.object_path(CONFIG_R2).exists())
        self.assertEqual(self.sandbox.object_count(), 1)

    def test_injected_commit_failure_answers_500_and_keeps_the_mark(self):
        snapshot_id = self.mark_lost()
        history = self.sandbox.history
        original_transaction = history._deletion_transaction

        def delete_then_fail(*args):
            original_transaction(*args)
            raise RuntimeError('commit failed')

        with mock.patch.object(history, '_deletion_transaction', side_effect=delete_then_fail), \
                self.assertLogs('app', level='ERROR'), self.assertLogs('database.session', level='ERROR'):
            response = self.reset('lost')

        self.assertEqual(response.status_code, 500)
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 1)
        blocked = self.version_state('lost')
        self.assert_code(blocked, 503, 'versioning_unavailable')
        self.assertEqual(blocked.get_json()['details'], {'reason': 'missing_objects'})

    def test_api_delete_of_a_marked_snapshot_purges_its_rows(self):
        snapshot_id = self.mark_lost()

        response = self.client.delete('/api/snapshots/lost')

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.sandbox.row(snapshot_id))
        self.assertEqual(self.sandbox.versions(snapshot_id), [])
        self.assertIsNone(self.sandbox.state.unavailable_reason(snapshot_id))
        with self.assertNoLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()

    def test_accepted_store_loss_count_reaches_zero_after_the_resets(self):
        self.sandbox.create_snapshot('alpha', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('beta', {'configs/r2.cfg': CONFIG_R2})
        self.version_state('alpha')
        self.version_state('beta')
        shutil.rmtree(self.sandbox.history.objects_dir)
        self.sandbox.settings.HISTORY_ACCEPT_STORE_LOSS = self.sandbox.history.db_id
        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            self.restart()
        self.assertTrue(any('2 snapshots are marked missing_objects' in line for line in logs.output))

        for name in ('alpha', 'beta'):
            response = self.reset(name)
            self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])

        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            self.restart()
        guard = [line for line in logs.output if 'loss guard is' in line]
        self.assertEqual(len(guard), 1)
        self.assertIn('0 snapshots are marked missing_objects', guard[0])
        self.assertIsNone(self.sandbox.state.global_unavailable_reason())
        self.assertEqual(self.version_state('alpha').status_code, 200)


class UnavailableDeletionRouteTest(HistoryRouteTestCase):
    def assert_deletes_unavailable(self, name: str, reason: str):
        responses = {
            'delete-single': self.delete_version(name, UNKNOWN_VERSION_ID),
            'delete-oldest': self.delete_versions(name, {'mode': 'oldest', 'count': 1}),
            'delete-all': self.delete_versions(name, {'mode': 'all'}),
            'delete-all-marked': self.delete_versions(name, {'mode': 'all', 'expected_unavailable': 'missing_objects'}),
            'admin-namespaces': self.client.get('/api/admin/snapshot-history/namespaces'),
            'admin-orphans': self.purge({'older_than_days': 0}),
            'admin-namespace-purge': self.purge({'namespace': 'other-ns', 'confirm': 'other-ns'}),
        }
        for route, response in responses.items():
            with self.subTest(route=route, reason=reason):
                self.assert_code(response, 503, 'versioning_unavailable')
                self.assertEqual(response.get_json()['details'], {'reason': reason})

    def test_storage_fault_blocks_deletion_and_admin_routes(self):
        self.sandbox.create_snapshot('stored', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('other', {'configs/r2.cfg': CONFIG_R2})
        self.version_state('stored')
        self.version_state('other')
        shutil.rmtree(self.sandbox.history.objects_dir)
        with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()

        self.assert_deletes_unavailable('stored', 'storage')
        self.assertEqual(self.sandbox.version_count(), 2)
        with self.assertLogs('app', level='WARNING'):
            self.assertEqual(self.client.delete('/api/snapshots/stored').status_code, 200)
        self.assertEqual(self.sandbox.version_count(), 2)

    def test_invalid_namespace_blocks_the_admin_routes_and_keeps_the_rows(self):
        self.sandbox.create_snapshot('kept-ns')
        self.version_state('kept-ns')
        snapshot_id = self.sandbox.snapshot_id('kept-ns')
        marker_namespace = self.sandbox.state.namespace
        marker = self.sandbox.snapshots_dir / STORE_MARKER_FILENAME
        marker_text = marker.read_text(encoding='utf-8')
        cases = ['deployment-id', 'corrupt-marker'] + ([] if IS_ROOT else ['unreadable-marker'])
        for case in cases:
            with self.subTest(case=case):
                self.sandbox.settings.DEPLOYMENT_ID = 'result_cache' if case == 'deployment-id' else ''
                if case == 'corrupt-marker':
                    marker.write_text('{corrupt', encoding='utf-8')
                elif case == 'unreadable-marker':
                    os.chmod(marker, 0o000)
                try:
                    with self.assertLogs(STATE_LOGGER, level='ERROR'):
                        self.restart()
                    self.assert_deletes_unavailable('kept-ns', 'namespace')
                    purge = self.purge({'namespace': marker_namespace, 'confirm': marker_namespace})
                    self.assert_code(purge, 503, 'versioning_unavailable')
                    self.assertIsNotNone(self.sandbox.row(snapshot_id, namespace=marker_namespace))
                finally:
                    os.chmod(marker, 0o644)
                    marker.write_text(marker_text, encoding='utf-8')

        self.sandbox.settings.DEPLOYMENT_ID = ''
        self.restart()
        self.assertEqual(self.sandbox.state.namespace, marker_namespace)
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 1)

    def test_database_unavailable_blocks_deletion_and_admin_routes(self):
        self.sandbox.create_snapshot('no-db')
        database = self.sandbox.db
        self.sandbox.db = None
        try:
            self.restart()
            self.assert_deletes_unavailable('no-db', 'database')
        finally:
            self.sandbox.db = database


class SnapshotDeletePurgeRouteTest(HistoryRouteTestCase):
    def test_delete_purges_rows_objects_and_the_staging_copy(self):
        self.build_history('purged', 2)
        snapshot_id = self.sandbox.snapshot_id('purged')
        staging = self.sandbox.state.staging_root() / snapshot_id / 'purged'
        write_file(staging / 'configs' / 'r1.cfg', 'staged copy\n')
        objects = [self.object_path(config_for(f'purged-v{index}')) for index in (1, 2)]
        self.assertEqual([path.exists() for path in objects], [True, True])

        response = self.client.delete('/api/snapshots/purged')

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.sandbox.row(snapshot_id))
        self.assertEqual(self.sandbox.version_count(), 0)
        self.assertFalse(staging.parent.exists())
        self.assertEqual([path.exists() for path in objects], [False, False])
        self.assertEqual(self.sandbox.object_count(), 0)

    def test_deleting_an_unopened_copy_keeps_the_original_history(self):
        self.build_history('original', 2)
        original_id = self.sandbox.snapshot_id('original')
        shutil.copytree(self.sandbox.snapshots_dir / 'original', self.sandbox.snapshots_dir / 'copy')

        response = self.client.delete('/api/snapshots/copy')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sandbox.row(original_id).snapshot_name, 'original')
        self.assertEqual(len(self.sandbox.versions(original_id)), 2)
        self.assertTrue(self.object_path(config_for('original-v2')).exists())
        self.assertEqual(self.version_state('original').status_code, 200)

    def test_row_renamed_to_a_copy_between_rmtree_and_the_purge_is_kept(self):
        self.build_history('source', 1)
        snapshot_id = self.sandbox.snapshot_id('source')
        state = self.sandbox.state
        history = self.sandbox.history
        state.mark_versioning_unavailable(state.id_key(snapshot_id), 'missing_objects')
        shutil.copytree(self.sandbox.snapshots_dir / 'source', self.sandbox.snapshots_dir / 'twin')
        original_purge = history.delete_all_for_snapshot

        def resolve_twin_first(purged_id, deleted_name, *args):
            state.resolve_snapshot_identity(self.sandbox.snapshots_dir / 'twin')
            return original_purge(purged_id, deleted_name, *args)

        with mock.patch.object(history, 'delete_all_for_snapshot', side_effect=resolve_twin_first), \
                self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            response = self.client.delete('/api/snapshots/source')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(logs.output), 1, logs.output)
        self.assertIn('twin', logs.output[0])
        self.assertEqual(self.sandbox.row(snapshot_id).snapshot_name, 'twin')
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 1)
        self.assertEqual(state.unavailable_reason(snapshot_id, 'twin'), 'missing_objects')

    def test_database_failure_in_the_purge_still_answers_200(self):
        self.build_history('fragile', 1)
        self.build_history('present', 1)
        snapshot_id = self.sandbox.snapshot_id('fragile')
        service = self.batfish_service
        service.network_name = app_module.config.BATFISH_NETWORK
        service.current_snapshot_name = 'fragile'
        service._initialized = True
        failure = OperationalError('DELETE FROM snapshot_states', {}, Exception('database is locked'))

        with mock.patch.object(self.sandbox.history, '_purge_deleted_snapshot_rows', side_effect=failure), \
                self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs, \
                self.assertLogs('database.session', level='ERROR'):
            response = self.client.delete('/api/snapshots/fragile')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(logs.output), 1, logs.output)
        self.assertIsNone(service.current_snapshot_name)
        self.assertFalse(service._initialized)
        self.assertIsNotNone(self.sandbox.row(snapshot_id))
        self.sandbox.history.scan_orphans()
        self.assertIsNotNone(self.sandbox.row(snapshot_id).missing_since)

    def test_gc_failure_after_the_purge_still_answers_200(self):
        history = self.sandbox.history
        for failure in ('move', 'unlink', 'database'):
            with self.subTest(failure=failure):
                name = f'purge-{failure}'
                self.build_history(name, 1)
                snapshot_id = self.sandbox.snapshot_id(name)
                stored = self.object_path(config_for(f'{name}-v1'))

                with self.gc_failure(failure), self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
                    response = self.client.delete(f'/api/snapshots/{name}')

                self.assertEqual(response.status_code, 200)
                self.assertIsNone(self.sandbox.row(snapshot_id))
                self.assertEqual(self.sandbox.versions(snapshot_id), [])
                self.assertEqual(len(logs.output), 1, logs.output)
                history.gc_unreferenced()
                self.assertFalse(stored.exists())
                self.assertEqual(list(history.trash_dir.iterdir()), [])
        self.assertEqual(self.sandbox.object_count(), 0)

    def test_purges_remove_objects_only_through_the_trash_step(self):
        for purge in ('snapshot-delete', 'orphan-purge', 'namespace-purge'):
            with self.subTest(purge=purge):
                shared = config_for(f'shared-{purge}')
                donor = f'donor-{purge}'
                adopter = f'adopter-{purge}'
                if purge == 'namespace-purge':
                    self.sandbox.settings.DEPLOYMENT_ID = 'donor-ns'
                    self.restart()
                self.sandbox.create_snapshot(donor, {'configs/shared.cfg': shared})
                self.version_state(donor)
                if purge == 'namespace-purge':
                    self.sandbox.settings.DEPLOYMENT_ID = ''
                    self.restart()
                self.sandbox.create_snapshot(adopter, {'configs/own.cfg': f"hostname {adopter}\n"})
                self.version_state(adopter)
                self.upload(adopter, 'shared.cfg', shared)
                adopter_id = self.sandbox.snapshot_id(adopter)
                history = self.sandbox.history
                if purge == 'orphan-purge':
                    donor_id = self.sandbox.snapshot_id(donor)
                    shutil.rmtree(self.sandbox.snapshots_dir / donor)
                    history.scan_orphans()
                    self.age_orphan(donor_id)
                commits = []
                original_gc = history.gc_unreferenced

                def commit_then_collect(candidates=None, skip_grace=False, db=None):
                    if not commits:
                        commits.append(history.commit(adopter_id, self.sandbox.snapshots_dir / adopter, 'adopt'))
                    return original_gc(candidates, skip_grace=skip_grace, db=db)

                with mock.patch.object(history, 'gc_unreferenced', side_effect=commit_then_collect):
                    if purge == 'snapshot-delete':
                        response = self.client.delete(f'/api/snapshots/{donor}')
                    elif purge == 'orphan-purge':
                        response = self.purge({'older_than_days': 1})
                    else:
                        response = self.purge({'namespace': 'donor-ns', 'confirm': 'donor-ns'})

                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                if purge == 'orphan-purge':
                    self.assertEqual(response.get_json()['data'], {'purged': 1, 'last_seen_at': None})
                if purge == 'namespace-purge':
                    self.assertEqual(response.get_json()['data']['purged'], 1)
                self.assertEqual(commits[0]['kind'], 'manual')
                self.assertTrue(self.object_path(shared).exists())
                for entry in history.get_version(adopter_id, commits[0]['version_id'])['files']:
                    self.assertTrue(history.object_path(entry['sha256']).exists())


class AdminSnapshotHistoryRouteTest(HistoryRouteTestCase):
    def namespace_row_count(self, namespace: str) -> int:
        with self.sandbox.db.get_db_session() as session:
            return session.execute(
                select(func.count()).select_from(SnapshotStateRow).where(SnapshotStateRow.namespace == namespace)
            ).scalar_one()

    def test_namespace_list_reports_every_namespace(self):
        self.build_history('listed', 1)
        now = datetime.now(timezone.utc)
        with self.sandbox.db.get_db_session() as session:
            session.add(HistoryNamespace(
                namespace='other-ns', first_seen_at=now - timedelta(days=9), last_seen_at=now - timedelta(days=2),
            ))
            for name in ('x', 'y'):
                session.add(SnapshotStateRow(
                    namespace='other-ns', snapshot_id=str(uuid.uuid4()), snapshot_name=name, next_seq=1,
                    pending_external=False,
                ))

        response = self.client.get('/api/admin/snapshot-history/namespaces')

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        items = {item['namespace']: item for item in response.get_json()['data']['items']}
        self.assertEqual(set(items), {self.sandbox.state.namespace, 'other-ns'})
        current = items[self.sandbox.state.namespace]
        self.assertEqual((current['current'], current['rows']), (True, 1))
        self.assertTrue(current['first_seen_at'] and current['last_seen_at'])
        other = items['other-ns']
        self.assertEqual(set(other), {'namespace', 'current', 'first_seen_at', 'last_seen_at', 'rows'})
        self.assertEqual((other['current'], other['rows']), (False, 2))
        self.assertEqual(other['last_seen_at'], (now - timedelta(days=2)).isoformat())

    def test_orphan_purge_removes_only_expired_rows_that_are_still_orphaned(self):
        self.build_history('gone', 2)
        self.build_history('back', 1)
        self.build_history('present', 1)
        gone_id = self.sandbox.snapshot_id('gone')
        back_id = self.sandbox.snapshot_id('back')
        shutil.rmtree(self.sandbox.snapshots_dir / 'gone')
        self.sandbox.history.scan_orphans()

        recent = self.purge({'older_than_days': 1})
        self.assertEqual(recent.get_json()['data'], {'purged': 0, 'last_seen_at': None})
        self.age_orphan(gone_id)
        self.age_orphan(back_id)

        response = self.purge({'older_than_days': 1})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['data'], {'purged': 1, 'last_seen_at': None})
        self.assertIsNone(self.sandbox.row(gone_id))
        self.assertEqual(self.sandbox.versions(gone_id), [])
        self.assertFalse(self.object_path(config_for('gone-v2')).exists())
        self.assertIsNotNone(self.sandbox.row(back_id))
        self.assertEqual(len(self.sandbox.versions(back_id)), 1)
        self.assertEqual(self.version_state('present').status_code, 200)

    def assert_changed_row_is_skipped(self, change: str):
        history = self.sandbox.history
        self.build_history('present', 1)
        self.build_history('drifting', 1)
        snapshot_id = self.sandbox.snapshot_id('drifting')
        shutil.rmtree(self.sandbox.snapshots_dir / 'drifting')
        self.age_orphan(snapshot_id)
        values = {'snapshot_name': 'drifted'} if change == 'name' else {'missing_since': datetime.now(timezone.utc)}
        original_view = history.read_store_view

        def view_then_change():
            view = original_view()
            with self.sandbox.db.get_db_session() as session:
                session.execute(
                    update(SnapshotStateRow).where(SnapshotStateRow.snapshot_id == snapshot_id).values(**values)
                )
            return view

        with mock.patch.object(history, 'read_store_view', side_effect=view_then_change), \
                self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            response = self.purge({'older_than_days': 1})

        self.assertEqual(response.get_json()['data'], {'purged': 0, 'last_seen_at': None})
        self.assertEqual(len([line for line in logs.output if 'changed during the purge' in line]), 1, logs.output)
        self.assertIsNotNone(self.sandbox.row(snapshot_id))
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 1)

    def test_orphan_purge_skips_a_row_renamed_between_its_holds(self):
        self.assert_changed_row_is_skipped('name')

    def test_orphan_purge_skips_a_row_whose_missing_since_changed_between_its_holds(self):
        self.assert_changed_row_is_skipped('missing_since')

    def test_orphan_purge_purges_nothing_when_a_directory_appears_meanwhile(self):
        history = self.sandbox.history
        self.build_history('present', 1)
        self.build_history('wanderer', 2)
        snapshot_id = self.sandbox.snapshot_id('wanderer')
        home = self.sandbox.snapshots_dir / 'wanderer'
        away = self.sandbox.root / 'wanderer-away'
        shutil.move(str(home), str(away))
        history.scan_orphans()
        self.age_orphan(snapshot_id)
        original_view = history.read_store_view

        def view_then_move_back():
            view = original_view()
            shutil.move(str(away), str(home))
            return view

        with mock.patch.object(history, 'read_store_view', side_effect=view_then_move_back), \
                self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            response = self.purge({'older_than_days': 1})

        self.assertEqual(response.get_json()['data'], {'purged': 0, 'last_seen_at': None})
        self.assertEqual(len([line for line in logs.output if 'snapshot store changed' in line]), 1, logs.output)
        self.assertIsNotNone(self.sandbox.row(snapshot_id))
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 2)
        self.assertEqual(self.version_state('wanderer').status_code, 200)

    def test_namespace_purge_removes_every_row_and_the_staging_leftover(self):
        self.build_history('mine', 1)
        marker_namespace = self.sandbox.state.namespace
        self.sandbox.settings.DEPLOYMENT_ID = 'other-ns'
        self.restart()
        self.sandbox.create_snapshot('theirs', {'configs/r1.cfg': 'hostname theirs\n'})
        self.version_state('theirs')
        self.version_state('mine')
        self.sandbox.settings.DEPLOYMENT_ID = ''
        self.restart()
        self.assertEqual(self.sandbox.state.namespace, marker_namespace)
        leftover = self.sandbox.data_dir / 'other-ns' / 'staging' / 'crashed' / 'r1.cfg'
        write_file(leftover, 'staged copy\n')
        theirs_object = self.object_path('hostname theirs\n')
        self.assertTrue(theirs_object.exists())

        response = self.purge({'namespace': 'other-ns', 'confirm': 'other-ns'})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        data = response.get_json()['data']
        self.assertEqual(data['purged'], 2)
        self.assertTrue(data['last_seen_at'].startswith('20'))
        self.assertEqual(self.namespace_row_count('other-ns'), 0)
        with self.sandbox.db.get_db_session() as session:
            self.assertIsNone(session.get(HistoryNamespace, 'other-ns'))
            self.assertEqual(session.execute(
                select(func.count()).select_from(SnapshotVersion).where(SnapshotVersion.namespace == 'other-ns')
            ).scalar_one(), 0)
        self.assertFalse((self.sandbox.data_dir / 'other-ns' / 'staging').exists())
        self.assertFalse(theirs_object.exists())
        self.assertTrue(self.object_path(config_for('mine-v1')).exists())
        listed = self.client.get('/api/admin/snapshot-history/namespaces').get_json()['data']['items']
        self.assertEqual([item['namespace'] for item in listed], [marker_namespace])
        self.assert_code(self.purge({'namespace': 'other-ns', 'confirm': 'other-ns'}), 404, 'namespace_not_found')
        self.assertEqual(self.version_state('mine').status_code, 200)

    def use_case_insensitive_namespace_columns(self) -> None:
        """Move the sandbox to a database whose namespace columns compare with NOCASE, like a case-insensitive collation."""
        columns = [model.__table__.c.namespace for model in (HistoryNamespace, SnapshotStateRow, SnapshotVersion)]
        database = DatabaseManager(f"sqlite:///{self.sandbox.root / 'nocase.db'}")
        for column in columns:
            column.type.collation = 'NOCASE'
        try:
            database.create_all()
        finally:
            for column in columns:
                column.type.collation = None
        self.addCleanup(self.sandbox.db.engine.dispose)
        self.sandbox.db = database
        self.restart()

    def test_case_variant_of_the_current_namespace_is_refused_where_the_database_ignores_case(self):
        self.use_case_insensitive_namespace_columns()
        self.build_history('live', 2)
        current = self.sandbox.state.namespace
        variant = current.upper()
        self.assertNotEqual(variant, current)
        self.assertEqual(self.namespace_row_count(variant), 1)
        snapshot_id = self.sandbox.snapshot_id('live')
        objects = [self.object_path(config_for(f'live-v{index}')) for index in (1, 2)]
        exact_refusal = self.purge({'namespace': current, 'confirm': current})

        response = self.purge({'namespace': variant, 'confirm': variant})

        self.assert_code(response, 400, 'validation_error')
        self.assertEqual(response.get_json(), exact_refusal.get_json())
        self.assertEqual(response.get_json()['details'], {'field': 'namespace'})
        self.assertIsNotNone(self.sandbox.row(snapshot_id))
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 2)
        self.assertEqual([path.exists() for path in objects], [True, True])
        self.assertEqual(self.sandbox.object_count(), 2)
        with self.sandbox.db.get_db_session() as session:
            self.assertIsNotNone(session.get(HistoryNamespace, current))

    def test_case_variant_namespace_with_its_own_rows_is_purged_where_the_database_respects_case(self):
        self.build_history('live', 1)
        current = self.sandbox.state.namespace
        variant = current.upper()
        self.assertNotEqual(variant, current)
        snapshot_id = self.sandbox.snapshot_id('live')
        loose = self.sandbox.root / 'variant.cfg'
        loose.write_text(config_for('variant'), encoding='utf-8')
        variant_sha = self.sandbox.history.put_object(loose)
        now = datetime.now(timezone.utc)
        with self.sandbox.db.get_db_session() as session:
            session.add(HistoryNamespace(namespace=variant, first_seen_at=now, last_seen_at=now))
            session.add(SnapshotStateRow(
                namespace=variant, snapshot_id=snapshot_id, snapshot_name='live', next_seq=2, pending_external=False,
            ))
            session.add(HistoryObject(sha256=variant_sha, size=loose.stat().st_size))
            version = SnapshotVersion(
                version_id=str(uuid.uuid4()), snapshot_id=snapshot_id, namespace=variant, seq=1,
                content_hash='0' * 64, kind='baseline', message='Initial state', file_count=1,
                total_bytes=loose.stat().st_size,
            )
            session.add(version)
            session.flush()
            session.add(SnapshotVersionFile(
                version_id=version.version_id, path='configs/r1.cfg', sha256=variant_sha, size=loose.stat().st_size,
            ))

        response = self.purge({'namespace': variant, 'confirm': variant})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['data']['purged'], 1)
        self.assertEqual(self.namespace_row_count(variant), 0)
        self.assertFalse(self.sandbox.history.object_path(variant_sha).exists())
        self.assertIsNotNone(self.sandbox.row(snapshot_id))
        self.assertEqual(len(self.sandbox.versions(snapshot_id)), 1)
        self.assertTrue(self.object_path(config_for('live-v1')).exists())
        with self.sandbox.db.get_db_session() as session:
            self.assertIsNotNone(session.get(HistoryNamespace, current))

    def test_purging_the_store_directory_namespace_keeps_a_snapshot_named_staging(self):
        store = self.sandbox.data_dir / 'snapshots'
        store.mkdir()
        self.sandbox.snapshot_service.snapshots_dir = store
        self.sandbox.snapshots_dir = store
        self.restart()
        self.sandbox.create_snapshot('staging', {'configs/r1.cfg': 'hostname staging\n'})
        now = datetime.now(timezone.utc)
        with self.sandbox.db.get_db_session() as session:
            session.add(HistoryNamespace(namespace='snapshots', first_seen_at=now, last_seen_at=now))
            session.add(SnapshotStateRow(
                namespace='snapshots', snapshot_id=str(uuid.uuid4()), snapshot_name='old', next_seq=1,
                pending_external=False,
            ))

        with self.assertLogs(HISTORY_LOGGER, level='WARNING') as logs:
            response = self.purge({'namespace': 'snapshots', 'confirm': 'snapshots'})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['data']['purged'], 1)
        self.assertTrue(any('is not removed because' in line for line in logs.output))
        self.assertEqual(self.namespace_row_count('snapshots'), 0)
        self.assertTrue((store / 'staging' / 'configs' / 'r1.cfg').exists())
        self.assertEqual(self.version_state('staging').status_code, 200)

    def test_admin_purge_request_validation(self):
        self.build_history('validated', 1)
        current = self.sandbox.state.namespace
        sentinel = self.sandbox.root / 'escape' / 'staging' / 'keep.cfg'
        write_file(sentinel, 'keep\n')

        for body in (
            {}, {'confirm': 'x'},
            {'older_than_days': -1}, {'older_than_days': True}, {'older_than_days': 1.5},
            {'older_than_days': '1'}, {'older_than_days': None}, {'older_than_days': 1, 'confirm': 5},
            {'namespace': 5, 'confirm': 5}, {'namespace': None, 'confirm': None},
            {'namespace': '../escape', 'confirm': '../escape'}, {'namespace': 'x' * 65, 'confirm': 'x' * 65},
            {'namespace': '', 'confirm': ''},
            {'namespace': 'other-ns'}, {'namespace': 'other-ns', 'confirm': 'other'},
            {'namespace': 'other-ns', 'confirm': 5},
            {'namespace': 'other-ns', 'confirm': 'other-ns', 'older_than_days': 'bad'},
            {'namespace': current, 'confirm': current},
        ):
            with self.subTest(body=body):
                self.assert_code(self.purge(body), 400, 'validation_error')
        for raw, content_type in (('', None), ('[1]', 'application/json'), ('{bad', 'application/json')):
            with self.subTest(raw=raw):
                response = self.client.delete('/api/admin/snapshot-history/orphans', data=raw, content_type=content_type)
                self.assert_code(response, 400, 'invalid_json')
        self.assert_code(self.purge({'namespace': 'unknown-ns', 'confirm': 'unknown-ns'}), 404, 'namespace_not_found')
        self.assert_code(self.purge({'namespace': 'unknown-ns', 'confirm': 'unknown-ns', 'older_than_days': 3}), 404,
                         'namespace_not_found')

        accepted = self.purge({'older_than_days': 0})

        self.assertEqual(accepted.get_json()['data'], {'purged': 0, 'last_seen_at': None})
        self.assertTrue(sentinel.exists())
        self.assertEqual(len(self.sandbox.versions(self.sandbox.snapshot_id('validated'))), 1)


class PeriodicMaintenanceRouteTest(HistoryRouteTestCase):
    def namespace_last_seen(self):
        with self.sandbox.db.get_db_session() as session:
            return session.get(HistoryNamespace, self.sandbox.state.namespace).last_seen_at

    def test_hourly_trigger_runs_in_a_daemon_thread_with_its_own_engine(self):
        history = self.sandbox.history
        self.build_history('periodic', 1)
        loose = self.sandbox.root / 'loose.cfg'
        loose.write_text('unreferenced object\n', encoding='utf-8')
        leftover = history.object_path(history.put_object(loose))
        before = self.namespace_last_seen()
        managers = []
        calls = []
        original_factory = self.sandbox.db.create_null_pool_manager
        original_gc = history.gc_unreferenced

        def capture_manager():
            manager = original_factory()
            managers.append(manager)
            return manager

        def spy_gc(*args, **kwargs):
            calls.append((threading.current_thread(), kwargs.get('db')))
            return original_gc(*args, **kwargs)

        history._last_periodic_run -= history_module.PERIODIC_MAINTENANCE_INTERVAL_SECONDS + 1
        lock = mock.MagicMock()
        with mock.patch.object(self.sandbox.db, 'create_null_pool_manager', side_effect=capture_manager), \
                mock.patch.object(history, 'gc_unreferenced', side_effect=spy_gc), \
                mock.patch.object(app_module, 'batfish_request_lock', lock):
            response = self.client.get('/api/snapshots')
            history.periodic_worker.join(20)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(history.periodic_worker.is_alive())
        worker_thread, worker_db = calls[0]
        self.assertIsNot(worker_thread, threading.main_thread())
        self.assertTrue(worker_thread.daemon)
        self.assertIs(worker_db, managers[0])
        self.assertIsInstance(managers[0].engine.pool, NullPool)
        with managers[0].engine.connect() as connection:
            self.assertEqual(connection.exec_driver_sql('PRAGMA foreign_keys').scalar(), 1)
        managers[0].engine.dispose()
        self.assertFalse(leftover.exists())
        self.assertGreater(self.namespace_last_seen(), before)
        lock.acquire.assert_not_called()
        self.assertFalse(history.schedule_periodic_gc())


def tree_entries(root: Path) -> dict:
    """Describe every entry below root without following symlinks: type plus inode and content, or target."""
    entries = {}
    for directory, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(directory) / name
            info = os.lstat(path)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                entries[relative] = ('link', os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                entries[relative] = ('dir',)
            elif stat.S_ISREG(info.st_mode):
                entries[relative] = ('file', info.st_ino, path.read_bytes())
            else:
                entries[relative] = ('special', stat.S_IFMT(info.st_mode))
    return entries


class RestoreRouteTestCase(HistoryRouteTestCase):
    def restore(self, name: str, version_id: str, body=None):
        path = f'/api/snapshots/{name}/versions/{version_id}/restore'
        if body is None:
            return self.client.post(path)
        return self.client.post(path, json=body)

    def state_of(self, name: str) -> dict:
        response = self.version_state(name)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        return response.get_json()['data']

    def manifest_hash(self, name: str) -> str:
        return self.sandbox.state.compute_manifest(self.sandbox.snapshots_dir / name).content_hash

    def ref(self, version: dict) -> dict:
        return {'version_id': version['version_id'], 'seq': version['seq']}

    def assert_restored(self, response, version: dict):
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['data'], {'requires_reinitialize': True, 'restored_from': self.ref(version)})

    def assert_stale(self, response):
        self.assert_code(response, 409, 'version_conflict')
        self.assertNotIn('details', response.get_json())

    def assert_path_clash(self, response, path: str):
        self.assert_code(response, 409, 'version_conflict')
        self.assertEqual(response.get_json()['details'], {'reason': 'path_clash', 'path': path})

    def assert_no_flag(self):
        self.assertEqual(self.sandbox.state._in_progress, {})

    def flag_spy(self):
        state = self.sandbox.state
        return mock.patch.object(state, 'begin_api_write', wraps=state.begin_api_write)

    def after_flag_hold(self, action):
        """Run action right after the restore's flag hold; the tree it leaves behind is appended to the returned list."""
        state = self.sandbox.state
        original = state.begin_restore_write
        trees = []

        def begin_then_act(key, snapshot_dir, *args):
            prepared = original(key, snapshot_dir, *args)
            action(Path(snapshot_dir))
            trees.append(tree_entries(Path(snapshot_dir)))
            return prepared

        return mock.patch.object(state, 'begin_restore_write', side_effect=begin_then_act), trees


class RestoreRouteTest(RestoreRouteTestCase):
    def test_restore_rewrites_the_tree_and_stays_uncommitted_until_a_commit(self):
        snapshot = self.sandbox.create_snapshot('roll', {'configs/r1.cfg': config_for('roll-v1')})
        baseline = self.state_of('roll')
        first = baseline['head']
        self.upload('roll', 'r1.cfg', config_for('roll-v2'))
        self.upload('roll', 'r2.cfg', config_for('roll-r2'))
        head = self.commit('roll', {'message': 'v2'}).get_json()['data']
        replaced_inode = (snapshot / 'configs' / 'r1.cfg').stat().st_ino

        response = self.restore('roll', first['version_id'])

        self.assert_restored(response, first)
        self.assertEqual((snapshot / 'configs' / 'r1.cfg').read_text(encoding='utf-8'), config_for('roll-v1'))
        self.assertNotEqual((snapshot / 'configs' / 'r1.cfg').stat().st_ino, replaced_inode)
        self.assertFalse((snapshot / 'configs' / 'r2.cfg').exists())
        self.assertEqual([path for path in tree_entries(snapshot) if path.endswith('.tmp')], [])
        self.assert_no_flag()
        state = self.state_of('roll')
        self.assertEqual(state['content_hash'], baseline['content_hash'])
        self.assertEqual(state['head']['version_id'], head['version_id'])
        self.assertTrue(state['uncommitted'])
        self.assertFalse(state['pending_external'])
        self.assertEqual(state['restored_from'], self.ref(first))
        self.assertEqual(self.sandbox.version_count(), 2)

        committed = self.commit('roll', {'message': 'back to v1'})

        self.assertEqual(committed.status_code, 201, committed.get_data(as_text=True)[:300])
        version = committed.get_json()['data']
        self.assertEqual((version['kind'], version['restored_from'], version['parent']),
                         ('restore', self.ref(first), self.ref(head)))
        self.assertIsNone(self.state_of('roll')['restored_from'])

    def test_restored_from_survives_later_api_writes_and_the_deletion_of_its_source(self):
        versions = self.build_history('carry', 3)

        self.assert_restored(self.restore('carry', versions[1]['version_id']), versions[1])
        self.assertEqual(self.upload('carry', 'r9.cfg', config_for('carry-r9')).status_code, 200)
        self.assertEqual(self.state_of('carry')['restored_from'], self.ref(versions[1]))
        version = self.commit('carry', {'message': 'restore plus r9'}).get_json()['data']
        self.assertEqual((version['kind'], version['restored_from']), ('restore', self.ref(versions[1])))

        self.assert_restored(self.restore('carry', versions[0]['version_id']), versions[0])
        self.assertEqual(self.delete_version('carry', versions[0]['version_id']).status_code, 200)
        self.assertEqual(self.state_of('carry')['restored_from'], {'version_id': None, 'seq': 1})
        version = self.commit('carry', {'message': 'source gone'}).get_json()['data']
        self.assertEqual((version['kind'], version['restored_from']), ('restore', {'version_id': None, 'seq': 1}))

    def test_file_names_at_the_length_limit_restore_head_cleanly(self):
        long_names = {255: 'a' * 251 + '.cfg', 253: 'あ' * 83 + '.cfg'}
        snapshot = self.sandbox.create_snapshot('long-names')
        self.state_of('long-names')
        self.assertEqual(self.upload('long-names', 'r2.cfg', config_for('long-names-r2')).status_code, 200)
        for length, file_name in long_names.items():
            self.assertEqual(len(file_name.encode('utf-8')), length)
            write_file(snapshot / 'configs' / file_name, config_for(f'long-{length}'))
        committed = self.commit('long-names', {'message': 'long names'})
        self.assertEqual(committed.status_code, 201, committed.get_data(as_text=True)[:300])
        head = committed.get_json()['data']
        committed_hash = self.state_of('long-names')['content_hash']
        self.assertEqual(self.client.delete('/api/snapshots/long-names/files/r2.cfg').status_code, 200)
        for length, file_name in long_names.items():
            write_file(snapshot / 'configs' / file_name, config_for(f'long-{length}-changed'))
        changed = self.state_of('long-names')
        self.assertTrue(changed['uncommitted'])
        self.assertEqual(changed['head']['version_id'], head['version_id'])

        response = self.restore('long-names', head['version_id'])

        self.assert_restored(response, head)
        for length, file_name in long_names.items():
            self.assertEqual((snapshot / 'configs' / file_name).read_text(encoding='utf-8'), config_for(f'long-{length}'))
        self.assertEqual((snapshot / 'configs' / 'r2.cfg').read_text(encoding='utf-8'), config_for('long-names-r2'))
        self.assertEqual([path for path in tree_entries(snapshot) if path.endswith('.tmp')], [])
        state = self.state_of('long-names')
        self.assertEqual(state['content_hash'], committed_hash)
        self.assertFalse(state['uncommitted'])
        self.assertIsNone(state['restored_from'])
        self.assert_no_flag()

    def test_expected_working_hash_guards_the_restore(self):
        versions = self.build_history('guard', 2)
        snapshot = self.sandbox.snapshots_dir / 'guard'
        listed_hash = self.state_of('guard')['content_hash']
        self.assertEqual(self.upload('guard', 'late.cfg', config_for('guard-late')).status_code, 200)
        before = tree_entries(snapshot)

        with self.flag_spy() as begin, self.assertNoLogs('app', level='ERROR'), \
                self.assertNoLogs('database.session', level='ERROR'):
            stale = self.restore('guard', versions[0]['version_id'], {'expected_working_hash': listed_hash})

        self.assert_stale(stale)
        begin.assert_not_called()
        self.assertEqual(tree_entries(snapshot), before)
        self.assertIsNone(self.state_of('guard')['restored_from'])

        current_hash = self.state_of('guard')['content_hash']
        matched = self.restore('guard', versions[0]['version_id'], {'expected_working_hash': current_hash})

        self.assert_restored(matched, versions[0])
        self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['r1.cfg'])
        self.assert_no_flag()

    def test_request_validation_writes_nothing_and_never_sets_the_flag(self):
        versions = self.build_history('checked', 2)
        snapshot = self.sandbox.snapshots_dir / 'checked'
        target = versions[0]['version_id']
        state = self.sandbox.state
        before = tree_entries(snapshot)

        with mock.patch.object(state, 'settle_external_changes', wraps=state.settle_external_changes) as settle, \
                self.flag_spy() as begin:
            for value in (None, 5, True, ['x'], {}):
                with self.subTest(expected_working_hash=value):
                    response = self.restore('checked', target, {'expected_working_hash': value})
                    self.assert_code(response, 400, 'validation_error')
            for raw, content_type in (('[1]', 'application/json'), ('{bad', 'application/json'),
                                      ('"x"', 'application/json'), ('null', 'application/json'),
                                      ('x=1', 'application/x-www-form-urlencoded')):
                with self.subTest(raw=raw):
                    response = self.client.post(
                        f'/api/snapshots/checked/versions/{target}/restore', data=raw, content_type=content_type,
                    )
                    self.assert_code(response, 400, 'invalid_json')

        settle.assert_not_called()
        begin.assert_not_called()
        self.assertEqual(tree_entries(snapshot), before)
        self.assertEqual(self.sandbox.version_count(), 2)

    def test_fingerprint_moved_between_the_settle_and_the_flag_hold_answers_conflict(self):
        versions = self.build_history('moving', 2)
        snapshot = self.sandbox.snapshots_dir / 'moving'
        state = self.sandbox.state
        original_settle = state.settle_external_changes
        trees = []

        def settle_then_add(snapshot_id, snapshot_dir):
            settled = original_settle(snapshot_id, snapshot_dir)
            write_file(snapshot / 'configs' / 'late.cfg', config_for('moving-late'))
            trees.append(tree_entries(snapshot))
            return settled

        with mock.patch.object(state, 'settle_external_changes', side_effect=settle_then_add), \
                self.flag_spy() as begin:
            response = self.restore('moving', versions[0]['version_id'])

        self.assert_stale(response)
        begin.assert_not_called()
        self.assertEqual(tree_entries(snapshot), trees[0])
        self.assertIsNone(self.state_of('moving')['restored_from'])

    def test_removal_set_is_the_flag_hold_listing_and_a_later_file_stays_uncommitted(self):
        versions = self.build_history('late', 3)
        snapshot = self.sandbox.snapshots_dir / 'late'
        patch, _ = self.after_flag_hold(
            lambda directory: write_file(directory / 'configs' / 'late.cfg', config_for('late-file')),
        )

        with patch:
            response = self.restore('late', versions[0]['version_id'])

        self.assert_restored(response, versions[0])
        self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['late.cfg', 'r1.cfg'])
        state = self.state_of('late')
        self.assertTrue(state['uncommitted'])
        self.assertEqual(state['restored_from'], self.ref(versions[0]))
        self.assertEqual(state['content_hash'], self.manifest_hash('late'))
        self.assertEqual(self.sandbox.row(self.sandbox.snapshot_id('late')).content_hash, self.manifest_hash('late'))

    def test_restore_of_head_clears_pending_external_and_records_no_restored_from(self):
        snapshot = self.sandbox.create_snapshot('pending')
        baseline = self.state_of('pending')
        head = baseline['head']
        self.assertEqual(self.upload('pending', 'r2.cfg', config_for('pending-r2')).status_code, 200)
        write_file(snapshot / 'configs' / 'r3.cfg', config_for('pending-r3'))
        flagged = self.state_of('pending')
        self.assertTrue(flagged['pending_external'])
        self.assertTrue(flagged['uncommitted'])

        self.assert_restored(self.restore('pending', head['version_id']), head)

        state = self.state_of('pending')
        self.assertEqual(state['content_hash'], baseline['content_hash'])
        self.assertFalse(state['pending_external'])
        self.assertFalse(state['uncommitted'])
        self.assertIsNone(state['restored_from'])
        row = self.sandbox.row(state['snapshot_id'])
        self.assertEqual((row.pending_external, row.restored_from_version_id, row.restored_from_seq), (False, None, None))
        self.assertEqual(self.sandbox.version_count(), 1)
        self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['r1.cfg'])

    def test_restoring_the_working_content_is_a_no_op(self):
        versions = self.build_history('same', 2)
        snapshot = self.sandbox.snapshots_dir / 'same'
        state = self.sandbox.state
        snapshot_id = self.sandbox.snapshot_id('same')
        before = tree_entries(snapshot)

        with self.flag_spy() as begin, mock.patch.object(state, 'end_api_write', wraps=state.end_api_write) as end:
            head_noop = self.restore('same', versions[1]['version_id'])

        self.assert_restored(head_noop, versions[1])
        begin.assert_not_called()
        end.assert_not_called()
        self.assertEqual(tree_entries(snapshot), before)
        self.assertIsNone(self.state_of('same')['restored_from'])
        self.assertIsNone(self.sandbox.row(snapshot_id).restored_from_seq)

        self.assertEqual(self.client.delete('/api/snapshots/same/files/r2.cfg').status_code, 200)
        working_hash = self.state_of('same')['content_hash']
        before = tree_entries(snapshot)

        with self.flag_spy() as begin, mock.patch.object(state, 'end_api_write', wraps=state.end_api_write) as end:
            earlier_noop = self.restore('same', versions[0]['version_id'], {'expected_working_hash': working_hash})

        self.assert_restored(earlier_noop, versions[0])
        begin.assert_not_called()
        end.assert_not_called()
        self.assertEqual(tree_entries(snapshot), before)
        restored = self.state_of('same')
        self.assertTrue(restored['uncommitted'])
        self.assertEqual(restored['restored_from'], self.ref(versions[0]))
        self.assertEqual(self.sandbox.version_count(), 2)
        version = self.commit('same', {'message': 'back at v1'}).get_json()['data']
        self.assertEqual((version['kind'], version['restored_from']), ('restore', self.ref(versions[0])))

    def test_failed_write_records_the_tree_and_keeps_an_earlier_restored_from(self):
        snapshot = self.sandbox.create_snapshot('flaky', {'configs/r1.cfg': config_for('flaky-v1')})
        first = self.state_of('flaky')['head']
        versions = [first]
        for label in ('v2', 'v3'):
            self.upload('flaky', 'r1.cfg', config_for(f'flaky-{label}'))
            self.upload('flaky', 'r2.cfg', config_for(f'flaky-{label}-r2'))
            versions.append(self.commit('flaky', {'message': label}).get_json()['data'])
        self.assert_restored(self.restore('flaky', versions[1]['version_id']), versions[1])
        real_replace = os.replace

        def failing_replace(source, destination, *args, **kwargs):
            if os.path.basename(os.fsdecode(destination)) == 'r1.cfg':
                raise OSError(errno.EIO, 'Input/output error')
            return real_replace(source, destination, *args, **kwargs)

        with mock.patch('services.snapshot_history_service.os.replace', side_effect=failing_replace), \
                self.assertLogs('app', level='ERROR'):
            failed = self.restore('flaky', versions[0]['version_id'])

        self.assert_code(failed, 500, 'restore_failed')
        self.assertEqual((snapshot / 'configs' / 'r1.cfg').read_text(encoding='utf-8'), config_for('flaky-v2'))
        self.assertFalse((snapshot / 'configs' / 'r2.cfg').exists())
        self.assertEqual([path for path in tree_entries(snapshot) if path.endswith('.tmp')], [])
        self.assert_no_flag()
        snapshot_id = self.sandbox.snapshot_id('flaky')
        row = self.sandbox.row(snapshot_id)
        self.assertEqual(row.content_hash, self.manifest_hash('flaky'))
        self.assertEqual((row.restored_from_version_id, row.restored_from_seq), (versions[1]['version_id'], 2))
        state = self.state_of('flaky')
        self.assertTrue(state['uncommitted'])
        self.assertEqual(state['restored_from'], self.ref(versions[1]))

        version = self.commit('flaky', {'message': 'after a failed restore'}).get_json()['data']

        self.assertEqual((version['kind'], version['restored_from']), ('restore', self.ref(versions[1])))

    def test_settle_failure_answers_restore_failed_before_anything_is_written(self):
        versions = self.build_history('settle-fail', 2)
        snapshot = self.sandbox.snapshots_dir / 'settle-fail'
        state = self.sandbox.state
        before = tree_entries(snapshot)

        for failure in (OSError(errno.EIO, 'Input/output error'),
                        OperationalError('SELECT 1', {}, Exception('database is unavailable'))):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(state, 'settle_external_changes', side_effect=failure), \
                        self.flag_spy() as begin, self.assertLogs('app', level='ERROR'):
                    response = self.restore('settle-fail', versions[0]['version_id'])
                self.assert_code(response, 500, 'restore_failed')
                begin.assert_not_called()
                self.assertEqual(state._markers, {})
                self.assertEqual(tree_entries(snapshot), before)

    def test_a_database_failure_while_settling_logs_only_its_type(self):
        versions = self.build_history('settle-db', 2)
        state = self.sandbox.state
        statement = "SELECT snapshot_states.head_version_id FROM snapshot_states WHERE snapshot_states.snapshot_id = ?"
        connection_text = (
            'connection to server at "db.internal.example" (192.0.2.10), port 5432 failed: '
            'FATAL: password authentication failed for user "history_owner"'
        )
        failures = (
            OperationalError(statement, ('bound-parameter-value',), Exception(connection_text)),
            sqlite3.OperationalError(f"unable to open database file /srv/private/history.db; {connection_text}"),
        )
        for failure in failures:
            with self.subTest(failure=f"{type(failure).__module__}.{type(failure).__name__}"):
                with mock.patch.object(state, 'settle_external_changes', side_effect=failure), \
                        self.assertLogs('app', level='ERROR') as logs:
                    response = self.restore('settle-db', versions[0]['version_id'])
                self.assert_code(response, 500, 'restore_failed')
                logged = '\n'.join(logs.output)
                self.assertIn('Failed to restore snapshot version: OperationalError', logged)
                for text in ('SELECT', 'bound-parameter-value', 'db.internal.example', '5432', 'history_owner',
                             '/srv/private'):
                    self.assertNotIn(text, logged)
                    self.assertNotIn(text, response.get_data(as_text=True))

    def test_missing_or_corrupt_objects_fail_before_any_write(self):
        versions = self.build_history('damaged', 2)
        snapshot = self.sandbox.snapshots_dir / 'damaged'
        object_path = self.object_path(config_for('damaged-v1'))
        intact = object_path.read_bytes()

        for damage in ('corrupt', 'missing'):
            with self.subTest(damage=damage):
                if damage == 'corrupt':
                    object_path.write_bytes(intact.replace(b'hostname', b'HOSTNAME'))
                else:
                    object_path.unlink()
                before = tree_entries(snapshot)
                with self.assertLogs('app', level='ERROR'):
                    response = self.restore('damaged', versions[0]['version_id'])
                self.assert_code(response, 500, 'restore_failed')
                self.assertEqual(tree_entries(snapshot), before)
                self.assert_no_flag()
                self.assertIsNone(self.state_of('damaged')['restored_from'])
                object_path.write_bytes(intact)

        self.assert_restored(self.restore('damaged', versions[0]['version_id']), versions[0])

    def test_excluded_and_topologix_owned_files_are_never_touched(self):
        snapshot = self.sandbox.create_snapshot('owned', {
            'configs/r1.cfg': config_for('owned-r1'),
            'batfish/layer1_topology.json': '{"edges": []}\n',
        })
        untouched = {
            '.hidden.cfg': 'hidden\n',
            '.git/HEAD': 'ref: refs/heads/main\n',
            'configs/r1.cfg~': 'backup\n',
            'configs/.r1.cfg.swp': 'swap\n',
            'configs/notes.swo': 'swap\n',
            'configs/#r1.cfg#': 'autosave\n',
            'configs/.r1.cfg.1234.tmp': 'temp\n',
        }
        for relative_path, content in untouched.items():
            write_file(snapshot / relative_path, content)
        os.symlink('r1.cfg', snapshot / 'configs' / 'alias.cfg')
        (snapshot / '.topologix-snapshot.json.lock').touch()
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            first = self.state_of('owned')['head']
        (snapshot / 'batfish' / 'layer1_topology.json').unlink()
        self.upload('owned', 'r2.cfg', config_for('owned-r2'))
        self.commit('owned', {'message': 'drop layer 1, add r2'})
        owned_paths = list(untouched) + ['configs/alias.cfg', '.topologix-snapshot.json',
                                         '.topologix-snapshot.json.lock']
        before = tree_entries(snapshot)

        self.assert_restored(self.restore('owned', first['version_id']), first)

        after = tree_entries(snapshot)
        for relative_path in owned_paths:
            with self.subTest(path=relative_path):
                self.assertEqual(after[relative_path], before[relative_path])
        self.assertEqual((snapshot / 'batfish' / 'layer1_topology.json').read_text(encoding='utf-8'), '{"edges": []}\n')
        self.assertNotIn('configs/r2.cfg', after)

    def test_snapshot_recreated_before_the_flag_hold_answers_500_without_writing(self):
        versions = self.build_history('reborn-restore', 2)
        snapshot = self.sandbox.snapshots_dir / 'reborn-restore'
        old_id = self.sandbox.snapshot_id('reborn-restore')
        state = self.sandbox.state
        original_settle = state.settle_external_changes
        trees = []

        def settle_then_recreate(snapshot_id, snapshot_dir):
            settled = original_settle(snapshot_id, snapshot_dir)
            shutil.rmtree(snapshot)
            self.sandbox.create_snapshot('reborn-restore', {'configs/fresh.cfg': config_for('fresh')})
            trees.append(tree_entries(snapshot))
            return settled

        with mock.patch.object(state, 'settle_external_changes', side_effect=settle_then_recreate), \
                self.flag_spy() as begin, self.assertLogs('app', level='ERROR'):
            response = self.restore('reborn-restore', versions[0]['version_id'])

        self.assert_code(response, 500, 'restore_failed')
        begin.assert_not_called()
        self.assertEqual(tree_entries(snapshot), trees[0])
        new_id = self.sandbox.snapshot_id('reborn-restore')
        self.assertNotEqual(new_id, old_id)
        self.assertIsNone(self.sandbox.row(new_id))
        self.assertEqual(len(self.sandbox.versions(old_id)), 2)

    def test_restore_is_matched_by_endpoint_and_holds_the_batfish_lock(self):
        for name in ('files-x', 'artifacts-x', 'plain'):
            with self.subTest(name=name):
                path = f'/api/snapshots/{name}/versions/{UNKNOWN_VERSION_ID}/restore'
                with app_module.app.test_request_context(path, method='POST'):
                    self.assertTrue(app_module.request_uses_batfish())

        versions = self.build_history('files-x', 2)
        lock = mock.MagicMock()
        with mock.patch.object(app_module, 'batfish_request_lock', lock):
            response = self.restore('files-x', versions[0]['version_id'])

        self.assert_restored(response, versions[0])
        lock.acquire.assert_called_once()
        lock.release.assert_called_once()

    def test_deletion_and_commit_answer_conflict_while_a_restore_holds_the_flag(self):
        versions = self.build_history('held', 3)
        history = self.sandbox.history
        original_write = history._write_version_tree
        concurrent = {}

        def delete_and_commit_while_writing(*args):
            concurrent['single'] = self.delete_version('held', versions[0]['version_id'])
            concurrent['oldest'] = self.delete_versions('held', {'mode': 'oldest', 'count': 1})
            concurrent['all'] = self.delete_versions('held', {'mode': 'all'})
            concurrent['commit'] = self.commit('held', {'message': 'during the restore'})
            return original_write(*args)

        with mock.patch.object(history, '_write_version_tree', side_effect=delete_and_commit_while_writing):
            response = self.restore('held', versions[0]['version_id'])

        self.assertEqual(set(concurrent), {'single', 'oldest', 'all', 'commit'})
        for route, conflict in concurrent.items():
            with self.subTest(route=route):
                self.assert_code(conflict, 409, 'version_conflict')
        self.assert_restored(response, versions[0])
        self.assertEqual(self.sandbox.version_count(), 3)
        self.assertEqual(self.state_of('held')['restored_from'], self.ref(versions[0]))

    def test_unknown_versions_and_snapshots_are_distinct_404s(self):
        versions = self.build_history('mine', 2)
        self.build_history('theirs', 1)

        self.assert_code(self.restore('mine', UNKNOWN_VERSION_ID), 404, 'version_not_found')
        self.assert_code(self.restore('theirs', versions[0]['version_id']), 404, 'version_not_found')
        self.assert_code(self.restore('nowhere', versions[0]['version_id']), 404, 'snapshot_not_found')
        self.assertEqual(self.restore('bad%20name', versions[0]['version_id']).status_code, 400)
        self.assert_no_flag()
        self.assertEqual(sorted(path.name for path in (self.sandbox.snapshots_dir / 'mine' / 'configs').iterdir()),
                         ['r1.cfg', 'r2.cfg'])


class RestorePathRouteTest(RestoreRouteTestCase):
    def prepare(self, name: str, version_files: dict, transform) -> tuple[Path, dict, str]:
        """Record version_files as a version, then reshape the working tree with transform and record it too."""
        files = {'configs/r1.cfg': config_for(f'{name}-r1'), **version_files}
        snapshot = self.sandbox.create_snapshot(name, files)
        recorded = self.state_of(name)
        transform(snapshot)
        self.state_of(name)
        return snapshot, recorded['head'], recorded['content_hash']

    def test_symlinks_at_a_manifest_path_or_a_component_are_path_clashes(self):
        outside = self.sandbox.root / 'outside'
        write_file(outside / 'target.cfg', 'outside\n')
        cases = {
            'in-root-file': ('configs/r2.cfg', 'r1.cfg'),
            'out-of-root-file': ('configs/r2.cfg', str(outside / 'target.cfg')),
            'in-root-component': ('configs/x', '.'),
            'out-of-root-component': ('configs/x', str(outside)),
        }
        for case, (link, target) in cases.items():
            with self.subTest(case=case):
                name = f'link-{case}'
                version_path = 'configs/x/y.cfg' if case.endswith('component') else 'configs/r2.cfg'

                def link_instead(snapshot, link=link, target=target, version_path=version_path):
                    (snapshot / version_path).unlink()
                    if version_path != link:
                        (snapshot / link).rmdir()
                    os.symlink(target, snapshot / link)

                with self.assertLogs(STATE_LOGGER, level='WARNING'):
                    snapshot, version, _ = self.prepare(name, {version_path: config_for(f'{name}-file')}, link_instead)
                before = tree_entries(snapshot)
                outside_before = tree_entries(outside)

                response = self.restore(name, version['version_id'])

                self.assert_path_clash(response, link)
                self.assertEqual(tree_entries(snapshot), before)
                self.assertEqual(tree_entries(outside), outside_before)
                self.assert_no_flag()
                self.assertIsNone(self.state_of(name)['restored_from'])

    def test_file_and_directory_clashes_answer_409_with_nothing_written(self):
        def remove_x_directory(snapshot):
            shutil.rmtree(snapshot / 'configs' / 'x')

        def x_file_to_directory_with(*entries):
            def transform(snapshot):
                (snapshot / 'configs' / 'x').unlink()
                (snapshot / 'configs' / 'x').mkdir()
                for entry in entries:
                    write_file(snapshot / 'configs' / 'x' / entry, 'not versioned\n')
            return transform

        def x_file_to_empty_directories(snapshot):
            (snapshot / 'configs' / 'x').unlink()
            (snapshot / 'configs' / 'x' / 'a').mkdir(parents=True)

        def fifo_instead_of(path):
            def transform(snapshot):
                if (snapshot / path).is_dir():
                    shutil.rmtree(snapshot / path)
                else:
                    (snapshot / path).unlink()
                os.mkfifo(snapshot / path)
            return transform

        cases = {
            'file-at-component-after-hold': (
                {'configs/x/y.cfg': 'y\n'}, remove_x_directory,
                lambda snapshot: write_file(snapshot / 'configs' / 'x', 'file\n')),
            'non-consumable-entry-in-directory': ({'configs/x': 'x\n'}, x_file_to_directory_with('.hidden'), None),
            'editor-file-in-nested-directory': ({'configs/x': 'x\n'}, x_file_to_directory_with('a/b.cfg~'), None),
            'nested-file-after-hold': (
                {'configs/x': 'x\n'}, x_file_to_empty_directories,
                lambda snapshot: write_file(snapshot / 'configs' / 'x' / 'a' / 'b.cfg', 'late\n')),
            'fifo-at-component': ({'configs/x/y.cfg': 'y\n'}, fifo_instead_of('configs/x'), None),
            'fifo-at-manifest-path': ({'configs/x': 'x\n'}, fifo_instead_of('configs/x'), None),
        }
        for case, (version_files, transform, late_action) in cases.items():
            with self.subTest(case=case):
                name = f'clash-{case}'
                snapshot, version, _ = self.prepare(name, version_files, transform)
                if late_action is None:
                    before = tree_entries(snapshot)
                    response = self.restore(name, version['version_id'])
                else:
                    patch, trees = self.after_flag_hold(late_action)
                    with patch:
                        response = self.restore(name, version['version_id'])
                    before = trees[0]

                self.assert_path_clash(response, 'configs/x')
                self.assertEqual(tree_entries(snapshot), before)
                self.assert_no_flag()
                self.assertIsNone(self.state_of(name)['restored_from'])

    def test_entries_in_the_removal_set_are_removed_pruned_and_replaced(self):
        def x_directory_to_file(snapshot):
            shutil.rmtree(snapshot / 'configs' / 'x')
            write_file(snapshot / 'configs' / 'x', 'now a file\n')

        def x_file_to(relative_path):
            def transform(snapshot):
                (snapshot / 'configs' / 'x').unlink()
                if relative_path is None:
                    (snapshot / 'configs' / 'x').mkdir()
                else:
                    write_file(snapshot / 'configs' / 'x' / relative_path, 'nested\n')
            return transform

        cases = {
            'working-file-at-component': ({'configs/x/y.cfg': 'y\n'}, x_directory_to_file),
            'working-file-in-directory': ({'configs/x': 'x\n'}, x_file_to('y.cfg')),
            'empty-directory': ({'configs/x': 'x\n'}, x_file_to(None)),
            'nested-file-in-directory': ({'configs/x': 'x\n'}, x_file_to('a/b.cfg')),
        }
        for case, (version_files, transform) in cases.items():
            with self.subTest(case=case):
                name = f'prune-{case}'
                snapshot, version, version_hash = self.prepare(name, version_files, transform)

                response = self.restore(name, version['version_id'])

                self.assert_restored(response, version)
                for relative_path, content in version_files.items():
                    self.assertEqual((snapshot / relative_path).read_text(encoding='utf-8'), content)
                state = self.state_of(name)
                self.assertEqual(state['content_hash'], version_hash)
                self.assertEqual(self.manifest_hash(name), version_hash)
                self.assertEqual(state['restored_from'], self.ref(version))
                self.assert_no_flag()

    def test_resolver_rejection_is_a_path_clash(self):
        versions = self.build_history('resolver', 2)
        snapshot = self.sandbox.snapshots_dir / 'resolver'
        before = tree_entries(snapshot)

        with mock.patch.object(app_module.snapshot_service, '_resolve_snapshot_relative_path',
                               side_effect=ValueError('Artifact path escapes snapshot root')):
            response = self.restore('resolver', versions[0]['version_id'])

        self.assert_path_clash(response, 'configs/r1.cfg')
        self.assertEqual(tree_entries(snapshot), before)
        self.assert_no_flag()


class RestoreUnavailableRouteTest(RestoreRouteTestCase):
    def assert_unavailable(self, response, reason: str):
        self.assert_code(response, 503, 'versioning_unavailable')
        self.assertEqual(response.get_json()['details'], {'reason': reason})

    def test_storage_fault_answers_503_on_restore(self):
        self.sandbox.create_snapshot('stored', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('other', {'configs/r2.cfg': CONFIG_R2})
        stored = self.state_of('stored')['head']
        self.state_of('other')
        shutil.rmtree(self.sandbox.history.objects_dir)
        with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()
        snapshot = self.sandbox.snapshots_dir / 'stored'
        before = tree_entries(snapshot)

        self.assert_unavailable(self.restore('stored', stored['version_id']), 'storage')
        self.assertEqual(tree_entries(snapshot), before)
        self.assert_no_flag()

    def test_missing_objects_answer_503_on_restore_for_the_affected_snapshot_only(self):
        self.sandbox.create_snapshot('lost', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('kept', {'configs/r2.cfg': CONFIG_R2})
        lost = self.state_of('lost')['head']
        kept = self.state_of('kept')['head']
        self.object_path(CONFIG_R1).unlink()
        with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()
        snapshot = self.sandbox.snapshots_dir / 'lost'
        before = tree_entries(snapshot)

        self.assert_unavailable(self.restore('lost', lost['version_id']), 'missing_objects')
        self.assertEqual(tree_entries(snapshot), before)
        self.assert_restored(self.restore('kept', kept['version_id']), kept)

    def test_database_failure_of_identity_resolution_answers_503_database(self):
        versions = self.build_history('db-part', 2)
        snapshot = self.sandbox.snapshots_dir / 'db-part'
        state = self.sandbox.state
        before = tree_entries(snapshot)
        failure = OperationalError('SELECT 1', {}, Exception('database is unavailable'))

        with mock.patch.object(state, '_resolve_rows', side_effect=failure), self.flag_spy() as begin:
            response = self.restore('db-part', versions[0]['version_id'])

        self.assert_unavailable(response, 'database')
        begin.assert_not_called()
        self.assertEqual(state._markers, {})
        self.assertEqual(tree_entries(snapshot), before)

    @unittest.skipIf(IS_ROOT, "directory permissions are not enforced for root")
    def test_read_only_directory_that_needs_an_id_answers_503_sidecar(self):
        snapshot = self.sandbox.snapshots_dir / 'frozen'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        os.chmod(snapshot, 0o555)
        try:
            before = tree_entries(snapshot)
            with self.flag_spy() as begin, self.assertLogs(STATE_LOGGER, level='WARNING'):
                response = self.restore('frozen', UNKNOWN_VERSION_ID)
            self.assert_unavailable(response, 'sidecar')
            begin.assert_not_called()
            self.assertEqual(tree_entries(snapshot), before)
            self.assertEqual(self.sandbox.state.unavailable_reason(snapshot_name='frozen'), 'sidecar')
        finally:
            os.chmod(snapshot, 0o755)

    def test_failed_fresh_id_write_during_the_settle_answers_503_sidecar(self):
        origin = self.sandbox.create_snapshot('origin')
        version = self.state_of('origin')['head']
        origin_id = self.sandbox.snapshot_id('origin')
        copy = self.sandbox.snapshots_dir / 'copy'
        shutil.copytree(origin, copy)
        (copy / '.topologix-snapshot.json.lock').touch()
        state = self.sandbox.state
        original_rows = state._resolve_rows
        calls = []

        def first_resolution_misses_the_copy(snapshot_id, snapshot_dir):
            calls.append(snapshot_dir.name)
            if len(calls) == 1:
                return 'done'
            return original_rows(snapshot_id, snapshot_dir)

        before = tree_entries(copy)
        with mock.patch.object(state, '_resolve_rows', side_effect=first_resolution_misses_the_copy), \
                mock.patch.object(app_module.snapshot_service, '_write_metadata',
                                  side_effect=PermissionError(errno.EACCES, 'Permission denied')), \
                self.flag_spy() as begin, self.assertLogs(STATE_LOGGER, level='WARNING'):
            response = self.restore('copy', version['version_id'])

        self.assert_unavailable(response, 'sidecar')
        self.assertGreaterEqual(len(calls), 2)
        begin.assert_not_called()
        self.assertEqual(state._markers, {})
        self.assertEqual(tree_entries(copy), before)
        self.assertEqual(state.unavailable_reason(snapshot_name='copy'), 'sidecar')
        self.assertEqual(self.sandbox.row(origin_id).snapshot_name, 'origin')


def size_of(content: str) -> int:
    return len(content.encode('utf-8'))


def remove_entry(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


class DiffRouteTestCase(RestoreRouteTestCase):
    def diff(self, name: str, version_id: str, against: str | None = None):
        query = {} if against is None else {'against': against}
        return self.client.get(f'/api/snapshots/{name}/versions/{version_id}/diff', query_string=query)

    def diff_file(self, name: str, version_id: str, against: str | None = None, path: str | None = None):
        query = {key: value for key, value in (('against', against), ('path', path)) if value is not None}
        return self.client.get(f'/api/snapshots/{name}/versions/{version_id}/diff/file', query_string=query)

    def data_of(self, response) -> dict:
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        return response.get_json()['data']

    def changes(self, file_diff: dict) -> list:
        return [(line['type'], line['text']) for hunk in file_diff['hunks'] for line in hunk['lines']]

    def assert_removed_on_the_working_side(self, response, content: str):
        data = self.data_of(response)
        self.assertEqual((data['binary'], data['too_large'], data['truncated']), (False, False, False))
        self.assertEqual(self.changes(data), [('-', line) for line in content.splitlines()])
        self.assertEqual([(hunk['new_start'], hunk['new_lines']) for hunk in data['hunks']], [(0, 0)])
        self.assertNotIn(OUTSIDE_SECRET.strip(), response.get_data(as_text=True))

    def request_within(self, send, fifo: Path, seconds: float = 10.0):
        """Send a request in a worker thread and fail when it blocks, releasing a reader blocked on fifo."""
        outcome = {}
        worker = threading.Thread(target=lambda: outcome.setdefault('response', send()), daemon=True)
        worker.start()
        worker.join(seconds)
        if worker.is_alive():
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
            worker.join(seconds)
            self.fail("The diff request blocked on a FIFO")
        return outcome['response']


class VersionDiffRouteTest(DiffRouteTestCase):
    def test_summary_lists_the_changes_from_the_version_to_against(self):
        snapshot = self.sandbox.create_snapshot('changes', {
            'configs/core.cfg': config_for('core'),
            'configs/r1.cfg': config_for('r1-v1'),
            'configs/r2.cfg': config_for('r2'),
        })
        first = self.state_of('changes')['head']
        self.assertEqual(self.upload('changes', 'r1.cfg', config_for('r1-v2')).status_code, 200)
        self.assertEqual(self.client.delete('/api/snapshots/changes/files/r2.cfg').status_code, 200)
        self.assertEqual(self.upload('changes', 'r3.cfg', config_for('r3')).status_code, 200)
        second = self.commit('changes', {'message': 'v2'}).get_json()['data']
        write_file(snapshot / 'configs' / 'r4.cfg', config_for('r4'))
        write_file(snapshot / 'configs' / os.fsdecode(b'odd-\xfe.cfg'), config_for('odd'))
        write_file(snapshot / os.fsdecode(b'odd-\xfe-dir') / 'inner.cfg', config_for('inner'))
        stored_hash = self.sandbox.row(self.sandbox.snapshot_id('changes')).content_hash
        between_versions = [
            {'path': 'configs/core.cfg', 'status': 'unchanged',
             'size': size_of(config_for('core')), 'against_size': size_of(config_for('core'))},
            {'path': 'configs/r1.cfg', 'status': 'modified',
             'size': size_of(config_for('r1-v1')), 'against_size': size_of(config_for('r1-v2'))},
            {'path': 'configs/r2.cfg', 'status': 'removed', 'size': size_of(config_for('r2')), 'against_size': None},
            {'path': 'configs/r3.cfg', 'status': 'added', 'size': None, 'against_size': size_of(config_for('r3'))},
        ]

        versions_diff = self.data_of(self.diff('changes', first['version_id'], second['version_id']))
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            working_diff = self.data_of(self.diff('changes', first['version_id'], 'working'))

        self.assertEqual(versions_diff, {
            'from': first['version_id'], 'against': second['version_id'], 'files': between_versions,
        })
        self.assertEqual(set(working_diff), DIFF_KEYS | {'working_content_hash'})
        self.assertEqual((working_diff['from'], working_diff['against']), (first['version_id'], 'working'))
        self.assertEqual(working_diff['files'], between_versions + [
            {'path': 'configs/r4.cfg', 'status': 'added', 'size': None, 'against_size': size_of(config_for('r4'))},
        ])
        self.assertEqual(working_diff['working_content_hash'], self.manifest_hash('changes'))
        reverse = self.data_of(self.diff('changes', second['version_id'], first['version_id']))
        self.assertEqual({entry['path']: entry['status'] for entry in reverse['files']}, {
            'configs/core.cfg': 'unchanged', 'configs/r1.cfg': 'modified',
            'configs/r2.cfg': 'added', 'configs/r3.cfg': 'removed',
        })
        self.assertEqual(self.sandbox.version_count(), 2)
        self.assertEqual(self.sandbox.row(self.sandbox.snapshot_id('changes')).content_hash, stored_hash)

    def test_working_content_hash_is_the_hash_the_restore_dialog_sends(self):
        versions = self.build_history('dialog', 2)
        snapshot = self.sandbox.snapshots_dir / 'dialog'
        self.sandbox.settings.EXTERNAL_CHANGE_SETTLE_SECONDS = 3600
        write_file(snapshot / 'configs' / 'r1.cfg', config_for('dialog-edited'))
        write_file(snapshot / 'configs' / 'extra.cfg', config_for('dialog-extra'))
        settling = self.state_of('dialog')
        self.assertTrue(settling['external_settling'])

        summary = self.data_of(self.diff('dialog', versions[0]['version_id'], 'working'))

        self.assertEqual(summary['working_content_hash'], self.manifest_hash('dialog'))
        self.assertNotEqual(summary['working_content_hash'], settling['content_hash'])
        to_delete = [entry['path'] for entry in summary['files'] if entry['status'] == 'added']
        to_overwrite = [entry['path'] for entry in summary['files'] if entry['status'] in ('modified', 'removed')]
        self.assertEqual(to_delete, ['configs/extra.cfg', 'configs/r2.cfg'])
        self.assertEqual(to_overwrite, ['configs/r1.cfg'])

        restored = self.restore(
            'dialog', versions[0]['version_id'], {'expected_working_hash': summary['working_content_hash']},
        )

        self.assert_restored(restored, versions[0])
        self.assertEqual(sorted(path.name for path in (snapshot / 'configs').iterdir()), ['r1.cfg'])
        self.assertEqual((snapshot / 'configs' / 'r1.cfg').read_text(encoding='utf-8'), config_for('dialog-v1'))

        listed = self.data_of(self.diff('dialog', versions[1]['version_id'], 'working'))
        self.assertEqual(self.upload('dialog', 'late.cfg', config_for('dialog-late')).status_code, 200)
        stale = self.restore(
            'dialog', versions[1]['version_id'], {'expected_working_hash': listed['working_content_hash']},
        )
        self.assert_stale(stale)
        self.assertTrue((snapshot / 'configs' / 'late.cfg').is_file())

    def test_file_diff_answers_unified_hunks(self):
        old_text = ''.join(f'line {index}\n' for index in range(1, 21))
        new_text = old_text.replace('line 10\n', 'line 10 changed\n') + 'line 21\n'
        snapshot = self.sandbox.create_snapshot('hunks', {
            'configs/long.cfg': old_text,
            'configs/same.cfg': 'same\n',
            'configs/gone.cfg': 'a\nb\n',
            'configs/eol.cfg': 'a\nb\n',
        })
        first = self.state_of('hunks')['head']
        write_file(snapshot / 'configs' / 'long.cfg', new_text)
        (snapshot / 'configs' / 'gone.cfg').unlink()
        write_file(snapshot / 'configs' / 'eol.cfg', 'a\nb')
        write_file(snapshot / 'configs' / 'new.cfg', 'x\ny\n')

        def file_diff(path):
            return self.data_of(self.diff_file('hunks', first['version_id'], 'working', path))

        long_diff = file_diff('configs/long.cfg')

        self.assertEqual(set(long_diff), FILE_DIFF_KEYS)
        self.assertEqual(
            (long_diff['path'], long_diff['binary'], long_diff['too_large'], long_diff['truncated']),
            ('configs/long.cfg', False, False, False),
        )

        def lines(*entries):
            return [{'type': kind, 'text': text} for kind, text in entries]

        self.assertEqual(long_diff['hunks'], [
            {'old_start': 7, 'old_lines': 7, 'new_start': 7, 'new_lines': 7, 'lines': lines(
                (' ', 'line 7'), (' ', 'line 8'), (' ', 'line 9'), ('-', 'line 10'), ('+', 'line 10 changed'),
                (' ', 'line 11'), (' ', 'line 12'), (' ', 'line 13'),
            )},
            {'old_start': 18, 'old_lines': 3, 'new_start': 18, 'new_lines': 4, 'lines': lines(
                (' ', 'line 18'), (' ', 'line 19'), (' ', 'line 20'), ('+', 'line 21'),
            )},
        ])
        self.assertEqual(file_diff('configs/new.cfg')['hunks'], [
            {'old_start': 0, 'old_lines': 0, 'new_start': 1, 'new_lines': 2, 'lines': lines(('+', 'x'), ('+', 'y'))},
        ])
        self.assertEqual(file_diff('configs/gone.cfg')['hunks'], [
            {'old_start': 1, 'old_lines': 2, 'new_start': 0, 'new_lines': 0, 'lines': lines(('-', 'a'), ('-', 'b'))},
        ])
        self.assertEqual(file_diff('configs/same.cfg')['hunks'], [])
        self.assertEqual(self.changes(file_diff('configs/eol.cfg')), [(' ', 'a'), ('-', 'b'), ('+', 'b')])

    def test_binary_too_large_and_truncated_file_diffs(self):
        self.assertEqual(
            (app_module.config.SNAPSHOT_DIFF_MAX_BYTES, app_module.config.SNAPSHOT_DIFF_MAX_LINES), (512 * 1024, 2000),
        )
        snapshot = self.sandbox.create_snapshot('limits', {
            'configs/nul.bin': b'\x00\x01text\n',
            'configs/latin1.cfg': b'caf\xe9\n',
            'configs/text.cfg': 'text\n',
            'configs/big.cfg': 'x' * 65 + '\n',
            'configs/edge.cfg': 'y' * 63 + '\n',
            'configs/many.cfg': ''.join(f'old {index}\n' for index in range(8)),
        })
        first = self.state_of('limits')['head']
        write_file(snapshot / 'configs' / 'nul.bin', b'\x00\x02text\n')
        write_file(snapshot / 'configs' / 'latin1.cfg', 'café\n')
        write_file(snapshot / 'configs' / 'text.cfg', b'text\x00\n')
        write_file(snapshot / 'configs' / 'edge.cfg', 'z' * 63 + '\n')
        write_file(snapshot / 'configs' / 'many.cfg', ''.join(f'new {index}\n' for index in range(8)))
        write_file(snapshot / 'configs' / 'grown.cfg', 'g' * 100)
        self.sandbox.settings.SNAPSHOT_DIFF_MAX_BYTES = 64
        self.sandbox.settings.SNAPSHOT_DIFF_MAX_LINES = 5

        def file_diff(path):
            return self.data_of(self.diff_file('limits', first['version_id'], 'working', path))

        for path in ('configs/nul.bin', 'configs/latin1.cfg', 'configs/text.cfg'):
            with self.subTest(path=path):
                data = file_diff(path)
                self.assertEqual((data['binary'], data['too_large'], data['truncated'], data['hunks']),
                                 (True, False, False, []))
        history = self.sandbox.history
        with mock.patch.object(history, 'open_object', wraps=history.open_object) as opened:
            big = file_diff('configs/big.cfg')
        opened.assert_not_called()
        self.assertEqual((big['binary'], big['too_large'], big['truncated'], big['hunks']), (False, True, False, []))
        grown = file_diff('configs/grown.cfg')
        self.assertEqual((grown['too_large'], grown['hunks']), (True, []))
        edge = file_diff('configs/edge.cfg')
        self.assertFalse(edge['too_large'])
        self.assertEqual(self.changes(edge), [('-', 'y' * 63), ('+', 'z' * 63)])

        many = file_diff('configs/many.cfg')

        self.assertTrue(many['truncated'])
        self.assertEqual(self.changes(many), [('-', f'old {index}') for index in range(5)])
        for hunk in many['hunks']:
            self.assertEqual(hunk['old_lines'], sum(1 for line in hunk['lines'] if line['type'] != '+'))
            self.assertEqual(hunk['new_lines'], sum(1 for line in hunk['lines'] if line['type'] != '-'))

    def test_pathological_pair_answers_too_large_within_the_match_budget(self):
        budget = history_module.DIFF_MATCH_BUDGET
        count = int((budget * 0.45 * 110) ** 0.5)
        tokens = [f't{index:03d}' for index in range(110)]
        snapshot = self.sandbox.create_snapshot('cyclic', {
            'configs/cyclic.cfg': ''.join(f'{tokens[index % 110]}\n' for index in range(count)),
        })
        version = self.state_of('cyclic')['head']
        write_file(snapshot / 'configs' / 'cyclic.cfg',
                   ''.join(f'{tokens[(index * 7) % 110]}\n' for index in range(count)))
        created = []

        class Recording(history_module._BudgetedMatcher):
            def __init__(self, a, b, matcher_budget, strip):
                created.append(self)
                super().__init__(a, b, matcher_budget, strip)

        started = time.monotonic()
        with mock.patch.object(history_module, '_BudgetedMatcher', Recording):
            response = self.diff_file('cyclic', version['version_id'], 'working', 'configs/cyclic.cfg')
        elapsed = time.monotonic() - started

        data = self.data_of(response)
        self.assertEqual((data['binary'], data['too_large'], data['truncated'], data['hunks']),
                         (False, True, False, []))
        self.assertEqual(len(created), 2)
        self.assertTrue(all(matcher.work > 0 for matcher in created))
        self.assertLessEqual(sum(matcher.work for matcher in created), budget)
        self.assertLess(elapsed, 60)

    def test_path_must_be_a_file_of_either_side(self):
        snapshot = self.sandbox.create_snapshot('paths', {
            'configs/r1.cfg': config_for('paths-r1'), 'configs/r2.cfg': config_for('paths-r2'),
        })
        first = self.state_of('paths')['head']
        self.assertEqual(self.client.delete('/api/snapshots/paths/files/r2.cfg').status_code, 200)
        self.assertEqual(self.upload('paths', 'r3.cfg', config_for('paths-r3')).status_code, 200)
        second = self.commit('paths', {'message': 'v2'}).get_json()['data']
        (snapshot / 'configs' / 'r3.cfg').unlink()
        write_file(snapshot / 'configs' / 'w.cfg', config_for('paths-w'))
        os.symlink('r1.cfg', snapshot / 'configs' / 'link.cfg')
        write_file(self.sandbox.snapshots_dir / 'outside.cfg', OUTSIDE_SECRET)

        only_in_against = self.diff_file('paths', first['version_id'], second['version_id'], 'configs/r3.cfg')
        self.assertEqual(self.changes(self.data_of(only_in_against)),
                         [('+', line) for line in config_for('paths-r3').splitlines()])
        with self.assertLogs(STATE_LOGGER, level='WARNING'):
            working_only = self.diff_file('paths', first['version_id'], 'working', 'configs/w.cfg')
        self.assertEqual(self.changes(self.data_of(working_only)),
                         [('+', line) for line in config_for('paths-w').splitlines()])
        self.assert_removed_on_the_working_side(
            self.diff_file('paths', first['version_id'], 'working', 'configs/r2.cfg'), config_for('paths-r2'),
        )

        for against, path in (
            ('working', 'configs/missing.cfg'),
            ('working', 'configs/link.cfg'),
            (second['version_id'], 'configs/w.cfg'),
            ('working', '../outside.cfg'),
            ('working', 'configs/../configs/r1.cfg'),
            ('working', '/configs/r1.cfg'),
            ('working', 'configs'),
        ):
            with self.subTest(against=against, path=path):
                response = self.diff_file('paths', first['version_id'], against, path)
                self.assert_code(response, 400, 'validation_error')
                self.assertEqual(response.get_json()['details'], {'field': 'path'})
                self.assertNotIn(OUTSIDE_SECRET.strip(), response.get_data(as_text=True))

        for query, field in (
            ({}, 'against'),
            ({'against': ''}, 'against'),
            ({'path': 'configs/r1.cfg'}, 'against'),
            ({'against': 'working'}, 'path'),
            ({'against': 'working', 'path': ''}, 'path'),
        ):
            with self.subTest(query=query):
                response = self.client.get(
                    f"/api/snapshots/paths/versions/{first['version_id']}/diff/file", query_string=query,
                )
                self.assert_code(response, 400, 'validation_error')
                self.assertEqual(response.get_json()['details'], {'field': field})
        for query in ({}, {'against': ''}):
            with self.subTest(route='diff', query=query):
                response = self.client.get(f"/api/snapshots/paths/versions/{first['version_id']}/diff",
                                           query_string=query)
                self.assert_code(response, 400, 'validation_error')
                self.assertEqual(response.get_json()['details'], {'field': 'against'})

    def test_absent_working_entries_diff_as_removed(self):
        outside = self.sandbox.root / 'outside'
        write_file(outside / 'r2.cfg', OUTSIDE_SECRET)
        write_file(outside / 'y.cfg', OUTSIDE_SECRET)
        cases = {
            'symlink-leaving-the-root': ('configs/r2.cfg', 'configs/r2.cfg',
                                         lambda target: os.symlink(outside / 'r2.cfg', target)),
            'symlink-in-the-root': ('configs/r2.cfg', 'configs/r2.cfg', lambda target: os.symlink('r1.cfg', target)),
            'directory': ('configs/r2.cfg', 'configs/r2.cfg',
                          lambda target: write_file(target / 'inner.cfg', 'inner\n')),
            'fifo': ('configs/r2.cfg', 'configs/r2.cfg', os.mkfifo),
            'vanished': ('configs/r2.cfg', 'configs/r2.cfg', lambda target: None),
            'below-a-regular-file': ('configs/x/y.cfg', 'configs/x', lambda target: write_file(target, 'file\n')),
            'symlinked-component': ('configs/x/y.cfg', 'configs/x', lambda target: os.symlink(outside, target)),
        }
        for case, (path, replaced, make) in cases.items():
            with self.subTest(case=case):
                name = f'absent-{case}'
                files = {
                    'configs/r1.cfg': config_for(f'{name}-r1'),
                    'configs/r2.cfg': config_for(f'{name}-r2'),
                    'configs/x/y.cfg': config_for(f'{name}-y'),
                }
                snapshot = self.sandbox.create_snapshot(name, files)
                first = self.state_of(name)['head']
                write_file(snapshot / path, config_for(f'{name}-changed'))
                second = self.state_of(name)['head']
                self.assertEqual((second['seq'], second['kind']), (2, 'external'))
                remove_entry(snapshot / replaced)
                make(snapshot / replaced)

                response = self.request_within(
                    lambda: self.diff_file(name, second['version_id'], 'working', path), snapshot / replaced,
                )

                self.assert_removed_on_the_working_side(response, config_for(f'{name}-changed'))
                summary = self.data_of(self.diff(name, second['version_id'], 'working'))
                entry = next(entry for entry in summary['files'] if entry['path'] == path)
                self.assertEqual((entry['status'], entry['against_size']), ('removed', None))
                with mock.patch.object(self.sandbox.state, 'scan_tree', wraps=self.sandbox.state.scan_tree) as scan:
                    between = self.data_of(self.diff_file(name, first['version_id'], second['version_id'], path))
                scan.assert_not_called()
                old_lines = files[path].splitlines()
                new_lines = config_for(f'{name}-changed').splitlines()
                self.assertEqual(self.changes(between), [
                    ('-', old_lines[0]), ('+', new_lines[0]), (' ', old_lines[1]), (' ', old_lines[2]),
                ])

    def test_working_entry_swapped_between_the_resolver_and_the_open_is_absent(self):
        outside = self.sandbox.root / 'outside'
        write_file(outside / 'r2.cfg', OUTSIDE_SECRET)
        write_file(outside / 'y.cfg', OUTSIDE_SECRET)

        def bind_socket(target):
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(server.close)
            server.bind(str(target))

        cases = {
            'vanished': ('configs/r2.cfg', 'configs/r2.cfg', lambda target: None),
            'final-symlink': ('configs/r2.cfg', 'configs/r2.cfg',
                              lambda target: os.symlink(outside / 'r2.cfg', target)),
            'fifo': ('configs/r2.cfg', 'configs/r2.cfg', os.mkfifo),
            'socket': ('configs/r2.cfg', 'configs/r2.cfg', bind_socket),
            'directory': ('configs/r2.cfg', 'configs/r2.cfg', os.mkdir),
            'component-symlink': ('configs/x/y.cfg', 'configs/x', lambda target: os.symlink(outside, target)),
            'component-file': ('configs/x/y.cfg', 'configs/x', lambda target: write_file(target, 'file\n')),
            'component-fifo': ('configs/x/y.cfg', 'configs/x', os.mkfifo),
        }
        resolver = app_module.snapshot_service._resolve_snapshot_relative_path
        for case, (path, replaced, make) in cases.items():
            with self.subTest(case=case):
                name = f'swap-{case}'
                files = {'configs/r1.cfg': config_for(f'{name}-r1'), path: config_for(f'{name}-file')}
                snapshot = self.sandbox.create_snapshot(name, files)
                version = self.state_of(name)['head']
                swaps = []

                def resolve_then_swap(snapshot_dir, relative_path, replaced=replaced, make=make, snapshot=snapshot):
                    resolved = resolver(snapshot_dir, relative_path)
                    if not swaps:
                        remove_entry(snapshot / replaced)
                        make(snapshot / replaced)
                        swaps.append(relative_path)
                    return resolved

                with mock.patch.object(app_module.snapshot_service, '_resolve_snapshot_relative_path',
                                       side_effect=resolve_then_swap):
                    response = self.request_within(
                        lambda: self.diff_file(name, version['version_id'], 'working', path), snapshot / replaced,
                    )

                self.assertEqual(swaps, [Path(path)])
                self.assert_removed_on_the_working_side(response, config_for(f'{name}-file'))

    def test_resolver_rejection_is_absent_on_the_working_side(self):
        snapshot = self.sandbox.create_snapshot('rejected', {'configs/r1.cfg': config_for('rejected-r1')})
        version = self.state_of('rejected')['head']
        write_file(snapshot / 'configs' / 'r1.cfg', config_for('rejected-working'))

        with mock.patch.object(app_module.snapshot_service, '_resolve_snapshot_relative_path',
                               side_effect=ValueError('Artifact path escapes snapshot root')) as resolver:
            response = self.diff_file('rejected', version['version_id'], 'working', 'configs/r1.cfg')

        resolver.assert_called_once()
        self.assert_removed_on_the_working_side(response, config_for('rejected-r1'))

    def test_object_trashed_after_the_manifest_read_is_version_not_found(self):
        history = self.sandbox.history
        original = history._read_diff_manifests
        for side in ('version', 'against'):
            with self.subTest(side=side):
                name = f'trashed-{side}'
                first, second = self.build_history(name, 2, rewrite=True)
                snapshot = self.sandbox.snapshots_dir / name
                snapshot_id = self.sandbox.snapshot_id(name)

                def read_then_delete(*args, snapshot=snapshot, snapshot_id=snapshot_id, first=first):
                    manifests = original(*args)
                    history.delete_versions(snapshot_id, snapshot, 'single', version_id=first['version_id'])
                    return manifests

                with mock.patch.object(history, '_read_diff_manifests', side_effect=read_then_delete), \
                        self.assertNoLogs('app', level='ERROR'):
                    if side == 'version':
                        response = self.diff_file(name, first['version_id'], 'working', 'configs/r1.cfg')
                    else:
                        response = self.diff_file(name, second['version_id'], first['version_id'], 'configs/r1.cfg')

                self.assertFalse(self.object_path(config_for(f'{name}-v1')).exists())
                self.assert_code(response, 404, 'version_not_found')

    def test_object_missing_while_the_version_exists_is_500(self):
        first, _ = self.build_history('lost-object', 2, rewrite=True)
        self.object_path(config_for('lost-object-v1')).unlink()

        with self.assertLogs('app', level='ERROR') as logs:
            response = self.diff_file('lost-object', first['version_id'], 'working', 'configs/r1.cfg')

        self.assert_code(response, 500, None)
        self.assertNotIn('hostname', response.get_data(as_text=True))
        self.assertNotIn('hostname', '\n'.join(logs.output))

    def test_unknown_and_foreign_versions_are_version_not_found(self):
        mine = [version['version_id'] for version in self.build_history('mine', 2)]
        theirs = self.build_history('theirs', 1)[0]['version_id']

        for route in ('diff', 'diff/file'):
            def call(name, version_id, against, route=route):
                if route == 'diff':
                    return self.diff(name, version_id, against)
                return self.diff_file(name, version_id, against, 'configs/r1.cfg')

            for name, version_id, against in (
                ('mine', UNKNOWN_VERSION_ID, 'working'),
                ('mine', mine[0], UNKNOWN_VERSION_ID),
                ('mine', theirs, 'working'),
                ('mine', mine[0], theirs),
                ('theirs', mine[0], 'working'),
                ('theirs', theirs, mine[1]),
            ):
                with self.subTest(route=route, name=name, version_id=version_id, against=against):
                    self.assert_code(call(name, version_id, against), 404, 'version_not_found')
            with self.subTest(route=route, name='nowhere'):
                self.assert_code(call('nowhere', mine[0], 'working'), 404, 'snapshot_not_found')
                self.assertEqual(call('bad%20name', mine[0], 'working').status_code, 400)

    def test_diff_routes_are_matched_by_endpoint_and_never_take_the_batfish_lock(self):
        for name in ('files-x', 'artifacts-x'):
            for path in (f'/api/snapshots/{name}/versions/{UNKNOWN_VERSION_ID}/diff',
                         f'/api/snapshots/{name}/versions/{UNKNOWN_VERSION_ID}/diff/file'):
                with self.subTest(path=path):
                    with app_module.app.test_request_context(f'{path}?against=working&path=configs/r1.cfg'):
                        self.assertFalse(app_module.request_uses_batfish())

        versions = self.build_history('files-x', 2)
        lock = mock.MagicMock()
        with mock.patch.object(app_module, 'batfish_request_lock', lock):
            summary = self.diff('files-x', versions[0]['version_id'], 'working')
            file_diff = self.diff_file('files-x', versions[0]['version_id'], versions[1]['version_id'],
                                       'configs/r2.cfg')
        self.assertEqual((summary.status_code, file_diff.status_code), (200, 200))
        lock.acquire.assert_not_called()


class DiffUnavailableRouteTest(DiffRouteTestCase):
    def assert_diff_unavailable(self, name: str, version_id: str, path: str, reason: str):
        for route, response in (
            ('diff', self.diff(name, version_id, 'working')),
            ('diff/file', self.diff_file(name, version_id, 'working', path)),
        ):
            with self.subTest(route=route, reason=reason):
                self.assert_code(response, 503, 'versioning_unavailable')
                self.assertEqual(response.get_json()['details'], {'reason': reason})

    def test_absent_or_empty_object_store_answers_storage_on_both_diff_routes(self):
        self.sandbox.create_snapshot('stored', {'configs/r1.cfg': CONFIG_R1})
        stored = self.state_of('stored')['head']
        objects_dir = self.sandbox.history.objects_dir
        for store in ('absent', 'empty'):
            with self.subTest(store=store):
                if objects_dir.exists():
                    shutil.rmtree(objects_dir)
                if store == 'empty':
                    objects_dir.mkdir()
                with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
                    self.restart()

                self.assert_diff_unavailable('stored', stored['version_id'], 'configs/r1.cfg', 'storage')

    def test_missing_objects_answer_503_on_both_diff_routes_for_the_affected_snapshot_only(self):
        self.sandbox.create_snapshot('lost', {'configs/r1.cfg': CONFIG_R1})
        self.sandbox.create_snapshot('kept', {'configs/r2.cfg': CONFIG_R2})
        lost = self.state_of('lost')['head']
        kept = self.state_of('kept')['head']
        self.object_path(CONFIG_R1).unlink()
        with self.assertLogs(HISTORY_LOGGER, level='ERROR'):
            self.restart()

        self.assert_diff_unavailable('lost', lost['version_id'], 'configs/r1.cfg', 'missing_objects')
        self.assertEqual(self.data_of(self.diff('kept', kept['version_id'], 'working'))['files'][0]['status'],
                         'unchanged')
        self.assertEqual(self.data_of(self.diff_file('kept', kept['version_id'], 'working', 'configs/r2.cfg'))['hunks'],
                         [])


class EndpointMatchingAndOptionalBodyRouteTest(RestoreRouteTestCase):
    NEW_ENDPOINTS = frozenset({
        'get_snapshot_version_state',
        'list_snapshot_versions',
        'commit_snapshot_version',
        'get_snapshot_version',
        'get_snapshot_version_diff',
        'get_snapshot_version_file_diff',
        'restore_snapshot_version',
        'delete_snapshot_version',
        'delete_snapshot_versions',
        'clear_snapshot_result_cache',
        'get_result_cache_stats',
        'purge_snapshot_history_orphans',
        'list_snapshot_history_namespaces',
    })

    def test_every_new_route_is_matched_by_endpoint_before_the_path_rules(self):
        rules = [rule for rule in app_module.app.url_map.iter_rules() if rule.endpoint in self.NEW_ENDPOINTS]
        self.assertEqual({rule.endpoint for rule in rules}, self.NEW_ENDPOINTS)
        adapter = app_module.app.url_map.bind('localhost')
        for name in ('files-x', 'artifacts-x'):
            values = {'name': name, 'version_id': UNKNOWN_VERSION_ID}
            for rule in rules:
                (method,) = rule.methods - {'HEAD', 'OPTIONS'}
                path = adapter.build(rule.endpoint, {key: values[key] for key in rule.arguments}, method=method)
                with self.subTest(name=name, endpoint=rule.endpoint):
                    with app_module.app.test_request_context(path, method=method):
                        self.assertEqual(flask_request.endpoint, rule.endpoint)
                        self.assertIs(app_module.request_uses_batfish(), rule.endpoint == 'restore_snapshot_version')

    def test_cache_clear_of_a_snapshot_named_files_x_never_takes_the_batfish_lock(self):
        self.sandbox.create_snapshot('files-x')
        self.version_state('files-x')
        lock = mock.MagicMock()

        with mock.patch.object(app_module, 'batfish_request_lock', lock):
            response = self.client.post('/api/snapshots/files-x/cache/clear')

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()['data'], {'cleared': False})
        lock.acquire.assert_not_called()

    def test_body_less_posts_to_restore_and_cache_clear_are_not_rejected_as_invalid_json(self):
        versions = self.build_history('bodyless', 2)
        restore_path = f"/api/snapshots/bodyless/versions/{versions[0]['version_id']}/restore"
        clear_path = '/api/snapshots/bodyless/cache/clear'

        for headers in ({}, {'Content-Type': 'application/json'}):
            with self.subTest(route='restore', headers=headers):
                self.assert_restored(self.client.post(restore_path, headers=headers), versions[0])
            with self.subTest(route='cache/clear', headers=headers):
                response = self.client.post(clear_path, headers=headers)
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()['data'], {'cleared': False})

        for path in (restore_path, clear_path):
            with self.subTest(path=path):
                malformed = self.client.post(path, data='{bad', content_type='application/json')
                self.assert_code(malformed, 400, 'invalid_json')
        self.assert_code(self.client.post('/api/snapshots/bodyless/versions'), 400, 'invalid_json')


class _StubVersionProbe:
    clock = staticmethod(lambda: 0.0)

    def __init__(self, version: str):
        self.version = version

    def current(self):
        return self.version

    def peek(self):
        return self.version

    def feed(self, version, observed_at):
        return self.version

    def snapshot_status(self, network, snapshot):
        return 200, '{}'


class _UploadRecordingSession:
    def __init__(self):
        self.network = None
        self.snapshot = None
        self.uploads = []

    def set_network(self, name):
        self.network = name

    def get_component_versions(self):
        return {'Batfish': '2025.07.07.2423'}

    def init_snapshot(self, path, name=None, overwrite=False):
        self.uploads.append((Path(path).name, name))
        self.snapshot = name
        return name


class LoadedStateAndBypassRouteTest(VersionRouteTestCase):
    """Loaded-state fields recorded by an activation and the cache bypass of an unavailable snapshot."""

    sandbox_options = {'RESULT_CACHE_ENABLED': True}
    SAVED = ('_session', 'version_probe', '_state_service', 'loaded_clear_counter', 'activation_payload',
             'activation_failures', 'last_upload_hash')

    def setUp(self):
        super().setUp()
        service = self.batfish_service
        self.saved_service = {name: getattr(service, name) for name in self.SAVED}
        self.originals_cache = app_module.result_cache
        self.cache = ResultCache(
            self.sandbox.settings.RESULT_CACHE_DIR, max_bytes=10 ** 9, max_entries=10 ** 6, protect_seconds=900,
            build_id='build', pybatfish_version='pyb', schema_version=1,
        )
        self.sandbox.history.attach_result_cache(self.cache)
        app_module.result_cache = self.cache
        self.session = _UploadRecordingSession()
        service._session = self.session
        service.version_probe = _StubVersionProbe('2025.07.07.2423')
        service.attach_state_service(self.sandbox.state)
        service.activation_failures = ActivationFailureCache()
        service.network_name = app_module.config.BATFISH_NETWORK
        service.current_snapshot_name = None
        service._initialized = False
        service._reset_loaded_state()
        self.patches = [
            mock.patch.object(service, name, return_value=[])
            for name in ('get_file_parse_status', 'get_init_issues', 'get_parse_warnings')
        ]
        self.patches.append(mock.patch.object(service, 'get_node_properties', side_effect=self.node_properties))
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        for name, value in self.saved_service.items():
            setattr(self.batfish_service, name, value)
        app_module.result_cache = self.originals_cache
        super().tearDown()

    def node_properties(self):
        self.batfish_service._ensure_initialized()
        return [{'node': 'r1'}]

    def test_activation_records_the_loaded_hash_and_batfish_version(self):
        self.sandbox.create_snapshot('loaded')

        activate = self.client.post('/api/snapshots/loaded/activate')

        self.assertEqual(activate.status_code, 200, activate.get_data(as_text=True)[:300])
        data = self.version_state('loaded').get_json()['data']
        self.assertEqual(data['loaded_content_hash'], data['content_hash'])
        self.assertIsNotNone(data['content_hash'])
        self.assertEqual(data['loaded_batfish_version'], '2025.07.07.2423')
        self.assertFalse(data['loaded_live'])
        self.assertTrue(data['result_cache_enabled'])
        self.assertEqual(self.session.uploads, [('loaded', 'loaded')])

    def test_lazy_activation_of_a_cached_miss_records_the_loaded_fields(self):
        self.sandbox.create_snapshot('lazy')
        self.batfish_service.current_snapshot_name = 'lazy'

        response = self.client.get('/api/network/nodes')

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.headers['X-Topologix-Cache'], 'stored')
        data = self.version_state('lazy').get_json()['data']
        self.assertEqual(data['loaded_content_hash'], data['content_hash'])
        self.assertEqual(response.headers['X-Topologix-Content-Hash'], data['content_hash'])
        self.assertEqual(data['loaded_batfish_version'], '2025.07.07.2423')

    @unittest.skipIf(IS_ROOT, "directory permissions are not enforced for root")
    def test_read_only_directory_bypasses_the_cache_while_version_routes_answer_503(self):
        snapshot = self.sandbox.snapshots_dir / 'frozen'
        write_file(snapshot / 'configs' / 'r1.cfg', CONFIG_R1)
        os.chmod(snapshot, 0o555)
        self.batfish_service.current_snapshot_name = 'frozen'

        with self.assertLogs('services.snapshot_state_service', level='WARNING'):
            state = self.version_state('frozen')
        nodes = self.client.get('/api/network/nodes')
        os.chmod(snapshot, 0o755)

        self.assertEqual(state.status_code, 503)
        self.assertEqual(state.get_json()['details'], {'reason': 'sidecar'})
        self.assertEqual(nodes.status_code, 200, nodes.get_data(as_text=True)[:300])
        self.assertEqual(nodes.headers['X-Topologix-Cache'], 'bypass')
        self.assertEqual(nodes.headers['X-Topologix-Content-Hash'], '')
        self.assertEqual(nodes.headers['Cache-Control'], 'no-store')
        self.assertNotIn('ETag', nodes.headers)
        self.assertEqual(self.cache.stats()['entries'], 0)

    def test_snapshot_delete_clears_the_stored_active_snapshot_even_when_the_purge_fails(self):
        self.sandbox.create_snapshot('stored-name')
        self.assertEqual(self.client.post('/api/snapshots/stored-name/activate').status_code, 200)
        active_file = self.sandbox.data_dir / self.sandbox.state.namespace / 'active_snapshot.json'
        self.assertTrue(active_file.is_file())
        self.batfish_service.current_snapshot_name = None

        with mock.patch.object(self.sandbox.history, '_purge_deleted_snapshot_rows',
                               side_effect=OperationalError('DELETE', {}, Exception('database is unavailable'))), \
                self.assertLogs(HISTORY_LOGGER, level='WARNING'):
            response = self.client.delete('/api/snapshots/stored-name')

        self.assertEqual(response.status_code, 200)
        self.assertFalse(active_file.exists())
        self.assertIsNone(self.batfish_service.current_snapshot_name)


AUTH_VERSION_SCRIPT = r'''
import io
import json
import os

from app import app

ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
CONFIG = b"hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
CONFIG_2 = b"hostname r2\ninterface Loopback0\n ip address 192.0.2.2 255.255.255.255\n"
results = {}


def login(username, password):
    client = app.test_client()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    data = (response.get_json(silent=True) or {}).get("data") or {}
    client.environ_base["HTTP_X_CSRF_TOKEN"] = data.get("csrf_token") or ""
    return client


def record(key, response):
    payload = response.get_json(silent=True) or {}
    results[key] = {"status": response.status_code, "code": payload.get("code"), "data": payload.get("data")}


admin = login("admin", ADMIN_PASSWORD)
bearer = {"Authorization": f"Bearer {admin.get_cookie('access_token').value}"}
created = admin.post(
    "/api/users",
    json={"username": "bob", "email": "bob@example.test", "password": "Pw!bobA9xyz12"},
    headers=bearer,
)
results["create_user"] = created.status_code
admin.post("/api/snapshots", json={"name": "owned"})
admin.post("/api/snapshots/owned/files", data={"file": (io.BytesIO(CONFIG), "r1.cfg")},
           content_type="multipart/form-data")
record("owner_state", admin.get("/api/snapshots/owned/version-state"))
admin.post("/api/snapshots/owned/files", data={"file": (io.BytesIO(CONFIG_2), "r2.cfg")},
           content_type="multipart/form-data")
record("owner_commit", admin.post("/api/snapshots/owned/versions", json={"message": "admin commit"}))
record("owner_list", admin.get("/api/snapshots/owned/versions"))

bob = login("bob", "Pw!bobA9xyz12")
record("other_state", bob.get("/api/snapshots/owned/version-state"))
record("other_list", bob.get("/api/snapshots/owned/versions"))
record("other_commit", bob.post("/api/snapshots/owned/versions", json={"message": "bob commit"}))
record("anonymous_state", app.test_client().get("/api/snapshots/owned/version-state"))

oldest_id = admin.get("/api/snapshots/owned/versions").get_json()["data"]["items"][-1]["version_id"]
record("other_delete_single", bob.delete(f"/api/snapshots/owned/versions/{oldest_id}"))
record("other_delete_all", bob.delete("/api/snapshots/owned/versions", json={"mode": "all"}))
record("other_namespaces", bob.get("/api/admin/snapshot-history/namespaces"))
record("other_orphans", bob.delete("/api/admin/snapshot-history/orphans", json={"older_than_days": 0}))
record("anonymous_namespaces", app.test_client().get("/api/admin/snapshot-history/namespaces"))
tokenless = login("bob", "Pw!bobA9xyz12")
tokenless.delete_cookie("access_token")
record("anonymous_orphans", tokenless.delete("/api/admin/snapshot-history/orphans", json={"older_than_days": 0}))
record("admin_namespaces", admin.get("/api/admin/snapshot-history/namespaces"))
record("admin_orphans", admin.delete("/api/admin/snapshot-history/orphans", json={"older_than_days": 0}))
record("owner_delete_single", admin.delete(f"/api/snapshots/owned/versions/{oldest_id}"))
record("owner_list_after_delete", admin.get("/api/snapshots/owned/versions"))
print(json.dumps(results))
'''


class AuthVersionRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / 'snapshots').mkdir()
            (root / 'data').mkdir()
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "version-route-test-secret-key",
                "JWT_SECRET_KEY": "version-route-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "version-route-test-csrf-secret-key",
                "CSRF_MODE": "session",
                "ALLOW_REGISTRATION": "true",
                "AUTH_DEFAULT_ADMIN_USER": "admin",
                "AUTH_DEFAULT_ADMIN_PASS": "VersionRouteAdmin123!",
                "DATABASE_URL": f"sqlite:///{root / 'version-routes.db'}",
                "SNAPSHOTS_DIR": str(root / 'snapshots'),
                "DATA_DIR": str(root / 'data'),
                "PYTHONPATH": str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, "-c", AUTH_VERSION_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def test_owner_reaches_the_version_routes_and_is_recorded_as_author(self):
        self.assertEqual(self.results["create_user"], 201)
        self.assertEqual(self.results["owner_state"]["status"], 200)
        self.assertEqual(self.results["owner_state"]["data"]["head"]["kind"], "baseline")
        self.assertEqual(self.results["owner_commit"]["status"], 201)
        self.assertEqual(self.results["owner_commit"]["data"]["author"], "admin")
        self.assertEqual(self.results["owner_list"]["data"]["total"], 2)

    def test_other_users_and_anonymous_requests_are_rejected(self):
        for key in ("other_state", "other_list", "other_commit"):
            self.assertEqual(self.results[key]["status"], 403, key)
        self.assertEqual(self.results["anonymous_state"]["status"], 401)

    def test_history_deletion_is_owner_only(self):
        for key in ("other_delete_single", "other_delete_all"):
            self.assertEqual(self.results[key]["status"], 403, key)
        self.assertEqual(self.results["owner_delete_single"]["status"], 200)
        self.assertEqual(self.results["owner_delete_single"]["data"]["deleted"], 1)
        self.assertEqual(self.results["owner_list_after_delete"]["data"]["total"], 1)

    def test_admin_snapshot_history_routes_require_the_admin_role(self):
        for key in ("anonymous_namespaces", "anonymous_orphans"):
            self.assertEqual(self.results[key]["status"], 401, key)
        for key in ("other_namespaces", "other_orphans"):
            self.assertEqual(self.results[key]["status"], 403, key)
        self.assertEqual(self.results["admin_namespaces"]["status"], 200)
        items = self.results["admin_namespaces"]["data"]["items"]
        self.assertEqual([(item["current"], item["rows"]) for item in items], [(True, 1)])
        self.assertEqual(self.results["admin_orphans"]["status"], 200)
        self.assertEqual(self.results["admin_orphans"]["data"], {"purged": 0, "last_seen_at": None})


AUTH_RESTORE_SCRIPT = r'''
import io
import json
import os

from app import app

ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
CONFIG = b"hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
CONFIG_2 = b"hostname r2\ninterface Loopback0\n ip address 192.0.2.2 255.255.255.255\n"
results = {}


def login(username, password):
    client = app.test_client()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    data = (response.get_json(silent=True) or {}).get("data") or {}
    client.environ_base["HTTP_X_CSRF_TOKEN"] = data.get("csrf_token") or ""
    return client


def record(key, response):
    payload = response.get_json(silent=True) or {}
    results[key] = {"status": response.status_code, "code": payload.get("code"), "data": payload.get("data")}


def upload(client, filename, content):
    return client.post("/api/snapshots/owned/files", data={"file": (io.BytesIO(content), filename)},
                       content_type="multipart/form-data").status_code


admin = login("admin", ADMIN_PASSWORD)
bearer = {"Authorization": f"Bearer {admin.get_cookie('access_token').value}"}
results["create_user"] = admin.post(
    "/api/users",
    json={"username": "bob", "email": "bob@example.test", "password": "Pw!bobA9xyz12"},
    headers=bearer,
).status_code
admin.post("/api/snapshots", json={"name": "owned"})
results["setup"] = [upload(admin, "r1.cfg", CONFIG)]
results["setup"].append(admin.post("/api/snapshots/owned/versions", json={"message": "add r1"}).status_code)
first = admin.get("/api/snapshots/owned/version-state").get_json()["data"]
results["target"] = first["head"]
results["target_hash"] = first["content_hash"]
results["setup"].append(upload(admin, "r2.cfg", CONFIG_2))
results["setup"].append(admin.post("/api/snapshots/owned/versions", json={"message": "add r2"}).status_code)
target = f"/api/snapshots/owned/versions/{first['head']['version_id']}/restore"

bob = login("bob", "Pw!bobA9xyz12")
record("other_restore", bob.post(target))
tokenless = login("bob", "Pw!bobA9xyz12")
tokenless.delete_cookie("access_token")
record("anonymous_restore", tokenless.post(target))
record("state_after_rejections", admin.get("/api/snapshots/owned/version-state"))
working_hash = results["state_after_rejections"]["data"]["content_hash"]
record("owner_restore", admin.post(target, json={"expected_working_hash": working_hash}))
record("owner_state", admin.get("/api/snapshots/owned/version-state"))
record("owner_commit", admin.post("/api/snapshots/owned/versions", json={"message": "restored"}))
print(json.dumps(results))
'''


class AuthRestoreRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / 'snapshots').mkdir()
            (root / 'data').mkdir()
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "restore-route-test-secret-key",
                "JWT_SECRET_KEY": "restore-route-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "restore-route-test-csrf-secret-key",
                "CSRF_MODE": "session",
                "ALLOW_REGISTRATION": "true",
                "AUTH_DEFAULT_ADMIN_USER": "admin",
                "AUTH_DEFAULT_ADMIN_PASS": "RestoreRouteAdmin123!",
                "DATABASE_URL": f"sqlite:///{root / 'restore-routes.db'}",
                "SNAPSHOTS_DIR": str(root / 'snapshots'),
                "DATA_DIR": str(root / 'data'),
                "PYTHONPATH": str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, "-c", AUTH_RESTORE_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def test_only_the_owner_restores_and_the_commit_is_kind_restore(self):
        results = self.results
        target_ref = {"version_id": results["target"]["version_id"], "seq": 2}
        self.assertEqual(results["create_user"], 201)
        self.assertEqual(results["setup"], [200, 201, 200, 201])
        self.assertEqual(results["other_restore"]["status"], 403)
        self.assertEqual(results["anonymous_restore"]["status"], 401)
        untouched = results["state_after_rejections"]["data"]
        self.assertFalse(untouched["uncommitted"])
        self.assertIsNone(untouched["restored_from"])

        self.assertEqual(results["owner_restore"]["status"], 200)
        self.assertEqual(results["owner_restore"]["data"],
                         {"requires_reinitialize": True, "restored_from": target_ref})
        restored = results["owner_state"]["data"]
        self.assertEqual(restored["content_hash"], results["target_hash"])
        self.assertTrue(restored["uncommitted"])
        self.assertEqual(restored["restored_from"], target_ref)
        self.assertEqual(results["owner_commit"]["status"], 201)
        self.assertEqual((results["owner_commit"]["data"]["kind"], results["owner_commit"]["data"]["author"]),
                         ("restore", "admin"))


AUTH_DIFF_SCRIPT = r'''
import io
import json
import os

from app import app

ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
UNKNOWN = "00000000-0000-4000-8000-000000000000"
INTERFACE = b"interface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
results = {}


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
        "has_config": b"hostname" in response.get_data(),
        "cache_control": response.headers.get("Cache-Control"),
    }


def upload(client, snapshot, filename, content):
    return client.post(f"/api/snapshots/{snapshot}/files", data={"file": (io.BytesIO(content), filename)},
                       content_type="multipart/form-data").status_code


admin = login("admin", ADMIN_PASSWORD)
bearer = {"Authorization": f"Bearer {admin.get_cookie('access_token').value}"}
results["create_user"] = admin.post(
    "/api/users",
    json={"username": "bob", "email": "bob@example.test", "password": "Pw!bobA9xyz12"},
    headers=bearer,
).status_code
admin.post("/api/snapshots", json={"name": "owned"})
results["setup"] = [upload(admin, "owned", "r1.cfg", b"hostname owner-v1\n" + INTERFACE)]
results["setup"].append(admin.post("/api/snapshots/owned/versions", json={"message": "add r1"}).status_code)
first = admin.get("/api/snapshots/owned/version-state").get_json()["data"]["head"]["version_id"]
results["setup"].append(upload(admin, "owned", "r1.cfg", b"hostname owner-v2\n" + INTERFACE))
diff_url = f"/api/snapshots/owned/versions/{first}/diff?against=working"
file_url = f"/api/snapshots/owned/versions/{first}/diff/file?against=working&path=configs/r1.cfg"
unknown_url = f"/api/snapshots/owned/versions/{UNKNOWN}/diff/file?against=working&path=configs/nope.cfg"

record("owner_diff", admin.get(diff_url))
record("owner_file", admin.get(file_url))
bob = login("bob", "Pw!bobA9xyz12")
record("other_diff", bob.get(diff_url))
record("other_file", bob.get(file_url))
record("other_unknown", bob.get(unknown_url))
record("anonymous_diff", app.test_client().get(diff_url))
record("anonymous_file", app.test_client().get(file_url))

bob.post("/api/snapshots", json={"name": "theirs"})
results["setup"].append(upload(bob, "theirs", "r1.cfg", b"hostname bob-v1\n" + INTERFACE))
own = bob.get("/api/snapshots/theirs/version-state").get_json()["data"]["head"]["version_id"]
record("foreign_against", bob.get(f"/api/snapshots/theirs/versions/{own}/diff?against={first}"))
record("foreign_version",
       bob.get(f"/api/snapshots/theirs/versions/{first}/diff/file?against=working&path=configs/r1.cfg"))
record("own_file", bob.get(f"/api/snapshots/theirs/versions/{own}/diff/file?against=working&path=configs/r1.cfg"))
print(json.dumps(results))
'''


class AuthDiffRouteTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / 'snapshots').mkdir()
            (root / 'data').mkdir()
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "diff-route-test-secret-key",
                "JWT_SECRET_KEY": "diff-route-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "diff-route-test-csrf-secret-key",
                "CSRF_MODE": "session",
                "ALLOW_REGISTRATION": "true",
                "AUTH_DEFAULT_ADMIN_USER": "admin",
                "AUTH_DEFAULT_ADMIN_PASS": "DiffRouteAdmin123!",
                "DATABASE_URL": f"sqlite:///{root / 'diff-routes.db'}",
                "SNAPSHOTS_DIR": str(root / 'snapshots'),
                "DATA_DIR": str(root / 'data'),
                "PYTHONPATH": str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, "-c", AUTH_DIFF_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def test_owner_reads_the_diff_with_no_store(self):
        results = self.results
        self.assertEqual(results["create_user"], 201)
        self.assertEqual(results["setup"], [200, 201, 200, 200])
        self.assertEqual(results["owner_diff"]["status"], 200)
        self.assertEqual([(entry["path"], entry["status"]) for entry in results["owner_diff"]["data"]["files"]],
                         [("configs/r1.cfg", "modified")])
        owner_file = results["owner_file"]
        self.assertEqual(owner_file["status"], 200)
        self.assertEqual([(line["type"], line["text"]) for hunk in owner_file["data"]["hunks"] for line in hunk["lines"]],
                         [("-", "hostname owner-v1"), ("+", "hostname owner-v2"), (" ", "interface Loopback0"),
                          (" ", " ip address 192.0.2.1 255.255.255.255")])
        self.assertIn("no-store", owner_file["cache_control"])

    def test_other_users_and_anonymous_requests_learn_nothing(self):
        results = self.results
        for key in ("other_diff", "other_file", "other_unknown"):
            with self.subTest(key=key):
                self.assertEqual((results[key]["status"], results[key]["data"], results[key]["has_config"]),
                                 (403, None, False))
        for key in ("anonymous_diff", "anonymous_file"):
            with self.subTest(key=key):
                self.assertEqual((results[key]["status"], results[key]["data"], results[key]["has_config"]),
                                 (401, None, False))

    def test_versions_of_another_snapshot_are_version_not_found(self):
        results = self.results
        for key in ("foreign_against", "foreign_version"):
            with self.subTest(key=key):
                self.assertEqual((results[key]["status"], results[key]["code"], results[key]["has_config"]),
                                 (404, "version_not_found", False))
        self.assertEqual(results["own_file"]["status"], 200)


if __name__ == '__main__':
    unittest.main()
