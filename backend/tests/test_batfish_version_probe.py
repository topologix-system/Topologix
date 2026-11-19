import test_00_environment  # noqa: F401
import json
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import services.batfish_version_probe as probe_module
from services.batfish_service import BatfishService
from services.batfish_version_probe import BatfishProbeError, BatfishVersionProbe


class _CoordinatorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        server = self.server
        server.requests.append((self.path, dict(self.headers)))
        status, body = server.answers.get(self.path, (404, 'Network missing'))
        payload = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        return None


class FakeCoordinator:
    def __init__(self, answers: dict):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), _CoordinatorHandler)
        self.server.answers = answers
        self.server.requests = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def requests(self) -> list:
        return self.server.requests

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FakeClock:
    def __init__(self, now: float = 1_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class ProbeHttpTest(unittest.TestCase):
    def setUp(self):
        self.coordinator = FakeCoordinator({
            '/v2/version': (200, json.dumps({'Batfish': '2025.07.07.2423', 'Z3': '4.13'})),
            '/v2/networks/net%2Fa/snapshots/snap%20b': (200, '{"name": "snap b"}'),
        })
        self.addCleanup(self.coordinator.close)

    def test_version_is_fetched_from_the_component_versions_endpoint(self):
        probe = BatfishVersionProbe('127.0.0.1', self.coordinator.port)

        self.assertEqual(probe.current(), '2025.07.07.2423')
        path, headers = self.coordinator.requests[0]
        self.assertEqual(path, '/v2/version')
        self.assertIn('X-Batfish-Version', headers)

    def test_probe_never_touches_or_mutates_the_batfish_service(self):
        service = BatfishService()
        before = dict(service.__dict__)
        probe = BatfishVersionProbe('127.0.0.1', self.coordinator.port)

        with mock.patch.object(BatfishService, 'session', new_callable=mock.PropertyMock) as session:
            session.side_effect = AssertionError('the probe must not use the pybatfish session')
            self.assertEqual(probe.current(), '2025.07.07.2423')

        session.assert_not_called()
        self.assertEqual(service.__dict__, before)
        self.assertIsNone(service._session)

    def test_snapshot_status_quotes_names_and_returns_404_bodies(self):
        probe = BatfishVersionProbe('127.0.0.1', self.coordinator.port)

        self.assertEqual(probe.snapshot_status('net/a', 'snap b'), (200, '{"name": "snap b"}'))
        self.assertEqual(probe.snapshot_status('net', 'missing'), (404, 'Network missing'))

    def test_connection_refusal_raises_quickly(self):
        probe = BatfishVersionProbe('127.0.0.1', 1)
        started = time.monotonic()

        with self.assertRaises(BatfishProbeError):
            probe.snapshot_status('net', 'snap')
        with self.assertLogs('services.batfish_version_probe', level='WARNING'):
            self.assertIsNone(probe.current())

        self.assertLess(time.monotonic() - started, 2.0)


class StalledSocketTest(unittest.TestCase):
    def test_probe_times_out_within_two_seconds_against_a_stalled_socket(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(5)
        self.addCleanup(listener.close)
        accepted = []

        def accept_and_stall():
            try:
                connection, _ = listener.accept()
                accepted.append(connection)
            except OSError:
                pass

        threading.Thread(target=accept_and_stall, daemon=True).start()
        probe = BatfishVersionProbe('127.0.0.1', listener.getsockname()[1])
        started = time.monotonic()

        with self.assertLogs('services.batfish_version_probe', level='WARNING'):
            self.assertIsNone(probe.current())

        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 1.5)
        self.assertLess(elapsed, 6.0)
        for connection in accepted:
            connection.close()


class ProbeCachingTest(unittest.TestCase):
    def make_probe(self, clock: FakeClock, results: list) -> tuple[BatfishVersionProbe, list]:
        probe = BatfishVersionProbe('127.0.0.1', 1, ttl_seconds=300, grace_seconds=3600, clock=clock)
        calls = []

        def fetch():
            calls.append(clock.now)
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        probe.fetch_version = fetch
        return probe, calls

    def test_answers_are_cached_for_the_ttl(self):
        clock = FakeClock()
        probe, calls = self.make_probe(clock, ['v1', 'v2'])

        self.assertEqual(probe.current(), 'v1')
        clock.now += 299
        self.assertEqual(probe.current(), 'v1')
        self.assertEqual(len(calls), 1)
        clock.now += 2
        self.assertEqual(probe.current(), 'v2')
        self.assertEqual(len(calls), 2)

    def test_failures_are_negative_cached_and_grace_serves_the_last_value(self):
        clock = FakeClock()
        failure = BatfishProbeError('down')
        probe, calls = self.make_probe(clock, ['v1', failure, failure, failure])

        self.assertEqual(probe.current(), 'v1')
        clock.now += 301
        with self.assertLogs('services.batfish_version_probe', level='WARNING'):
            self.assertEqual(probe.current(), 'v1')
        clock.now += 29
        self.assertEqual(probe.current(), 'v1')
        self.assertEqual(len(calls), 2)
        clock.now += 2
        self.assertEqual(probe.current(), 'v1')
        self.assertEqual(len(calls), 3)

        clock.now = 1_000.0 + 3_601
        self.assertIsNone(probe.current())
        self.assertIsNone(probe.peek())

    def test_unknown_version_without_any_success(self):
        clock = FakeClock()
        probe, calls = self.make_probe(clock, [BatfishProbeError('down')])

        with self.assertLogs('services.batfish_version_probe', level='WARNING'):
            self.assertIsNone(probe.current())
        clock.now += 10
        self.assertIsNone(probe.current())
        self.assertEqual(len(calls), 1)

    def test_concurrent_callers_share_one_fetch(self):
        waiting = []

        class CountingEvent(threading.Event):
            def wait(self, timeout=None):
                waiting.append(threading.current_thread().name)
                return super().wait(timeout)

        with mock.patch.object(probe_module, 'threading', SimpleNamespace(Lock=threading.Lock, Event=CountingEvent)):
            probe = BatfishVersionProbe('127.0.0.1', 1)
            release = threading.Event()
            started = threading.Event()
            calls = []

            def slow_fetch():
                calls.append(1)
                started.set()
                release.wait(5)
                return 'shared'

            probe.fetch_version = slow_fetch
            results = []
            threads = [threading.Thread(target=lambda: results.append(probe.current())) for _ in range(5)]
            for thread in threads:
                thread.start()
            self.assertTrue(started.wait(5))
            deadline = time.monotonic() + 10
            while len(waiting) < 4 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(waiting), 4)
            release.set()
            for thread in threads:
                thread.join(5)

        self.assertEqual(calls, [1])
        self.assertEqual(results, ['shared'] * 5)

    def test_fed_values_never_overwrite_a_newer_answer_or_extend_its_ttl(self):
        clock = FakeClock(100.0)
        probe, calls = self.make_probe(clock, ['v1', 'v3'])

        self.assertEqual(probe.current(), 'v1')
        probe.feed('v0', observed_at=50.0)
        self.assertEqual(probe.peek(), 'v1')
        probe.feed('v2', observed_at=200.0)
        self.assertEqual(probe.peek(), 'v2')
        clock.now = 399.0
        self.assertEqual(probe.current(), 'v2')
        self.assertEqual(len(calls), 1)
        clock.now = 401.0
        self.assertEqual(probe.current(), 'v3')
        self.assertEqual(len(calls), 2)

    def test_a_fed_value_is_known_before_any_probe_answer(self):
        clock = FakeClock(100.0)
        probe, calls = self.make_probe(clock, [])

        probe.feed('v7', observed_at=100.0)

        self.assertEqual(probe.current(), 'v7')
        self.assertEqual(calls, [])


class _VersionedSession:
    def __init__(self):
        self.versions = ['2025.01.01']
        self.network = None
        self.snapshot = None

    def set_network(self, name):
        self.network = name

    def get_component_versions(self):
        return {'Batfish': self.versions[0]}

    def init_snapshot(self, path, name=None, overwrite=False):
        self.snapshot = name
        return name


class ActivationFeedTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.snapshot = Path(self.temp_dir.name) / 'fed'
        (self.snapshot / 'configs').mkdir(parents=True)
        self.clock = FakeClock(100.0)
        self.probe = BatfishVersionProbe('127.0.0.1', 1, clock=self.clock)
        self.probe.fetch_version = mock.Mock(side_effect=AssertionError('no direct probe fetch expected'))
        self.service = BatfishService()
        self.service._session = _VersionedSession()
        self.service.version_probe = self.probe
        for name in ('get_file_parse_status', 'get_init_issues', 'get_parse_warnings'):
            patch = mock.patch.object(self.service, name, return_value=[])
            patch.start()
            self.addCleanup(patch.stop)

    def test_a_version_change_between_two_activations_is_fed_and_recorded(self):
        self.service.initialize_network(self.snapshot, 'fed')
        self.assertEqual(self.service.loaded_batfish_version, '2025.01.01')
        self.assertEqual(self.probe.current(), '2025.01.01')

        self.clock.now += 10
        self.service._session.versions[0] = '2025.06.01'
        self.service.initialize_network(self.snapshot, 'fed')

        self.assertEqual(self.service.loaded_batfish_version, '2025.06.01')
        self.assertEqual(self.probe.current(), '2025.06.01')
        self.assertEqual(self.service.get_batfish_version_info()['batfish_version'], '2025.01.01')
        self.probe.fetch_version.assert_not_called()

    def test_the_process_cached_version_is_never_fed(self):
        self.service._batfish_version = 'process-cached'
        self.service._session.versions[0] = '2025.06.01'

        self.service.initialize_network(self.snapshot, 'fed')

        self.assertEqual(self.probe.peek(), '2025.06.01')
        self.assertEqual(self.service.loaded_batfish_version, '2025.06.01')

    def test_a_newer_probe_answer_wins_over_an_older_activation_value(self):
        self.probe.fetch_version = mock.Mock(return_value='2025.09.09')
        session = self.service._session
        original = session.get_component_versions

        def versions_observed_before_the_probe_answered():
            result = original()
            self.clock.now += 1
            self.assertEqual(self.probe.current(), '2025.09.09')
            return result

        session.get_component_versions = versions_observed_before_the_probe_answered

        self.service.initialize_network(self.snapshot, 'fed')

        self.assertEqual(self.probe.peek(), '2025.09.09')
        self.assertEqual(self.service.loaded_batfish_version, '2025.09.09')

    def test_loading_a_snapshot_by_name_feeds_the_probe(self):
        self.service._session.versions[0] = '2025.03.03'

        self.service._load_snapshot(self.snapshot, 'other')

        self.assertEqual(self.probe.peek(), '2025.03.03')
        self.assertIsNone(self.service.loaded_batfish_version)


if __name__ == '__main__':
    unittest.main()
