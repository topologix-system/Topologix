"""Sandboxed test environment, applied to os.environ at import time before any test module imports app or config."""
import logging
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SHARED_ROOTS = ('/app/data', '/app/snapshots')
FORCED_PATH_VARIABLES = ('DATA_DIR', 'SNAPSHOTS_DIR', 'DATABASE_URL')
DERIVED_DIRECTORY_VARIABLES = ('RESULT_CACHE_DIR', 'SNAPSHOT_HISTORY_DIR')
REMOVED_VARIABLES = (
    'DEPLOYMENT_ID',
    'APP_BUILD_ID',
    'HISTORY_ACCEPT_STORE_LOSS',
    'HISTORY_GC_GRACE_SECONDS',
    'EXTERNAL_CHANGE_SETTLE_SECONDS',
    'RESULT_CACHE_MAX_BYTES',
    'RESULT_CACHE_MAX_ENTRIES',
    'RESULT_CACHE_PROTECT_SECONDS',
    'BATFISH_VERSION_PROBE_TTL_SECONDS',
    'BATFISH_VERSION_GRACE_SECONDS',
    'SNAPSHOT_DIFF_MAX_BYTES',
    'SNAPSHOT_DIFF_MAX_LINES',
)
FIXED_VALUES = {
    'RESULT_CACHE_ENABLED': 'false',
    'BATFISH_HOST': '127.0.0.1',
    'BATFISH_PORT': '1',
}
BACKEND_DIR = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent

logger = logging.getLogger('test_00_environment')


def _is_under_shared_root(path_value: str) -> bool:
    resolved = Path(path_value).resolve(strict=False)
    return any(resolved == Path(root) or Path(root) in resolved.parents for root in SHARED_ROOTS)


def _sqlite_path(database_url: str) -> str | None:
    if not database_url.startswith('sqlite:///'):
        return None
    path = database_url[len('sqlite:///'):]
    if not path or path == ':memory:':
        return None
    return path


def _points_to_shared_root(name: str, value: str) -> bool:
    if name == 'DATABASE_URL':
        path = _sqlite_path(value)
        return path is not None and _is_under_shared_root(path)
    return _is_under_shared_root(value)


def sanitize_environment(environ, temp_root_factory=None) -> dict[str, str]:
    """Force the sandbox variables into environ; return the path variables that were replaced."""
    temp_root: list[str] = []

    def root() -> str:
        if not temp_root:
            temp_root.append(temp_root_factory() if temp_root_factory else tempfile.mkdtemp(prefix='topologix-test-env-'))
        return temp_root[0]

    builders = {
        'DATA_DIR': lambda base: base,
        'SNAPSHOTS_DIR': lambda base: os.path.join(base, 'snapshots'),
        'DATABASE_URL': lambda base: f"sqlite:///{os.path.join(base, 'test.db')}",
    }
    forced = {}
    for name in FORCED_PATH_VARIABLES:
        value = (environ.get(name) or '').strip()
        if not value or _points_to_shared_root(name, value):
            environ[name] = builders[name](root())
            forced[name] = environ[name]
    for name in DERIVED_DIRECTORY_VARIABLES + REMOVED_VARIABLES:
        environ.pop(name, None)
    environ.update(FIXED_VALUES)
    return forced


def _ensure_directories(environ) -> None:
    Path(environ['DATA_DIR']).mkdir(parents=True, exist_ok=True)
    Path(environ['SNAPSHOTS_DIR']).mkdir(parents=True, exist_ok=True)
    database_path = _sqlite_path(environ['DATABASE_URL'])
    if database_path:
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)


FORCED_VARIABLES = sanitize_environment(os.environ)
for _name, _value in FORCED_VARIABLES.items():
    logger.warning("Test environment: %s forced to temporary location %s", _name, _value)
_ensure_directories(os.environ)


class TestEnvironmentIsolationTest(unittest.TestCase):
    def test_effective_config_is_sandboxed(self):
        from config import config

        self.assertFalse(config.RESULT_CACHE_ENABLED)
        self.assertEqual(os.environ['RESULT_CACHE_ENABLED'], 'false')
        self.assertEqual(config.BATFISH_HOST, '127.0.0.1')
        self.assertEqual(config.BATFISH_PORT, 1)

        data_dir = os.environ['DATA_DIR']
        self.assertEqual(config.DATA_DIR, data_dir)
        self.assertFalse(config.DATA_DIR_FELL_BACK)
        self.assertFalse(_is_under_shared_root(config.DATA_DIR))
        self.assertEqual(config.SNAPSHOTS_DIR, os.environ['SNAPSHOTS_DIR'])
        self.assertFalse(_is_under_shared_root(config.SNAPSHOTS_DIR))
        self.assertEqual(config.SQLALCHEMY_DATABASE_URI, os.environ['DATABASE_URL'])
        self.assertFalse(_points_to_shared_root('DATABASE_URL', config.SQLALCHEMY_DATABASE_URI))
        self.assertEqual(config.RESULT_CACHE_DIR, os.path.join(data_dir, 'result_cache'))
        self.assertEqual(config.SNAPSHOT_HISTORY_DIR, os.path.join(data_dir, 'snapshot_history'))

        for name in DERIVED_DIRECTORY_VARIABLES + REMOVED_VARIABLES:
            self.assertNotIn(name, os.environ)
        self.assertEqual(config.DEPLOYMENT_ID, '')
        self.assertEqual(config.HISTORY_ACCEPT_STORE_LOSS, '')
        self.assertEqual(config.HISTORY_GC_GRACE_SECONDS, 600)
        self.assertEqual(config.EXTERNAL_CHANGE_SETTLE_SECONDS, 10)

    def test_empty_and_shared_paths_are_replaced_by_a_temporary_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            environ = {
                'DATA_DIR': '',
                'SNAPSHOTS_DIR': '/app/snapshots',
                'DATABASE_URL': 'sqlite:////app/data/topologix.db',
                'RESULT_CACHE_DIR': '/app/data/result_cache',
                'SNAPSHOT_HISTORY_DIR': '/elsewhere/history',
                'DEPLOYMENT_ID': 'from-env-file',
                'RESULT_CACHE_ENABLED': 'true',
                'BATFISH_HOST': 'batfish',
            }
            forced = sanitize_environment(environ, temp_root_factory=lambda: temp_dir)

            self.assertEqual(set(forced), {'DATA_DIR', 'SNAPSHOTS_DIR', 'DATABASE_URL'})
            self.assertEqual(environ['DATA_DIR'], temp_dir)
            self.assertEqual(environ['SNAPSHOTS_DIR'], os.path.join(temp_dir, 'snapshots'))
            self.assertEqual(environ['DATABASE_URL'], f"sqlite:///{os.path.join(temp_dir, 'test.db')}")
            for name in ('RESULT_CACHE_DIR', 'SNAPSHOT_HISTORY_DIR', 'DEPLOYMENT_ID'):
                self.assertNotIn(name, environ)
            self.assertEqual(environ['RESULT_CACHE_ENABLED'], 'false')
            self.assertEqual(environ['BATFISH_HOST'], '127.0.0.1')
            self.assertEqual(environ['BATFISH_PORT'], '1')

            from config import resolve_data_dir
            self.assertEqual(resolve_data_dir(environ, '/app/data'), (temp_dir, False))

    def test_explicit_sandbox_paths_are_kept(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            environ = {
                'DATA_DIR': os.path.join(temp_dir, 'data'),
                'SNAPSHOTS_DIR': os.path.join(temp_dir, 'snapshots'),
                'DATABASE_URL': f"sqlite:///{os.path.join(temp_dir, 'test.db')}",
            }
            expected = dict(environ)

            self.assertEqual(sanitize_environment(environ), {})
            for name, value in expected.items():
                self.assertEqual(environ[name], value)

    def test_empty_data_dir_in_a_child_process_resolves_to_the_temporary_directory(self):
        env = os.environ.copy()
        env['DATA_DIR'] = ''
        env['PYTHONPATH'] = os.pathsep.join([str(TESTS_DIR), str(BACKEND_DIR)])
        script = (
            "import os, tempfile, test_00_environment, config\n"
            "print(config.config.DATA_DIR)\n"
            "print(os.environ['DATA_DIR'])\n"
            "print(tempfile.gettempdir())\n"
        )
        completed = subprocess.run(
            [sys.executable, '-c', script],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
        config_data_dir, environ_data_dir, temp_dir = completed.stdout.strip().splitlines()[-3:]
        self.assertEqual(config_data_dir, environ_data_dir)
        self.assertTrue(Path(config_data_dir).resolve().is_relative_to(Path(temp_dir).resolve()))
        self.assertFalse(_is_under_shared_root(config_data_dir))


if __name__ == '__main__':
    unittest.main()
