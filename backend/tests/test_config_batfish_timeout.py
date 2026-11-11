import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BACKEND_DIR = Path(__file__).resolve().parents[1]


class BatfishQueryTimeoutConfigTest(unittest.TestCase):
    def _import_config(self, value):
        env = os.environ.copy()
        env["FLASK_ENV"] = "development"
        if value is None:
            env.pop("BATFISH_QUERY_TIMEOUT_SECONDS", None)
        else:
            env["BATFISH_QUERY_TIMEOUT_SECONDS"] = value

        with tempfile.TemporaryDirectory() as snapshots_dir:
            env["SNAPSHOTS_DIR"] = snapshots_dir
            return subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import config; print(config.config.BATFISH_QUERY_TIMEOUT_SECONDS)",
                ],
                cwd=BACKEND_DIR,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_timeout_parsing_and_minimum(self):
        for value, expected in ((None, "120"), ("5", "10"), ("300", "300")):
            with self.subTest(value=value):
                result = self._import_config(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_non_integer_stops_config_import(self):
        result = self._import_config("abc")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ValueError", result.stderr)
        self.assertIn("invalid literal for int()", result.stderr)


if __name__ == "__main__":
    unittest.main()
