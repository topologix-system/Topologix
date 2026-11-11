import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import app as app_module

BACKEND_DIR = Path(__file__).resolve().parents[1]
VALID_CONFIG = "hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"


class DeleteActiveSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshot_service = app_module.snapshot_service
        self.original_snapshots_dir = self.snapshot_service.snapshots_dir
        self.snapshot_service.snapshots_dir = Path(self.temp_dir.name)
        self.batfish_service = app_module.batfish_service
        self.original_state = (
            self.batfish_service.network_name,
            self.batfish_service.current_snapshot_name,
            self.batfish_service._initialized,
        )
        self.batfish_service.network_name = app_module.config.BATFISH_NETWORK
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.snapshot_service.snapshots_dir = self.original_snapshots_dir
        (
            self.batfish_service.network_name,
            self.batfish_service.current_snapshot_name,
            self.batfish_service._initialized,
        ) = self.original_state
        self.temp_dir.cleanup()

    def create_snapshot(self, name: str) -> None:
        self.snapshot_service.create_snapshot(name)
        (Path(self.temp_dir.name) / name / "configs" / "r1.cfg").write_text(VALID_CONFIG, encoding="utf-8")

    def activate(self, name: str) -> None:
        self.batfish_service.current_snapshot_name = name
        self.batfish_service._initialized = True

    def get_nodes(self):
        def node_properties():
            self.batfish_service._ensure_initialized()
            return [{"node": "r1"}]

        with mock.patch.object(self.batfish_service, "get_node_properties", side_effect=node_properties):
            return self.client.get("/api/network/nodes")

    def test_deleting_the_active_snapshot_leaves_no_snapshot_active(self):
        self.create_snapshot("fx-del-active")
        self.activate("fx-del-active")
        self.assertEqual(self.get_nodes().status_code, 200)

        response = self.client.delete("/api/snapshots/fx-del-active")

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIsNone(self.batfish_service.current_snapshot_name)
        self.assertFalse(self.batfish_service._initialized)
        nodes = self.get_nodes()
        self.assertEqual(nodes.status_code, 400, nodes.get_data(as_text=True)[:300])
        self.assertIn("not initialized", nodes.get_json()["message"])

    def test_deleting_another_snapshot_keeps_the_active_one(self):
        self.create_snapshot("fx-del-active")
        self.create_snapshot("fx-del-other")
        self.activate("fx-del-active")

        response = self.client.delete("/api/snapshots/fx-del-other")

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-del-active")
        self.assertTrue(self.batfish_service._initialized)
        self.assertEqual(self.get_nodes().status_code, 200)

    def test_deletion_waits_for_a_running_batfish_operation(self):
        self.create_snapshot("fx-del-race")
        self.activate("fx-del-previous")
        lock_held = threading.Event()
        finish_activation = threading.Event()
        responses = []

        def activation_in_progress():
            with app_module.batfish_request_lock:
                lock_held.set()
                finish_activation.wait(10)
                self.activate("fx-del-race")

        def delete():
            responses.append(app_module.app.test_client().delete("/api/snapshots/fx-del-race"))

        holder = threading.Thread(target=activation_in_progress)
        deleter = threading.Thread(target=delete)
        holder.start()
        try:
            self.assertTrue(lock_held.wait(10))
            deleter.start()
            deleter.join(0.3)

            self.assertTrue(deleter.is_alive())
            self.assertTrue((Path(self.temp_dir.name) / "fx-del-race").exists())
        finally:
            finish_activation.set()
            holder.join(10)
            if deleter.ident is not None:
                deleter.join(10)

        self.assertEqual(responses[0].status_code, 200, responses[0].get_data(as_text=True)[:300])
        self.assertFalse((Path(self.temp_dir.name) / "fx-del-race").exists())
        self.assertIsNone(self.batfish_service.current_snapshot_name)
        self.assertFalse(self.batfish_service._initialized)

    def test_same_name_active_in_another_network_is_left_to_that_network(self):
        self.create_snapshot("fx-del-active")
        self.activate("fx-del-active")
        self.batfish_service.network_name = "other_network"

        self.client.delete("/api/snapshots/fx-del-active")

        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-del-active")
        self.assertTrue(self.batfish_service._initialized)


AUTH_DELETE_SCRIPT = r'''
import io
import json
import os
import sys
from unittest import mock

from app import app

batfish_service = sys.modules["app"].batfish_service
ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
CONFIG = b"hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
results = {}
activations = []


def initialize(snapshot_dir, snapshot_name=None):
    activations.append(snapshot_name)
    batfish_service.current_snapshot_name = snapshot_name
    batfish_service._initialized = True
    return {"status": "success", "snapshot": snapshot_name}


def node_properties():
    batfish_service._ensure_initialized()
    return [{"node": "r1", "snapshot": batfish_service.current_snapshot_name}]


def record(key, response):
    results[key] = {"status": response.status_code, "json": response.get_json(silent=True)}


def login():
    client = app.test_client()
    response = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["data"]["csrf_token"]
    return client


admin = login()
admin.post("/api/snapshots", json={"name": "fx-auth-del"})
admin.post(
    "/api/snapshots/fx-auth-del/files",
    data={"file": (io.BytesIO(CONFIG), "r1.cfg")},
    content_type="multipart/form-data",
)

with mock.patch.object(batfish_service, "initialize_network", side_effect=initialize), \
        mock.patch.object(batfish_service, "get_node_properties", side_effect=node_properties):
    record("activate", admin.post("/api/snapshots/fx-auth-del/activate"))
    record("nodes_while_active", admin.get("/api/network/nodes"))

    second_session = login()
    record("nodes_from_session_without_active_snapshot", second_session.get("/api/network/nodes"))
    results["state_after_session_without_active_snapshot"] = [
        batfish_service.current_snapshot_name, batfish_service._initialized]
    activations_before_query = len(activations)
    record("nodes_after_session_without_active_snapshot", admin.get("/api/network/nodes"))
    results["activations_for_query_after_session_without_active_snapshot"] = (
        len(activations) - activations_before_query)

    record("reactivate", admin.post("/api/snapshots/fx-auth-del/activate"))
    record("delete", admin.delete("/api/snapshots/fx-auth-del"))
    results["state_after_delete"] = [batfish_service.current_snapshot_name, batfish_service._initialized]
    record("nodes_after_delete", admin.get("/api/network/nodes"))

print(json.dumps(results))
'''


class AuthDeleteActiveSnapshotTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshots_dir = Path(temp_dir) / "snapshots"
            snapshots_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "delete-state-test-secret-key",
                "JWT_SECRET_KEY": "delete-state-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "delete-state-test-csrf-secret-key",
                "CSRF_MODE": "session",
                "ALLOW_REGISTRATION": "true",
                "AUTH_DEFAULT_ADMIN_USER": "admin",
                "AUTH_DEFAULT_ADMIN_PASS": "DeleteStateAdmin123!",
                "DATABASE_URL": f"sqlite:///{Path(temp_dir) / 'delete-state-test.db'}",
                "SNAPSHOTS_DIR": str(snapshots_dir),
                "PYTHONPATH": str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, "-c", AUTH_DELETE_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def test_active_snapshot_is_served_before_deletion(self):
        self.assertEqual(self.results["activate"]["status"], 200)
        nodes = self.results["nodes_while_active"]
        self.assertEqual(nodes["status"], 200)
        self.assertEqual(nodes["json"]["data"][0]["snapshot"], "fx-auth-del")

    def test_session_without_an_active_snapshot_is_uninitialized(self):
        nodes = self.results["nodes_from_session_without_active_snapshot"]
        self.assertEqual(nodes["status"], 400)
        self.assertEqual(nodes["json"]["status"], "error")
        self.assertIn("not initialized", nodes["json"]["message"])

    def test_session_without_an_active_snapshot_keeps_the_other_session_state(self):
        self.assertEqual(self.results["state_after_session_without_active_snapshot"], ["fx-auth-del", True])
        nodes = self.results["nodes_after_session_without_active_snapshot"]
        self.assertEqual(nodes["status"], 200)
        self.assertEqual(nodes["json"]["data"][0]["snapshot"], "fx-auth-del")
        self.assertEqual(self.results["activations_for_query_after_session_without_active_snapshot"], 0)

    def test_deleting_the_active_snapshot_stops_serving_it(self):
        self.assertEqual(self.results["reactivate"]["status"], 200)
        self.assertEqual(self.results["delete"]["status"], 200)
        self.assertEqual(self.results["state_after_delete"], [None, False])
        nodes = self.results["nodes_after_delete"]
        self.assertEqual(nodes["status"], 400)
        self.assertIn("not initialized", nodes["json"]["message"])


if __name__ == "__main__":
    unittest.main()
