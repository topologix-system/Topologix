import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app as app_module
from services import BatfishQueryError, BatfishService
from services.batfish_service import BatfishSnapshotLoadError

BACKEND_DIR = Path(__file__).resolve().parents[1]
STACK_MARKERS = ("work_item", "\tat ", "   at org.", "Exception in container", "answerElements")

# Sanitized reproduction of the work log pybatfish raises when Batfish rejects
# a snapshot (synthetic ids and names, no real environment data).
SANITIZED_INIT_FAILURE = (
    "Work terminated abnormally\n"
    'work_item: {"containerName": "example_network", '
    '"id": "00000000-0000-0000-0000-000000000000", '
    '"requestParams": {"testrig": "example"}, "testrigName": "example"}\n'
    "\n"
    "log: \n"
    "*** READING DEVICE CONFIGURATION FILES ***\n"
    "Snapshot 11111111-1111-1111-1111-111111111111 in network "
    "22222222-2222-2222-2222-222222222222 has total number of network configs:1\n"
    "Exception in container:22222222-2222-2222-2222-222222222222, "
    "testrig:11111111-1111-1111-1111-111111111111; "
    "exception:org.batfish.common.BatfishException: Example parser crashed on configs/r1.cfg\n"
    "\tat org.batfish.main.Batfish.serializeVendorConfigs(Batfish.java:2800)\n"
    '{"answerElements":[{"class":"org.batfish.common.BatfishException$BatfishStackTrace",'
    '"answer":["org.batfish.common.BatfishException: Example parser crashed on configs/r1.cfg",'
    '"   at org.batfish.main.Batfish.serializeVendorConfigs(Batfish.java:2800)",""]}],'
    '"status":"FAILURE"}'
)

# Synthetic work log whose failure reason carries a password-like token (no real credential).
SECRET_IN_REASON_FAILURE = (
    "Work terminated abnormally\n"
    "log: \n"
    "exception:org.batfish.common.BatfishException: "
    "Unrecognized line password: example-not-a-secret in configs/r1.cfg\n"
    "\tat org.batfish.main.Batfish.serializeVendorConfigs(Batfish.java:2800)\n"
)

VALID_CONFIG = "hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
LAYER1_TOPOLOGY = {
    "edges": [{
        "node1": {"hostname": "r1", "interfaceName": "GigabitEthernet0/0"},
        "node2": {"hostname": "r2", "interfaceName": "GigabitEthernet0/0"},
    }]
}


def assert_structured_error(test: unittest.TestCase, response, status: int, code: str) -> dict:
    test.assertEqual(response.status_code, status, response.get_data(as_text=True)[:300])
    test.assertTrue(response.is_json, response.get_data(as_text=True)[:300])
    payload = response.get_json()
    test.assertEqual(payload["status"], "error")
    test.assertEqual(payload.get("code"), code)
    test.assertIsInstance(payload.get("message"), str)
    return payload


class SnapshotDirTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshot_service = app_module.snapshot_service
        self.original_snapshots_dir = self.snapshot_service.snapshots_dir
        self.snapshot_service.snapshots_dir = Path(self.temp_dir.name)
        self.batfish_service = app_module.batfish_service
        self.original_current_snapshot = self.batfish_service.current_snapshot_name
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.snapshot_service.snapshots_dir = self.original_snapshots_dir
        self.batfish_service.current_snapshot_name = self.original_current_snapshot
        self.temp_dir.cleanup()

    def create_snapshot(self, name: str, files: dict[str, str] | None = None) -> Path:
        self.snapshot_service.create_snapshot(name)
        snapshot_path = Path(self.temp_dir.name) / name
        for filename, content in (files or {}).items():
            (snapshot_path / "configs" / filename).write_text(content, encoding="utf-8")
        return snapshot_path


class MalformedJsonBodyTest(SnapshotDirTestCase):
    def test_malformed_json_on_create_snapshot_returns_structured_400(self):
        response = self.client.post("/api/snapshots", data="{not json", content_type="application/json")

        payload = assert_structured_error(self, response, 400, "invalid_json")
        self.assertEqual(payload["message"], "Request body must be valid JSON")
        self.assertNotIn("Expecting", json.dumps(payload))
        self.assertEqual(list(Path(self.temp_dir.name).iterdir()), [])

    def test_malformed_json_on_batfish_route_never_reaches_the_service(self):
        with mock.patch.object(self.batfish_service, "resolve_node_specifier") as resolve:
            response = self.client.post(
                "/api/validation/resolve-node-specifier",
                data='{"nodes": ',
                content_type="application/json",
            )

        assert_structured_error(self, response, 400, "invalid_json")
        resolve.assert_not_called()

    def test_empty_json_body_still_reaches_routes_that_accept_no_body(self):
        snapshot_path = self.create_snapshot("fx-empty-body", {"r1.cfg": VALID_CONFIG})
        with mock.patch.object(
            self.batfish_service,
            "initialize_network",
            return_value={"status": "success", "snapshot": "fx-empty-body"},
        ) as initialize:
            response = self.client.post(
                "/api/snapshots/fx-empty-body/activate",
                data=b"",
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        initialize.assert_called_once_with(str(snapshot_path), "fx-empty-body")

    def test_empty_json_body_on_reachability_runs_the_default_query(self):
        with mock.patch.object(self.batfish_service, "get_reachability", return_value=[]) as reachability:
            response = self.client.post(
                "/api/analysis/reachability",
                data=b"",
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        reachability.assert_called_once_with(None)

    def test_valid_json_body_is_still_parsed_by_routes(self):
        response = self.client.post("/api/snapshots", json={"name": "fx-valid-json"})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertTrue((Path(self.temp_dir.name) / "fx-valid-json").is_dir())

    def test_non_object_json_body_returns_structured_400(self):
        cases = (
            ("/api/acl/test-filters", "[1, 2]", "test_filters"),
            ("/api/acl/test-filters", '"x"', "test_filters"),
            ("/api/analysis/reachability", "[1]", "get_reachability"),
        )
        for path, body, service_method in cases:
            with self.subTest(path=path, body=body):
                with mock.patch.object(self.batfish_service, service_method, return_value=[]) as query:
                    response = self.client.post(path, data=body, content_type="application/json")

                payload = assert_structured_error(self, response, 400, "invalid_json")
                self.assertEqual(payload["message"], "Request body must be a JSON object")
                query.assert_not_called()

    def test_null_json_body_is_left_to_the_route(self):
        with mock.patch.object(self.batfish_service, "get_reachability", return_value=[]) as reachability:
            response = self.client.post(
                "/api/analysis/reachability",
                data="null",
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        reachability.assert_called_once_with(None)

    def test_non_json_body_on_json_route_returns_structured_400(self):
        bodies = {
            "text/plain": {"data": '{"name": "fx-text"}', "content_type": "text/plain"},
            "form": {"data": "name=fx-form", "content_type": "application/x-www-form-urlencoded"},
            "multipart": {"data": {"name": "fx-multipart"}, "content_type": "multipart/form-data"},
            "no content type": {"data": '{"name": "fx-untyped"}'},
        }
        for label, request_kwargs in bodies.items():
            with self.subTest(body=label):
                response = self.client.post("/api/snapshots", **request_kwargs)

                payload = assert_structured_error(self, response, 400, "invalid_json")
                self.assertEqual(payload["message"], "Request body must be valid JSON")
        self.assertEqual(list(Path(self.temp_dir.name).iterdir()), [])

    def test_non_json_body_on_batfish_route_never_reaches_the_service(self):
        with mock.patch.object(self.batfish_service, "resolve_node_specifier") as resolve:
            response = self.client.post(
                "/api/validation/resolve-node-specifier",
                data="nodes=core-rtr1",
                content_type="text/plain",
            )

        assert_structured_error(self, response, 400, "invalid_json")
        resolve.assert_not_called()

    def test_empty_body_on_json_route_returns_structured_400(self):
        routes = ["/api/snapshots", "/api/snapshots/compare", "/api/validation/resolve-node-specifier"]
        bodies = {
            "no content type": {},
            "text/plain": {"data": b"", "content_type": "text/plain"},
            "form": {"data": b"", "content_type": "application/x-www-form-urlencoded"},
            "json": {"data": b"", "content_type": "application/json"},
        }
        with mock.patch.object(self.batfish_service, "resolve_node_specifier") as resolve:
            for path in routes:
                for label, request_kwargs in bodies.items():
                    with self.subTest(path=path, body=label):
                        response = self.client.post(path, **request_kwargs)

                        payload = assert_structured_error(self, response, 400, "invalid_json")
                        self.assertEqual(payload["message"], "Request body must be valid JSON")
        resolve.assert_not_called()
        self.assertEqual(list(Path(self.temp_dir.name).iterdir()), [])

    def test_empty_body_still_reaches_routes_that_run_without_a_body(self):
        snapshot_path = self.create_snapshot("fx-no-body", {"r1.cfg": VALID_CONFIG})
        with mock.patch.object(
            self.batfish_service, "initialize_network", return_value={"status": "success"}
        ) as initialize:
            response = self.client.post("/api/snapshots/fx-no-body/activate")

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        initialize.assert_called_once_with(str(snapshot_path), "fx-no-body")

        with mock.patch.object(self.batfish_service, "get_reachability", return_value=[]) as reachability:
            response = self.client.post("/api/analysis/reachability")

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        reachability.assert_called_once_with(None)

        for path in ("/api/snapshots/fx-missing/activate", "/api/snapshots/fx-missing/artifacts/validate"):
            with self.subTest(path=path):
                response = self.client.post(path)

                self.assertEqual(response.status_code, 404, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()["message"], "Snapshot 'fx-missing' not found")

        self.assertEqual(self.client.post("/api/does-not-exist").status_code, 404)

    def test_text_body_on_unmatched_route_keeps_the_routing_status(self):
        response = self.client.post("/api/does-not-exist", data="not json", content_type="text/plain")

        self.assertEqual(response.status_code, 404, response.get_data(as_text=True)[:300])

        response = self.client.put("/api/health", data="not json", content_type="text/plain")

        self.assertEqual(response.status_code, 405, response.get_data(as_text=True)[:300])

    def test_text_body_on_get_and_delete_routes_is_left_to_the_route(self):
        for name in ("fx-delete-plain", "fx-delete-text"):
            self.create_snapshot(name)
        text_body = {"data": "not json", "content_type": "text/plain"}

        without_body = self.client.get("/api/snapshots")
        with_body = self.client.get("/api/snapshots", **text_body)

        self.assertEqual(without_body.status_code, 200, without_body.get_data(as_text=True)[:300])
        self.assertEqual(with_body.status_code, without_body.status_code, with_body.get_data(as_text=True)[:300])

        without_body = self.client.delete("/api/snapshots/fx-delete-plain")
        with_body = self.client.delete("/api/snapshots/fx-delete-text", **text_body)

        self.assertEqual(without_body.status_code, 200, without_body.get_data(as_text=True)[:300])
        self.assertEqual(with_body.status_code, without_body.status_code, with_body.get_data(as_text=True)[:300])
        self.assertFalse((Path(self.temp_dir.name) / "fx-delete-text").exists())

    def test_upload_routes_keep_reading_multipart_bodies(self):
        self.create_snapshot("fx-multipart-upload")
        response = self.client.post(
            "/api/snapshots/fx-multipart-upload/files",
            data={"file": (io.BytesIO(VALID_CONFIG.encode()), "r1.cfg")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertTrue((Path(self.temp_dir.name) / "fx-multipart-upload" / "configs" / "r1.cfg").is_file())

        response = self.client.post(
            "/api/snapshots/fx-multipart-upload/files", data=VALID_CONFIG, content_type="text/plain"
        )

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()["message"], "No file provided")


class OversizedBodyTest(SnapshotDirTestCase):
    def setUp(self):
        super().setUp()
        self.original_limit = app_module.app.config["MAX_CONTENT_LENGTH"]
        app_module.app.config["MAX_CONTENT_LENGTH"] = 4096

    def tearDown(self):
        app_module.app.config["MAX_CONTENT_LENGTH"] = self.original_limit
        super().tearDown()

    def test_oversized_multipart_upload_returns_json_413(self):
        self.create_snapshot("fx-upload")
        content = VALID_CONFIG + "!" * 8192
        response = self.client.post(
            "/api/snapshots/fx-upload/files",
            data={"file": (io.BytesIO(content.encode()), "big.cfg")},
            content_type="multipart/form-data",
        )

        payload = assert_structured_error(self, response, 413, "request_too_large")
        self.assertIn("maximum", payload["message"])
        self.assertNotIn("Request Entity Too Large", payload["message"])
        self.assertEqual(list((Path(self.temp_dir.name) / "fx-upload" / "configs").iterdir()), [])

    def test_oversized_json_body_returns_json_413(self):
        response = self.client.post("/api/snapshots", json={"name": "x" * 8192})

        assert_structured_error(self, response, 413, "request_too_large")


class SnapshotActivationErrorTest(SnapshotDirTestCase):
    def test_activating_snapshot_without_configs_returns_400_without_calling_batfish(self):
        self.create_snapshot("fx-noconf")
        self.batfish_service.current_snapshot_name = "fx-previous"

        with mock.patch.object(self.batfish_service, "initialize_network") as initialize:
            response = self.client.post("/api/snapshots/fx-noconf/activate")

        payload = assert_structured_error(self, response, 400, "snapshot_empty")
        self.assertEqual(payload["details"], {"snapshot": "fx-noconf"})
        self.assertTrue(payload["hints"])
        initialize.assert_not_called()
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-previous")

    def test_supplemental_files_alone_do_not_count_as_configs(self):
        snapshot_path = self.create_snapshot("fx-l1only")
        (snapshot_path / "batfish").mkdir()
        (snapshot_path / "batfish" / "layer1_topology.json").write_text('{"edges": []}', encoding="utf-8")

        with mock.patch.object(self.batfish_service, "initialize_network") as initialize:
            response = self.client.post("/api/snapshots/fx-l1only/activate")

        assert_structured_error(self, response, 400, "snapshot_empty")
        initialize.assert_not_called()

    def test_non_config_directories_are_left_to_batfish(self):
        snapshot_path = self.create_snapshot("fx-aws")
        (snapshot_path / "aws_configs").mkdir()
        (snapshot_path / "aws_configs" / "vpcs.json").write_text("{}", encoding="utf-8")

        with mock.patch.object(
            self.batfish_service, "initialize_network", return_value={"status": "success"}
        ) as initialize:
            response = self.client.post("/api/snapshots/fx-aws/activate")

        self.assertEqual(response.status_code, 200)
        initialize.assert_called_once()

    def test_batfish_rejection_is_structured_and_sanitized(self):
        self.create_snapshot("fx-broken", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-previous"

        def fail(snapshot_dir, snapshot_name=None):
            self.batfish_service.current_snapshot_name = snapshot_name
            raise RuntimeError(SANITIZED_INIT_FAILURE)

        with mock.patch.object(self.batfish_service, "initialize_network", side_effect=fail):
            response = self.client.post("/api/snapshots/fx-broken/activate")

        payload = assert_structured_error(self, response, 422, "snapshot_activation_failed")
        body = response.get_data(as_text=True)
        for marker in STACK_MARKERS:
            self.assertNotIn(marker, body)
        self.assertNotIn("00000000-0000", body)
        self.assertNotIn("11111111-1111", body)
        self.assertNotIn("22222222-2222", body)
        self.assertIn("fx-broken", payload["message"])
        self.assertEqual(payload["details"]["snapshot"], "fx-broken")
        self.assertEqual(payload["details"]["reason"], "Example parser crashed on configs/r1.cfg")
        self.assertTrue(payload["hints"])
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-previous")

    def test_unexpected_activation_failure_does_not_echo_the_exception(self):
        self.create_snapshot("fx-down", {"r1.cfg": VALID_CONFIG})
        error = ConnectionError("HTTPConnectionPool(host='batfish', port=9996): Max retries exceeded")

        with mock.patch.object(self.batfish_service, "initialize_network", side_effect=error):
            response = self.client.post("/api/snapshots/fx-down/activate")

        payload = assert_structured_error(self, response, 500, "snapshot_activation_error")
        self.assertNotIn("HTTPConnectionPool", json.dumps(payload))
        self.assertNotIn("9996", json.dumps(payload))


class SnapshotListActiveFlagTest(SnapshotDirTestCase):
    def test_listing_marks_only_the_active_snapshot(self):
        self.create_snapshot("fx-list-a", {"r1.cfg": VALID_CONFIG})
        self.create_snapshot("fx-list-b", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-list-a"

        response = self.client.get("/api/snapshots")

        self.assertEqual(response.status_code, 200)
        flags = {row["name"]: row["active"] for row in response.get_json()["data"]}
        self.assertEqual(flags, {"fx-list-a": True, "fx-list-b": False})

    def test_listing_marks_nothing_active_before_any_activation(self):
        self.create_snapshot("fx-list-c")
        self.batfish_service.current_snapshot_name = None

        response = self.client.get("/api/snapshots")

        self.assertEqual([row["active"] for row in response.get_json()["data"]], [False])

    def test_failed_activation_keeps_the_previous_snapshot_active(self):
        self.create_snapshot("fx-list-a", {"r1.cfg": VALID_CONFIG})
        self.create_snapshot("fx-list-bad", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-list-a"

        def fail(snapshot_dir, snapshot_name=None):
            self.batfish_service.current_snapshot_name = snapshot_name
            raise RuntimeError(SANITIZED_INIT_FAILURE)

        with mock.patch.object(self.batfish_service, "initialize_network", side_effect=fail):
            self.client.post("/api/snapshots/fx-list-bad/activate")

        flags = {row["name"]: row["active"] for row in self.client.get("/api/snapshots").get_json()["data"]}
        self.assertEqual(flags, {"fx-list-a": True, "fx-list-bad": False})

    def test_failed_reactivation_of_the_active_snapshot_marks_nothing_active(self):
        self.create_snapshot("fx-list-a", {"r1.cfg": VALID_CONFIG})
        self.create_snapshot("fx-list-b", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-list-a"

        with mock.patch.object(
            self.batfish_service, "initialize_network", side_effect=RuntimeError(SANITIZED_INIT_FAILURE)
        ):
            response = self.client.post("/api/snapshots/fx-list-a/activate")

        assert_structured_error(self, response, 422, "snapshot_activation_failed")
        self.assertIsNone(self.batfish_service.current_snapshot_name)
        flags = {row["name"]: row["active"] for row in self.client.get("/api/snapshots").get_json()["data"]}
        self.assertEqual(flags, {"fx-list-a": False, "fx-list-b": False})


class Layer1ReloadErrorTest(SnapshotDirTestCase):
    def active_flags(self) -> dict:
        return {row["name"]: row["active"] for row in self.client.get("/api/snapshots").get_json()["data"]}

    def test_layer1_save_on_the_active_snapshot_reloads_batfish(self):
        snapshot_path = self.create_snapshot("fx-l1-ok", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-l1-ok"

        with mock.patch.object(
            self.batfish_service, "initialize_network", return_value={"status": "success"}
        ) as initialize:
            response = self.client.put("/api/snapshots/fx-l1-ok/layer1-topology", json=LAYER1_TOPOLOGY)

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()["message"], "Layer1 topology saved successfully")
        initialize.assert_called_once()
        self.assertEqual(initialize.call_args.args[0], str(snapshot_path))
        self.assertTrue((snapshot_path / "batfish" / "layer1_topology.json").is_file())
        self.assertEqual(self.active_flags(), {"fx-l1-ok": True})

    def test_failed_reload_after_layer1_save_is_sanitized_and_marks_nothing_active(self):
        self.create_snapshot("fx-l1-bad", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-l1-bad"

        with mock.patch.object(
            self.batfish_service, "initialize_network", side_effect=RuntimeError(SANITIZED_INIT_FAILURE)
        ):
            response = self.client.put("/api/snapshots/fx-l1-bad/layer1-topology", json=LAYER1_TOPOLOGY)

        payload = assert_structured_error(self, response, 422, "snapshot_activation_failed")
        body = response.get_data(as_text=True)
        for marker in STACK_MARKERS:
            self.assertNotIn(marker, body)
        self.assertNotIn("Work terminated abnormally", body)
        self.assertEqual(payload["details"]["snapshot"], "fx-l1-bad")
        self.assertIsNone(self.batfish_service.current_snapshot_name)
        self.assertEqual(self.active_flags(), {"fx-l1-bad": False})

    def test_failed_reload_after_layer1_delete_does_not_echo_the_exception(self):
        snapshot_path = self.create_snapshot("fx-l1-del", {"r1.cfg": VALID_CONFIG})
        (snapshot_path / "batfish").mkdir()
        (snapshot_path / "batfish" / "layer1_topology.json").write_text('{"edges": []}', encoding="utf-8")
        self.batfish_service.current_snapshot_name = "fx-l1-del"
        error = ConnectionError("HTTPConnectionPool(host='batfish', port=9996): Max retries exceeded")

        with mock.patch.object(self.batfish_service, "initialize_network", side_effect=error):
            response = self.client.delete("/api/snapshots/fx-l1-del/layer1-topology")

        payload = assert_structured_error(self, response, 500, "snapshot_activation_error")
        self.assertNotIn("HTTPConnectionPool", json.dumps(payload))
        self.assertEqual(self.active_flags(), {"fx-l1-del": False})


class NetworkInitializeRouteTest(SnapshotDirTestCase):
    def setUp(self):
        super().setUp()
        self.allowed_path_patch = mock.patch.object(
            app_module.config, "ALLOWED_SNAPSHOT_PATH", Path(self.temp_dir.name).resolve()
        )
        self.allowed_path_patch.start()

    def tearDown(self):
        self.allowed_path_patch.stop()
        super().tearDown()

    def active_flags(self) -> dict:
        return {row["name"]: row["active"] for row in self.client.get("/api/snapshots").get_json()["data"]}

    def test_failed_initialize_of_the_active_snapshot_is_sanitized_and_marks_nothing_active(self):
        self.create_snapshot("fx-init-a", {"r1.cfg": VALID_CONFIG})
        self.create_snapshot("fx-init-b", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-init-a"

        with mock.patch.object(
            self.batfish_service, "initialize_network", side_effect=RuntimeError(SANITIZED_INIT_FAILURE)
        ):
            response = self.client.post("/api/network/initialize", json={"snapshot_dir": "fx-init-a"})

        payload = assert_structured_error(self, response, 422, "snapshot_activation_failed")
        body = response.get_data(as_text=True)
        for marker in STACK_MARKERS:
            self.assertNotIn(marker, body)
        self.assertNotIn("Work terminated abnormally", body)
        self.assertNotIn("11111111-1111", body)
        self.assertEqual(payload["details"]["snapshot"], "fx-init-a")
        self.assertIsNone(self.batfish_service.current_snapshot_name)
        self.assertEqual(self.active_flags(), {"fx-init-a": False, "fx-init-b": False})

    def test_unexpected_initialize_failure_does_not_echo_the_exception(self):
        self.create_snapshot("fx-init-a", {"r1.cfg": VALID_CONFIG})
        self.batfish_service.current_snapshot_name = "fx-init-a"
        error = ConnectionError("HTTPConnectionPool(host='batfish', port=9996): Max retries exceeded")

        with mock.patch.object(self.batfish_service, "initialize_network", side_effect=error):
            response = self.client.post(
                "/api/network/initialize", json={"snapshot_dir": "fx-init-a", "snapshot_name": "fx-init-a"}
            )

        payload = assert_structured_error(self, response, 500, "snapshot_activation_error")
        self.assertNotIn("HTTPConnectionPool", json.dumps(payload))
        self.assertNotIn("9996", json.dumps(payload))
        self.assertEqual(self.active_flags(), {"fx-init-a": False})

    def test_successful_initialize_keeps_the_response_shape(self):
        snapshot_path = self.create_snapshot("fx-init-ok", {"r1.cfg": VALID_CONFIG})
        result = {
            "status": "success",
            "network": "topologix_network",
            "snapshot": "fx-init-ok",
            "file_parse_status": [],
            "init_issues": [],
            "parse_warnings": [],
            "initialization_result": {},
        }

        def succeed(snapshot_dir, snapshot_name=None):
            self.batfish_service.current_snapshot_name = snapshot_name
            return result

        with mock.patch.object(
            self.batfish_service, "initialize_network", side_effect=succeed
        ) as initialize:
            response = self.client.post("/api/network/initialize", json={"snapshot_dir": "fx-init-ok"})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        payload = response.get_json()
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["message"], "Network initialized successfully")
        self.assertEqual(payload["data"], result)
        self.assertEqual(initialize.call_args.args, (str(snapshot_path.resolve()), "fx-init-ok"))
        self.assertEqual(self.active_flags(), {"fx-init-ok": True})


class BatfishFailureReasonTest(unittest.TestCase):
    def test_the_innermost_reason_is_returned_without_ids_or_frames(self):
        self.assertEqual(
            app_module.extract_batfish_failure_reason(SANITIZED_INIT_FAILURE),
            "Example parser crashed on configs/r1.cfg",
        )

    def test_module_qualified_frames_on_the_reason_line_are_cut(self):
        message = (
            "Work terminated abnormally\n"
            "Caused by: org.batfish.common.BatfishException: Example parser crashed "
            "at java.base/java.lang.Thread.run(Thread.java:840) "
            "at org.batfish.main.Driver.lambda$runBatfish$0(Driver.java:148)\n"
        )

        self.assertEqual(app_module.extract_batfish_failure_reason(message), "Example parser crashed")

    def test_class_loader_and_constructor_frames_are_cut(self):
        message = (
            "Work terminated abnormally\n"
            "exception:java.lang.IllegalStateException: Example state error "
            "at app//org.batfish.main.Example.<init>(Example.java:10)\n"
        )

        self.assertEqual(app_module.extract_batfish_failure_reason(message), "Example state error")

    def test_a_log_without_an_exception_has_no_reason(self):
        self.assertIsNone(app_module.extract_batfish_failure_reason("Work terminated abnormally\nlog: \n"))

    def test_secret_like_values_in_the_reason_are_redacted(self):
        self.assertEqual(
            app_module.extract_batfish_failure_reason(SECRET_IN_REASON_FAILURE),
            "Unrecognized line password: [redacted] in configs/r1.cfg",
        )

    def test_load_and_activation_responses_carry_the_redacted_reason(self):
        with app_module.app.app_context():
            load_response, load_status = app_module.snapshot_load_error_response(
                BatfishSnapshotLoadError("fx-reason", SECRET_IN_REASON_FAILURE), "reference"
            )
            activation_response, activation_status = app_module.snapshot_activation_error_response(
                "fx-reason", RuntimeError(SECRET_IN_REASON_FAILURE)
            )

        expected_reason = "Unrecognized line password: [redacted] in configs/r1.cfg"
        self.assertEqual((load_status, activation_status), (422, 422))
        load_payload = load_response.get_json()
        self.assertEqual(load_payload["details"]["reason"], expected_reason)
        self.assertEqual(
            load_payload["message"],
            f"Batfish could not load reference snapshot 'fx-reason': {expected_reason}",
        )
        self.assertEqual(activation_response.get_json()["details"]["reason"], expected_reason)
        for response in (load_response, activation_response):
            self.assertNotIn("example-not-a-secret", response.get_data(as_text=True))


class InitializeNetworkSnapshotNameTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = BatfishService()
        self.service.current_snapshot_name = "fx-previous"
        self.service._session = mock.Mock()
        self.names_during_init = []

    def tearDown(self):
        self.temp_dir.cleanup()

    def record_name_during_init(self, *args, **kwargs):
        self.names_during_init.append(self.service.current_snapshot_name)

    def test_snapshot_name_is_kept_while_batfish_initializes_and_on_failure(self):
        def fail(*args, **kwargs):
            self.record_name_during_init()
            raise RuntimeError("Work terminated abnormally")

        self.service._session.init_snapshot.side_effect = fail

        with self.assertRaises(RuntimeError):
            self.service.initialize_network(self.temp_dir.name, "fx-next")

        self.assertEqual(self.names_during_init, ["fx-previous"])
        self.assertEqual(self.service.current_snapshot_name, "fx-previous")

    def test_snapshot_name_is_set_after_batfish_accepts_the_snapshot(self):
        self.service._session.init_snapshot.side_effect = self.record_name_during_init
        with mock.patch.object(self.service, "get_file_parse_status", return_value=[]), \
                mock.patch.object(self.service, "get_init_issues", return_value=[]), \
                mock.patch.object(self.service, "get_parse_warnings", return_value=[]):
            result = self.service.initialize_network(self.temp_dir.name, "fx-next")

        self.assertEqual(self.names_during_init, ["fx-previous"])
        self.assertEqual(self.service.current_snapshot_name, "fx-next")
        self.assertEqual(result["snapshot"], "fx-next")


class SpecifierErrorTest(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.batfish_service = app_module.batfish_service

    def query_error(self, query_name: str) -> BatfishQueryError:
        return BatfishQueryError(
            query_name=query_name,
            message="Batfish work failed: Error parsing '((' as nodeSpecifier after index 2.",
            error_type="specifier_no_match",
            details={"query": query_name},
            hints=["Check node, policy, filter, or location specifiers before running the query."],
            status_code=400,
        )

    def test_specifier_parse_errors_keep_the_structured_batfish_error(self):
        routes = [
            ("/api/validation/resolve-node-specifier", "resolve_node_specifier", {"nodes": "(("}),
            ("/api/validation/resolve-interface-specifier", "resolve_interface_specifier", {"interfaces": "(("}),
            ("/api/validation/resolve-filter-specifier", "resolve_filter_specifier", {"filters": "(("}),
            ("/api/advanced/resolve-location-specifier", "resolve_location_specifier", {"locations": "(("}),
            ("/api/advanced/resolve-ip-specifier", "resolve_ip_specifier", {"ips": "(("}),
            ("/api/advanced/resolve-ips-of-location-specifier", "resolve_ips_of_location_specifier", {"locations": "(("}),
        ]
        for path, method_name, body in routes:
            with self.subTest(path=path):
                with mock.patch.object(
                    self.batfish_service, method_name, side_effect=self.query_error(method_name)
                ):
                    response = self.client.post(path, json=body)

                payload = assert_structured_error(self, response, 400, "specifier_no_match")
                self.assertIn("Error parsing", payload["message"])
                self.assertEqual(payload["details"], {"query": method_name})
                self.assertTrue(payload["hints"])

    def test_list_input_is_joined_with_the_batfish_union_operator(self):
        with mock.patch.object(self.batfish_service, "resolve_node_specifier", return_value=[]) as resolve:
            response = self.client.post(
                "/api/validation/resolve-node-specifier",
                json={"nodes": ["core-rtr1", " core-rtr2 ", ""]},
            )

        self.assertEqual(response.status_code, 200)
        resolve.assert_called_once_with("core-rtr1,core-rtr2", None)

    def test_query_string_lists_are_joined_with_the_batfish_union_operator(self):
        with mock.patch.object(
            self.batfish_service, "get_filter_line_reachability", return_value=[]
        ) as reachability:
            response = self.client.get(
                "/api/acl/filter-line-reachability?nodes=core-rtr1&nodes=core-rtr2&filters=ACL1"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(reachability.call_args.kwargs["nodes"], "core-rtr1,core-rtr2")

    def test_regex_typed_vrfs_keep_the_regex_alternation(self):
        with mock.patch.object(self.batfish_service, "get_lpm_routes", return_value=[]) as lpm:
            response = self.client.post(
                "/api/topology/lpm-routes",
                json={"ip": "192.0.2.1", "nodes": ["r1", "r2"], "vrfs": ["default", "mgmt"]},
            )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        lpm.assert_called_once_with("192.0.2.1", "r1,r2", "default|mgmt")


AUTH_VALIDATION_SCRIPT = r'''
import io
import json
import os
import sys
from unittest import mock

from app import app

batfish_service = sys.modules["app"].batfish_service

ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]
SUBMITTED_SECRET = "Submitted-Secret-Value-9!"

results = {}


def record(key, response):
    results[key] = {
        "status": response.status_code,
        "is_json": response.is_json,
        "json": response.get_json(silent=True),
        "body": response.get_data(as_text=True),
    }


admin = app.test_client()
login = admin.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
admin.environ_base["HTTP_X_CSRF_TOKEN"] = login.get_json()["data"]["csrf_token"]
admin_id = admin.get("/api/users/me").get_json()["data"]["id"]

record("register_missing_password", app.test_client().post(
    "/api/users", json={"username": "newuser", "email": "newuser@example.test"}))
record("password_change_missing_new", admin.put(
    f"/api/users/{admin_id}/password", json={"current_password": SUBMITTED_SECRET}))
record("password_reset_missing_token", app.test_client().post(
    "/api/auth/password-reset", json={"new_password": SUBMITTED_SECRET}))
record("update_user_non_object", admin.put(f"/api/users/{admin_id}", json=["full_name"]))
record("login_missing_password", app.test_client().post("/api/auth/login", json={"username": "admin"}))
record("login_malformed_json", app.test_client().post(
    "/api/auth/login", data="not json", content_type="application/json"))
record("register_malformed_json", app.test_client().post(
    "/api/users", data='{"username": ', content_type="application/json"))
record("admin_login_still_works", app.test_client().post(
    "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}))

no_csrf_header = app.test_client()
no_csrf_header.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
record("malformed_json_without_csrf_header", no_csrf_header.post(
    "/api/snapshots", data='{"name": ', content_type="application/json"))
record("json_array_without_csrf_header", no_csrf_header.post("/api/snapshots", json=["fx-array"]))
record("malformed_json_with_csrf_header", admin.post(
    "/api/snapshots", data='{"name": ', content_type="application/json"))
record("text_body_with_csrf_header", admin.post(
    "/api/snapshots", data='{"name": "fx-text"}', content_type="text/plain"))
record("empty_body_with_csrf_header", admin.post("/api/snapshots"))

form_csrf = app.test_client()
form_csrf_token = form_csrf.post(
    "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).get_json()["data"]["csrf_token"]
record("form_body_with_csrf_form_field", form_csrf.post(
    "/api/snapshots",
    data={"name": "fx-form", "csrf_token": form_csrf_token},
    content_type="application/x-www-form-urlencoded",
))
record("multipart_body_with_csrf_form_field", form_csrf.post(
    "/api/snapshots",
    data={"name": "fx-multipart", "csrf_token": form_csrf_token},
    content_type="multipart/form-data",
))


def active_flags():
    return {row["name"]: row["active"] for row in admin.get("/api/snapshots").get_json()["data"]}


record("create_active_snapshot", admin.post("/api/snapshots", json={"name": "fx-auth-active"}))
record("upload_active_snapshot_config", admin.post(
    "/api/snapshots/fx-auth-active/files",
    data={"file": (io.BytesIO(b"hostname r1\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"), "r1.cfg")},
    content_type="multipart/form-data",
))
with mock.patch.object(batfish_service, "initialize_network", return_value={"status": "success"}):
    record("activate_active_snapshot", admin.post("/api/snapshots/fx-auth-active/activate"))
results["active_after_activation"] = active_flags()
with mock.patch.object(
    batfish_service, "initialize_network", side_effect=RuntimeError("Work terminated abnormally")
):
    record("reactivate_active_snapshot_fails", admin.post("/api/snapshots/fx-auth-active/activate"))
results["active_after_failed_reactivation"] = active_flags()

with mock.patch.object(batfish_service, "initialize_network", return_value={"status": "success"}):
    admin.post("/api/snapshots/fx-auth-active/activate")
with mock.patch.object(
    batfish_service, "initialize_network", side_effect=RuntimeError("Work terminated abnormally")
):
    record("layer1_reload_fails", admin.put("/api/snapshots/fx-auth-active/layer1-topology", json={"edges": []}))
results["active_after_failed_layer1_reload"] = active_flags()

with mock.patch.object(batfish_service, "initialize_network", return_value={"status": "success"}):
    admin.post("/api/snapshots/fx-auth-active/activate")
batfish_service.current_snapshot_name = None
with mock.patch.object(
    batfish_service, "initialize_network", side_effect=RuntimeError("Work terminated abnormally")
):
    record("session_snapshot_sync_fails", admin.get("/api/network/nodes"))
results["active_after_failed_session_snapshot_sync"] = active_flags()

with mock.patch.object(batfish_service, "initialize_network", return_value={"status": "success"}):
    admin.post("/api/snapshots/fx-auth-active/activate")
with mock.patch.object(
    batfish_service, "initialize_network", side_effect=RuntimeError("Work terminated abnormally")
):
    record("network_initialize_fails", admin.post(
        "/api/network/initialize", json={"snapshot_name": "fx-auth-active"}))
results["active_after_failed_network_initialize"] = active_flags()

print(json.dumps(results))
'''


class AuthValidationErrorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshots_dir = Path(temp_dir) / "snapshots"
            snapshots_dir.mkdir()
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "error-response-test-secret-key",
                "JWT_SECRET_KEY": "error-response-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "error-response-test-csrf-secret-key",
                "CSRF_MODE": "session",
                "ALLOW_REGISTRATION": "true",
                "AUTH_DEFAULT_ADMIN_USER": "admin",
                "AUTH_DEFAULT_ADMIN_PASS": "ErrorResponseAdmin123!",
                "DATABASE_URL": f"sqlite:///{Path(temp_dir) / 'error-response-test.db'}",
                "SNAPSHOTS_DIR": str(snapshots_dir),
                "PYTHONPATH": str(BACKEND_DIR),
            })
            completed = subprocess.run(
                [sys.executable, "-c", AUTH_VALIDATION_SCRIPT],
                capture_output=True,
                text=True,
                env=env,
                cwd=temp_dir,
            )
        if completed.returncode != 0:
            raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
        cls.results = json.loads(completed.stdout.strip().splitlines()[-1])

    def assert_validation_error(self, key: str, field: str | None):
        result = self.results[key]
        self.assertEqual(result["status"], 400, result["body"][:300])
        self.assertTrue(result["is_json"])
        payload = result["json"]
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "validation_error")
        if field is None:
            self.assertNotIn("details", payload)
        else:
            self.assertEqual(payload["details"], {"field": field})
            self.assertIn(field, payload["message"])
        self.assertNotIn("Submitted-Secret-Value-9!", result["body"])

    def test_register_missing_password_is_400(self):
        self.assert_validation_error("register_missing_password", "password")

    def test_password_change_missing_new_password_is_400(self):
        self.assert_validation_error("password_change_missing_new", "new_password")

    def test_password_reset_missing_token_is_400(self):
        self.assert_validation_error("password_reset_missing_token", "token")

    def test_update_user_with_non_object_body_is_400(self):
        result = self.results["update_user_non_object"]
        self.assertEqual(result["status"], 400, result["body"][:300])
        self.assertEqual(result["json"]["code"], "invalid_json")
        self.assertEqual(result["json"]["message"], "Request body must be a JSON object")

    def test_login_missing_password_is_structured_400(self):
        self.assert_validation_error("login_missing_password", "password")

    def test_malformed_json_on_auth_routes_is_400(self):
        for key in ("login_malformed_json", "register_malformed_json"):
            with self.subTest(key=key):
                result = self.results[key]
                self.assertEqual(result["status"], 400, result["body"][:300])
                self.assertEqual(result["json"]["code"], "invalid_json")

    def test_valid_login_is_unaffected(self):
        self.assertEqual(self.results["admin_login_still_works"]["status"], 200)

    def test_csrf_check_does_not_parse_unreadable_json(self):
        for key in ("malformed_json_without_csrf_header", "json_array_without_csrf_header"):
            with self.subTest(key=key):
                result = self.results[key]
                self.assertEqual(result["status"], 403, result["body"][:300])
                self.assertEqual(result["json"]["message"], "CSRF validation failed")

    def test_unreadable_bodies_with_csrf_token_are_invalid_json(self):
        for key in ("malformed_json_with_csrf_header", "text_body_with_csrf_header"):
            with self.subTest(key=key):
                result = self.results[key]
                self.assertEqual(result["status"], 400, result["body"][:300])
                self.assertEqual(result["json"]["code"], "invalid_json")

    def test_empty_body_with_csrf_token_is_invalid_json(self):
        result = self.results["empty_body_with_csrf_header"]
        self.assertEqual(result["status"], 400, result["body"][:300])
        self.assertEqual(result["json"]["code"], "invalid_json")

    def test_form_bodies_read_by_the_csrf_check_are_invalid_json(self):
        for key in ("form_body_with_csrf_form_field", "multipart_body_with_csrf_form_field"):
            with self.subTest(key=key):
                result = self.results[key]
                self.assertEqual(result["status"], 400, result["body"][:300])
                self.assertEqual(result["json"]["code"], "invalid_json")
                self.assertEqual(result["json"]["message"], "Request body must be valid JSON")

    def test_failed_reactivation_clears_the_session_active_snapshot(self):
        self.assertEqual(self.results["upload_active_snapshot_config"]["status"], 200)
        self.assertEqual(self.results["activate_active_snapshot"]["status"], 200)
        self.assertEqual(self.results["active_after_activation"], {"fx-auth-active": True})
        self.assertEqual(self.results["reactivate_active_snapshot_fails"]["status"], 422)
        self.assertEqual(self.results["active_after_failed_reactivation"], {"fx-auth-active": False})

    def test_failed_layer1_reload_clears_the_session_active_snapshot(self):
        result = self.results["layer1_reload_fails"]
        self.assertEqual(result["status"], 422, result["body"][:300])
        self.assertEqual(result["json"]["code"], "snapshot_activation_failed")
        self.assertNotIn("Work terminated abnormally", result["body"])
        self.assertEqual(self.results["active_after_failed_layer1_reload"], {"fx-auth-active": False})

    def test_failed_session_snapshot_sync_clears_the_session_active_snapshot(self):
        result = self.results["session_snapshot_sync_fails"]
        self.assertEqual(result["status"], 422, result["body"][:300])
        self.assertEqual(result["json"]["code"], "snapshot_activation_failed")
        self.assertNotIn("Work terminated abnormally", result["body"])
        self.assertEqual(self.results["active_after_failed_session_snapshot_sync"], {"fx-auth-active": False})

    def test_failed_network_initialize_clears_the_session_active_snapshot(self):
        result = self.results["network_initialize_fails"]
        self.assertEqual(result["status"], 422, result["body"][:300])
        self.assertEqual(result["json"]["code"], "snapshot_activation_failed")
        self.assertNotIn("Work terminated abnormally", result["body"])
        self.assertEqual(self.results["active_after_failed_network_initialize"], {"fx-auth-active": False})


if __name__ == "__main__":
    unittest.main()
