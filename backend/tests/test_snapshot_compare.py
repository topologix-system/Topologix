import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app as app_module
from services.batfish_service import BatfishQueryError, BatfishService, BatfishSnapshotLoadError

# Sanitized reproduction of the work log Batfish returns when differential
# reachability finds no start location shared by both snapshots (synthetic ids).
SANITIZED_NO_COMMON_START_LOCATION = (
    "Work terminated abnormally\n"
    'work_item: {"containerName": "example_network", "id": "00000000-0000-0000-0000-000000000000"}\n'
    "\n"
    "log: Loading configurations for NetworkSnapshot{network=example, snapshot=example}\n"
    "Caused by: org.batfish.common.BatfishException: Failed to answer question DifferentialReachabilityQuestion\n"
    "\tat org.batfish.main.Batfish.answer(Batfish.java:544)\n"
    "Caused by: org.batfish.common.BatfishException: "
    "no matching startLocation is present and active in both snapshots\n"
    "\tat org.batfish.question.differentialreachability.DifferentialReachabilityAnswerer.answerDiff("
    "DifferentialReachabilityAnswerer.java:61)\n"
)

# Sanitized reproduction of the work log Batfish returns when a snapshot
# without device configurations is loaded (synthetic ids and names).
SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE = (
    "Work terminated abnormally\n"
    'work_item: {"containerName": "example_network", "id": "00000000-0000-0000-0000-000000000000", '
    '"requestParams": {"testrig": "example", "si": "", "sv": "", "initinfo": ""}, "testrigName": "example"}\n'
    "\n"
    "log: \n"
    "*** READING DEVICE CONFIGURATION FILES ***\n"
    "Snapshot 11111111-1111-1111-1111-111111111111 in network "
    "22222222-2222-2222-2222-222222222222 has total number of network configs:0\n"
    "Exception in container:22222222-2222-2222-2222-222222222222, "
    "testrig:11111111-1111-1111-1111-111111111111; "
    "exception:org.batfish.common.BatfishException: No valid configurations found in snapshot\n"
    "\tat org.batfish.main.Batfish.serializeVendorConfigs(Batfish.java:2800)\n"
    "\tat java.base/java.lang.Thread.run(Thread.java:840)\n"
    '{"answerElements":[{"class":"org.batfish.common.BatfishException$BatfishStackTrace",'
    '"answer":["org.batfish.common.BatfishException: No valid configurations found in snapshot",'
    '"   at org.batfish.main.Batfish.serializeVendorConfigs(Batfish.java:2800)",'
    '"   at java.base/java.lang.Thread.run(Thread.java:840)",""]}],"status":"FAILURE"}'
)
LOAD_FAILURE_MARKERS = (
    "work_item",
    "Work terminated",
    "at org.",
    "at java.base",
    "Exception in container",
    "answerElements",
    "00000000-0000",
    "11111111-1111",
    "22222222-2222",
)


def route(node, network, next_hop, protocol="static", vrf="default"):
    return {
        "node": node,
        "vrf": vrf,
        "network": network,
        "next_hop": next_hop,
        "next_hop_ip": None,
        "next_hop_interface": "",
        "protocol": protocol,
        "metric": 0,
        "admin_distance": 1,
        "tag": None,
    }


class EcmpRouteDiffTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()

    def test_ecmp_next_hops_are_compared_as_sets(self):
        base = [
            route("r1", "10.24.4.0/24", "ip 10.2.13.2"),
            route("r1", "10.24.4.0/24", "ip 10.2.12.2"),
            route("r1", "10.0.0.0/24", "ip 10.2.12.2"),
            route("r1", "10.0.0.0/24", "ip 10.2.13.2"),
        ]
        comparison = [
            route("r1", "10.24.4.0/24", "ip 10.2.12.2"),
            route("r1", "10.0.0.0/24", "ip 10.2.13.2"),
            route("r1", "10.0.0.0/24", "ip 10.2.12.2"),
        ]

        diff = self.service._compare_routes_diff(base, comparison)

        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual((diff["total_base"], diff["total_comparison"]), (4, 3))
        self.assertEqual(diff["modified"], [{
            "network": "10.24.4.0/24",
            "node": "r1",
            "vrf": "default",
            "base_next_hop": "ip 10.2.12.2, ip 10.2.13.2",
            "comparison_next_hop": "ip 10.2.12.2",
            "base_next_hops": ["ip 10.2.12.2", "ip 10.2.13.2"],
            "comparison_next_hops": ["ip 10.2.12.2"],
            "base_protocol": "static",
            "comparison_protocol": "static",
        }])

    def test_added_and_removed_prefixes_list_every_ecmp_row(self):
        base = [
            route("r1", "10.1.0.0/24", "ip 10.2.12.2"),
            route("r1", "10.1.0.0/24", "ip 10.2.13.2"),
        ]
        comparison = [
            route("r1", "10.9.0.0/24", "ip 10.2.12.2"),
            route("r1", "10.9.0.0/24", "ip 10.2.13.2"),
        ]

        diff = self.service._compare_routes_diff(base, comparison)

        self.assertEqual(diff["added"], comparison)
        self.assertEqual(diff["removed"], base)
        self.assertEqual(diff["modified"], [])

    def test_single_path_changes_keep_the_previous_string_fields(self):
        diff = self.service._compare_routes_diff(
            [route("r1", "10.1.0.0/24", "ip 10.2.12.2", protocol="static")],
            [route("r1", "10.1.0.0/24", "ip 10.2.12.2", protocol="ospf")],
        )

        modified = diff["modified"][0]
        self.assertEqual(modified["base_next_hop"], "ip 10.2.12.2")
        self.assertEqual(modified["comparison_next_hop"], "ip 10.2.12.2")
        self.assertEqual((modified["base_protocol"], modified["comparison_protocol"]), ("static", "ospf"))

    def test_vrfs_and_nodes_are_separate_keys(self):
        diff = self.service._compare_routes_diff(
            [route("r1", "10.1.0.0/24", "ip 10.2.12.2", vrf="default")],
            [route("r1", "10.1.0.0/24", "ip 10.2.12.2", vrf="mgmt")],
        )

        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["removed"]), 1)
        self.assertEqual(diff["modified"], [])


class _FakeBatfishSession:
    """Mimics the pybatfish Session attributes touched by snapshot loading."""

    def __init__(self, snapshot=None):
        self.snapshot = snapshot
        self.network = None
        self.loaded = []

    def set_network(self, name):
        self.network = name

    def get_component_versions(self):
        return {"Batfish": "test"}

    def init_snapshot(self, path, name=None, overwrite=False):
        self.loaded.append((Path(path).name, name, overwrite))
        self.snapshot = name
        return name


class SnapshotScopeTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshots_dir = Path(self.temp_dir.name)
        for name in ("base-a", "comp-b", "active-x"):
            (self.snapshots_dir / name / "configs").mkdir(parents=True)
        self.service = BatfishService()
        self.service._session = _FakeBatfishSession(snapshot="active-x")
        self.service.current_snapshot_name = "active-x"
        self.service._initialized = True
        self.seen = []

    def tearDown(self):
        self.temp_dir.cleanup()

    def queried(self, kind, data):
        def query(**kwargs):
            self.service._ensure_initialized()
            snapshot = self.service._session.snapshot
            self.seen.append((kind, snapshot))
            return data[snapshot]
        return query

    def assert_active_state_unchanged(self, current="active-x", initialized=True, session_snapshot="active-x"):
        self.assertEqual(self.service.current_snapshot_name, current)
        self.assertEqual(self.service._initialized, initialized)
        self.assertEqual(self.service._session.snapshot, session_snapshot)
        self.assertIsNone(self.service._query_snapshot_name)


class CompareSnapshotsTest(SnapshotScopeTestCase):
    def setUp(self):
        super().setUp()
        nodes = {
            "base-a": [{"node": "r1"}, {"node": "r2"}],
            "comp-b": [{"node": "r3"}],
            "active-x": [{"node": "x1"}],
        }
        edges = {"base-a": [], "comp-b": [], "active-x": []}
        routes = {"base-a": [route("r1", "10.1.0.0/24", "ip 10.2.12.2")], "comp-b": [], "active-x": []}
        self.patches = [
            mock.patch.object(self.service, "get_node_properties", side_effect=self.queried("nodes", nodes)),
            mock.patch.object(self.service, "get_layer3_edges", side_effect=self.queried("edges", edges)),
            mock.patch.object(self.service, "get_routes", side_effect=self.queried("routes", routes)),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        super().tearDown()

    def compare(self, base="base-a", comparison="comp-b"):
        return self.service.compare_snapshots(
            base,
            comparison,
            base_snapshot_path=self.snapshots_dir / base,
            comparison_snapshot_path=self.snapshots_dir / comparison,
        )

    def test_reachability_failure_keeps_the_other_diffs_and_reports_the_reason(self):
        def fail(**kwargs):
            self.service._ensure_initialized()
            raise RuntimeError("differentialReachability query failed") from RuntimeError(
                SANITIZED_NO_COMMON_START_LOCATION
            )

        with mock.patch.object(self.service, "get_differential_reachability", side_effect=fail):
            result = self.compare()

        self.assertEqual(result["reachability"], [])
        self.assertEqual(result["reachability_error"], {
            "message": "Differential reachability could not be computed for these snapshots",
            "reason": "no matching startLocation is present and active in both snapshots",
        })
        self.assertEqual(result["nodes"]["added"], ["r3"])
        self.assertEqual(sorted(result["nodes"]["removed"]), ["r1", "r2"])
        self.assertEqual(len(result["routes"]["removed"]), 1)
        self.assertNotIn("work_item", str(result["reachability_error"]))
        self.assert_active_state_unchanged()

    def test_successful_comparison_has_no_reachability_error(self):
        with mock.patch.object(
            self.service, "get_differential_reachability", return_value=[{"flow": {}}]
        ) as reachability:
            result = self.compare()

        self.assertEqual(result["reachability"], [{"flow": {}}])
        self.assertIsNone(result["reachability_error"])
        reachability.assert_called_once_with(reference_snapshot="base-a", snapshot="comp-b")

    def test_each_snapshot_is_queried_by_name_and_the_active_snapshot_stays(self):
        with mock.patch.object(self.service, "get_differential_reachability", return_value=[]):
            self.compare()

        self.assertEqual(self.service._session.loaded, [
            ("base-a", "base-a", True),
            ("comp-b", "comp-b", True),
        ])
        self.assertEqual(self.seen, [
            ("nodes", "base-a"), ("edges", "base-a"), ("routes", "base-a"),
            ("nodes", "comp-b"), ("edges", "comp-b"), ("routes", "comp-b"),
        ])
        self.assert_active_state_unchanged()

    def test_the_active_snapshot_side_is_queried_without_reloading(self):
        for base, comparison, loaded_name in (("active-x", "comp-b", "comp-b"), ("base-a", "active-x", "base-a")):
            with self.subTest(base=base, comparison=comparison):
                self.service._session.loaded = []
                self.seen = []
                with mock.patch.object(self.service, "get_differential_reachability", return_value=[]) as reachability:
                    self.compare(base, comparison)

                self.assertEqual(self.service._session.loaded, [(loaded_name, loaded_name, True)])
                self.assertEqual(self.seen, [
                    ("nodes", base), ("edges", base), ("routes", base),
                    ("nodes", comparison), ("edges", comparison), ("routes", comparison),
                ])
                reachability.assert_called_once_with(reference_snapshot=base, snapshot=comparison)
                self.assert_active_state_unchanged()

    def test_a_failing_reload_cannot_break_the_active_snapshot(self):
        def fail_for_active(path, name=None, overwrite=False):
            if name == "active-x":
                self.service._session.snapshot = name
                raise RuntimeError("Work terminated abnormally")
            self.service._session.loaded.append((Path(path).name, name, overwrite))

        self.service._session.init_snapshot = fail_for_active

        with mock.patch.object(self.service, "get_differential_reachability", return_value=[]):
            result = self.compare("active-x", "comp-b")

        self.assertEqual(result["nodes"]["added"], ["r3"])
        self.assertEqual(result["nodes"]["removed"], ["x1"])
        self.assert_active_state_unchanged()

    def test_a_same_named_snapshot_that_is_not_initialized_is_loaded(self):
        self.service._initialized = False

        with mock.patch.object(self.service, "get_differential_reachability", return_value=[]):
            self.compare("active-x", "comp-b")

        self.assertEqual(self.service._session.loaded, [
            ("active-x", "active-x", True),
            ("comp-b", "comp-b", True),
        ])

    def test_comparison_without_an_active_snapshot_leaves_none_active(self):
        self.service.current_snapshot_name = None
        self.service._initialized = False
        self.service._session.snapshot = None

        with mock.patch.object(self.service, "get_differential_reachability", return_value=[]):
            self.compare()

        self.assert_active_state_unchanged(current=None, initialized=False, session_snapshot=None)
        with self.assertRaises(RuntimeError):
            self.service._ensure_initialized()

    def test_failed_snapshot_load_restores_the_session_snapshot(self):
        def fail_after_switch(path, name=None, overwrite=False):
            self.service._session.snapshot = name
            raise RuntimeError("Work terminated abnormally")

        self.service._session.init_snapshot = fail_after_switch

        with self.assertRaises(RuntimeError):
            self.compare()

        self.assert_active_state_unchanged()


class DifferentialReachabilityQueryTest(SnapshotScopeTestCase):
    def setUp(self):
        super().setUp()
        self.service._session.q = mock.MagicMock()
        self.question = self.service._session.q.differentialReachability
        self.answer = self.question.return_value.answer
        self.answer.return_value.frame.return_value = mock.MagicMock(empty=True)

    def test_a_batfish_work_failure_is_a_query_error_without_the_work_log(self):
        self.answer.side_effect = RuntimeError(SANITIZED_NO_COMMON_START_LOCATION)

        with self.assertRaises(BatfishQueryError) as raised:
            self.service.get_differential_reachability(reference_snapshot="base-a")

        error = raised.exception
        self.assertEqual(error.query_name, "differentialReachability")
        self.assertEqual(error.error_type, "query_error")
        self.assertEqual(error.status_code, 400)
        self.assertEqual(
            error.message,
            "Batfish work failed: no matching startLocation is present and active in both snapshots",
        )
        for marker in LOAD_FAILURE_MARKERS:
            self.assertNotIn(marker, f"{error.message} {error.details}")
        self.assertIsInstance(error.__cause__, RuntimeError)

    def test_the_reference_snapshot_is_loaded_by_name_and_the_active_snapshot_stays(self):
        result = self.service.get_differential_reachability(
            reference_snapshot="base-a",
            reference_snapshot_path=self.snapshots_dir / "base-a",
        )

        self.assertEqual(result, [])
        self.assertEqual(self.service._session.loaded, [("base-a", "base-a", True)])
        self.answer.assert_called_once_with(reference_snapshot="base-a")
        self.assert_active_state_unchanged()

    def test_an_active_reference_snapshot_is_queried_without_reloading(self):
        self.service.get_differential_reachability(
            reference_snapshot="active-x",
            snapshot="comp-b",
            reference_snapshot_path=self.snapshots_dir / "active-x",
        )

        self.assertEqual(self.service._session.loaded, [])
        self.answer.assert_called_once_with(reference_snapshot="active-x", snapshot="comp-b")
        self.assert_active_state_unchanged()

    def test_the_comparison_snapshot_is_loaded_by_name_unless_it_is_active(self):
        cases = (
            ("comp-b", [("base-a", "base-a", True), ("comp-b", "comp-b", True)]),
            ("active-x", [("base-a", "base-a", True)]),
            ("base-a", [("base-a", "base-a", True)]),
        )
        for snapshot, expected_loads in cases:
            with self.subTest(snapshot=snapshot):
                self.service._session.loaded = []
                self.answer.reset_mock()

                self.service.get_differential_reachability(
                    reference_snapshot="base-a",
                    snapshot=snapshot,
                    reference_snapshot_path=self.snapshots_dir / "base-a",
                    snapshot_path=self.snapshots_dir / snapshot,
                )

                self.assertEqual(self.service._session.loaded, expected_loads)
                self.answer.assert_called_once_with(reference_snapshot="base-a", snapshot=snapshot)
                self.assert_active_state_unchanged()

    def test_a_comparison_snapshot_batfish_rejects_raises_a_load_error_naming_it(self):
        loaded = self.service._session.init_snapshot

        def reject_comparison(path, name=None, overwrite=False):
            if name == "comp-b":
                self.service._session.snapshot = name
                raise RuntimeError(SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)
            return loaded(path, name=name, overwrite=overwrite)

        self.service._session.init_snapshot = reject_comparison

        with self.assertRaises(BatfishSnapshotLoadError) as raised:
            self.service.get_differential_reachability(
                reference_snapshot="base-a",
                snapshot="comp-b",
                reference_snapshot_path=self.snapshots_dir / "base-a",
                snapshot_path=self.snapshots_dir / "comp-b",
            )

        self.assertEqual(raised.exception.snapshot_name, "comp-b")
        self.question.assert_not_called()
        self.assert_active_state_unchanged()

    def test_invalid_headers_are_rejected_before_the_reference_snapshot_is_loaded(self):
        with self.assertRaises(BatfishQueryError) as raised:
            self.service.get_differential_reachability(
                reference_snapshot="base-a",
                headers={"icmpTypes": "!0-255"},
                reference_snapshot_path=self.snapshots_dir / "base-a",
            )

        self.assertEqual(raised.exception.error_type, "header_constraint_invalid")
        self.assertEqual(self.service._session.loaded, [])
        self.question.assert_not_called()

    def test_a_reference_snapshot_batfish_rejects_raises_a_load_error_naming_it(self):
        def reject(path, name=None, overwrite=False):
            self.service._session.snapshot = name
            raise RuntimeError(SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)

        self.service._session.init_snapshot = reject

        with self.assertRaises(BatfishSnapshotLoadError) as raised:
            self.service.get_differential_reachability(
                reference_snapshot="base-a",
                reference_snapshot_path=self.snapshots_dir / "base-a",
            )

        self.assertEqual(raised.exception.snapshot_name, "base-a")
        self.question.assert_not_called()
        self.assert_active_state_unchanged()


class InactiveSnapshotInterfacesTest(SnapshotScopeTestCase):
    def setUp(self):
        super().setUp()
        interfaces = {
            "active-x": [{"hostname": "x1", "interface": "Gi0/0"}],
            "comp-b": [{"hostname": "b1", "interface": "Gi0/1"}],
        }
        self.patch = mock.patch.object(
            self.service, "get_interface_properties", side_effect=self.queried("interfaces", interfaces)
        )
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        super().tearDown()

    def test_inactive_snapshot_is_loaded_and_queried_without_activation(self):
        result = self.service.get_snapshot_interface_properties(self.snapshots_dir / "comp-b", "comp-b")

        self.assertEqual(result, [{"hostname": "b1", "interface": "Gi0/1"}])
        self.assertEqual(self.service._session.loaded, [("comp-b", "comp-b", True)])
        self.assertEqual(self.seen, [("interfaces", "comp-b")])
        self.assert_active_state_unchanged()

    def test_active_snapshot_is_queried_without_reloading(self):
        result = self.service.get_snapshot_interface_properties(self.snapshots_dir / "active-x", "active-x")

        self.assertEqual(result, [{"hostname": "x1", "interface": "Gi0/0"}])
        self.assertEqual(self.service._session.loaded, [])
        self.assert_active_state_unchanged()

    def test_missing_snapshot_directory_is_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.service.get_snapshot_interface_properties(self.snapshots_dir / "missing", "missing")

        self.assert_active_state_unchanged()

    def test_a_snapshot_batfish_rejects_raises_a_load_error_naming_it(self):
        def reject(path, name=None, overwrite=False):
            self.service._session.snapshot = name
            raise RuntimeError(SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)

        self.service._session.init_snapshot = reject

        with self.assertRaises(BatfishSnapshotLoadError) as raised:
            self.service.get_snapshot_interface_properties(self.snapshots_dir / "comp-b", "comp-b")

        self.assertEqual(raised.exception.snapshot_name, "comp-b")
        self.assertEqual(str(raised.exception), SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assert_active_state_unchanged()

    def test_load_failures_other_than_a_batfish_rejection_keep_their_type(self):
        def unreachable(path, name=None, overwrite=False):
            raise ConnectionError("Batfish is unreachable")

        self.service._session.init_snapshot = unreachable

        with self.assertRaises(ConnectionError) as raised:
            self.service.get_snapshot_interface_properties(self.snapshots_dir / "comp-b", "comp-b")

        self.assertNotIsInstance(raised.exception, BatfishSnapshotLoadError)
        self.assert_active_state_unchanged()


class SnapshotInterfacesRouteTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshot_service = app_module.snapshot_service
        self.original_snapshots_dir = self.snapshot_service.snapshots_dir
        self.snapshot_service.snapshots_dir = Path(self.temp_dir.name)
        self.batfish_service = app_module.batfish_service
        self.original_state = (self.batfish_service.current_snapshot_name, self.batfish_service._initialized)
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.snapshot_service.snapshots_dir = self.original_snapshots_dir
        self.batfish_service.current_snapshot_name, self.batfish_service._initialized = self.original_state
        self.temp_dir.cleanup()

    def test_interfaces_of_an_inactive_snapshot_do_not_activate_it(self):
        self.snapshot_service.create_snapshot("fx-if-b")
        self.batfish_service.current_snapshot_name = "fx-if-a"
        self.batfish_service._initialized = True
        rows = [
            {"hostname": "r1", "interface": "Gi0/1", "active": True, "description": ""},
            {"hostname": "r1", "interface": "Gi0/0", "active": False, "description": "uplink"},
        ]

        fake_session = _FakeBatfishSession(snapshot="fx-if-a")
        with mock.patch.object(self.batfish_service, "_session", fake_session), \
                mock.patch.object(self.batfish_service, "_load_snapshot") as load, \
                mock.patch.object(self.batfish_service, "get_interface_properties", return_value=rows), \
                mock.patch.object(self.batfish_service, "initialize_network") as initialize:
            response = self.client.get("/api/snapshots/fx-if-b/interfaces")

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(
            [item["name"] for item in response.get_json()["data"]["r1"]["interfaces"]],
            ["Gi0/0", "Gi0/1"],
        )
        load.assert_called_once()
        self.assertEqual(load.call_args.args[1], "fx-if-b")
        initialize.assert_not_called()
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-if-a")
        self.assertEqual(fake_session.snapshot, "fx-if-a")
        flags = {row["name"]: row["active"] for row in self.client.get("/api/snapshots").get_json()["data"]}
        self.assertEqual(flags, {"fx-if-b": False})


class SnapshotLoadFailureRouteTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshot_service = app_module.snapshot_service
        self.original_snapshots_dir = self.snapshot_service.snapshots_dir
        self.snapshot_service.snapshots_dir = Path(self.temp_dir.name)
        self.batfish_service = app_module.batfish_service
        self.original_state = (self.batfish_service.current_snapshot_name, self.batfish_service._initialized)
        self.batfish_service.current_snapshot_name = "fx-active"
        self.batfish_service._initialized = True
        self.client = app_module.app.test_client()

        for name in ("fx-empty", "fx-full", "fx-active"):
            self.snapshot_service.create_snapshot(name)
        self.fake_session = _FakeBatfishSession(snapshot="fx-active")
        loaded = self.fake_session.init_snapshot

        def init_snapshot(path, name=None, overwrite=False):
            if name == "fx-empty":
                self.fake_session.snapshot = name
                raise RuntimeError(SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)
            return loaded(path, name=name, overwrite=overwrite)

        self.fake_session.init_snapshot = init_snapshot
        self.patches = [
            mock.patch.object(self.batfish_service, "_session", self.fake_session),
            mock.patch.object(self.batfish_service, "get_node_properties", return_value=[]),
            mock.patch.object(self.batfish_service, "get_layer3_edges", return_value=[]),
            mock.patch.object(self.batfish_service, "get_routes", return_value=[]),
            mock.patch.object(self.batfish_service, "get_interface_properties", return_value=[]),
            mock.patch.object(self.batfish_service, "get_differential_reachability", return_value=[]),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        self.snapshot_service.snapshots_dir = self.original_snapshots_dir
        self.batfish_service.current_snapshot_name, self.batfish_service._initialized = self.original_state
        self.temp_dir.cleanup()

    def assert_load_failure(self, response, snapshot, role=None):
        self.assertEqual(response.status_code, 422, response.get_data(as_text=True)[:300])
        payload = response.get_json()
        body = response.get_data(as_text=True)
        for marker in LOAD_FAILURE_MARKERS:
            self.assertNotIn(marker, body)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "snapshot_load_failed")
        label = f"{role} snapshot" if role else "snapshot"
        self.assertEqual(
            payload["message"],
            f"Batfish could not load {label} '{snapshot}': No valid configurations found in snapshot",
        )
        expected_details = {"snapshot": snapshot, "reason": "No valid configurations found in snapshot"}
        if role:
            expected_details["role"] = role
        self.assertEqual(payload["details"], expected_details)
        self.assertTrue(payload["hints"])
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-active")
        self.assertEqual(self.fake_session.snapshot, "fx-active")
        return payload

    def test_interfaces_of_a_snapshot_batfish_rejects_are_a_short_422(self):
        response = self.client.get("/api/snapshots/fx-empty/interfaces")

        self.assert_load_failure(response, "fx-empty")

    def test_comparison_names_the_base_snapshot_batfish_rejects(self):
        response = self.client.post(
            "/api/snapshots/compare",
            json={"base_snapshot": "fx-empty", "comparison_snapshot": "fx-full"},
        )

        self.assert_load_failure(response, "fx-empty", role="base")

    def test_comparison_names_the_comparison_snapshot_batfish_rejects(self):
        response = self.client.post(
            "/api/snapshots/compare",
            json={"base_snapshot": "fx-full", "comparison_snapshot": "fx-empty"},
        )

        self.assert_load_failure(response, "fx-empty", role="comparison")
        self.assertEqual(self.fake_session.loaded, [("fx-full", "fx-full", True)])

    def test_comparison_of_loadable_snapshots_still_succeeds(self):
        response = self.client.post(
            "/api/snapshots/compare",
            json={"base_snapshot": "fx-full", "comparison_snapshot": "fx-active"},
        )

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()["data"]["comparison_snapshot"], "fx-active")


class DifferentialReachabilityRouteTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshot_service = app_module.snapshot_service
        self.original_snapshots_dir = self.snapshot_service.snapshots_dir
        self.snapshot_service.snapshots_dir = Path(self.temp_dir.name)
        self.batfish_service = app_module.batfish_service
        self.original_state = (self.batfish_service.current_snapshot_name, self.batfish_service._initialized)
        self.batfish_service.current_snapshot_name = "fx-active"
        self.batfish_service._initialized = True
        self.client = app_module.app.test_client()

        for name in ("fx-empty", "fx-full", "fx-active"):
            self.snapshot_service.create_snapshot(name)
        self.fake_session = _FakeBatfishSession(snapshot="fx-active")
        loaded = self.fake_session.init_snapshot

        def init_snapshot(path, name=None, overwrite=False):
            if name == "fx-empty":
                self.fake_session.snapshot = name
                raise RuntimeError(SANITIZED_EMPTY_SNAPSHOT_LOAD_FAILURE)
            return loaded(path, name=name, overwrite=overwrite)

        self.fake_session.init_snapshot = init_snapshot
        self.fake_session.q = mock.MagicMock()
        self.answer = self.fake_session.q.differentialReachability.return_value.answer
        self.answer.return_value.frame.return_value = mock.MagicMock(empty=True)
        self.patch = mock.patch.object(self.batfish_service, "_session", self.fake_session)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.snapshot_service.snapshots_dir = self.original_snapshots_dir
        self.batfish_service.current_snapshot_name, self.batfish_service._initialized = self.original_state
        self.temp_dir.cleanup()

    def post(self, reference_snapshot, snapshot=None):
        body = {"reference_snapshot": reference_snapshot}
        if snapshot is not None:
            body["snapshot"] = snapshot
        return self.client.post("/api/advanced/differential-reachability", json=body)

    def assert_active_state_unchanged(self):
        self.assertEqual(self.batfish_service.current_snapshot_name, "fx-active")
        self.assertEqual(self.fake_session.snapshot, "fx-active")

    def test_a_reference_snapshot_batfish_rejects_is_a_short_422(self):
        response = self.post("fx-empty")

        self.assertEqual(response.status_code, 422, response.get_data(as_text=True)[:300])
        body = response.get_data(as_text=True)
        for marker in LOAD_FAILURE_MARKERS:
            self.assertNotIn(marker, body)
        payload = response.get_json()
        self.assertEqual(payload["code"], "snapshot_load_failed")
        self.assertEqual(
            payload["message"],
            "Batfish could not load reference snapshot 'fx-empty': No valid configurations found in snapshot",
        )
        self.assertEqual(payload["details"], {
            "snapshot": "fx-empty",
            "role": "reference",
            "reason": "No valid configurations found in snapshot",
        })
        self.answer.assert_not_called()
        self.assert_active_state_unchanged()

    def test_a_failed_query_is_a_400_without_the_batfish_work_log(self):
        self.answer.side_effect = RuntimeError(SANITIZED_NO_COMMON_START_LOCATION)

        response = self.post("fx-full")

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        body = response.get_data(as_text=True)
        for marker in LOAD_FAILURE_MARKERS:
            self.assertNotIn(marker, body)
        payload = response.get_json()
        self.assertEqual(payload["code"], "query_error")
        self.assertEqual(
            payload["message"],
            "Batfish work failed: no matching startLocation is present and active in both snapshots",
        )
        self.assertEqual(payload["details"], {"query": "differentialReachability"})
        self.assertEqual(self.fake_session.loaded, [("fx-full", "fx-full", True)])
        self.assert_active_state_unchanged()

    def test_the_reference_snapshot_is_loaded_unless_it_is_active(self):
        for reference, expected_loads in (("fx-full", [("fx-full", "fx-full", True)]), ("fx-active", [])):
            with self.subTest(reference=reference):
                self.fake_session.loaded = []
                self.answer.reset_mock()

                response = self.post(reference)

                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()["data"], [])
                self.assertEqual(self.fake_session.loaded, expected_loads)
                self.answer.assert_called_once_with(reference_snapshot=reference)
                self.assert_active_state_unchanged()

    def test_an_unknown_reference_snapshot_is_not_found(self):
        response = self.post("fx-missing")

        self.assertEqual(response.status_code, 404, response.get_data(as_text=True)[:300])
        self.answer.assert_not_called()
        self.assert_active_state_unchanged()

    def test_the_candidate_snapshot_is_loaded_unless_it_is_active(self):
        cases = (
            ("fx-active", "fx-full", [("fx-full", "fx-full", True)]),
            ("fx-full", "fx-active", [("fx-full", "fx-full", True)]),
            ("fx-full", "fx-full", [("fx-full", "fx-full", True)]),
        )
        for reference, snapshot, expected_loads in cases:
            with self.subTest(reference=reference, snapshot=snapshot):
                self.fake_session.loaded = []
                self.answer.reset_mock()

                response = self.post(reference, snapshot)

                self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()["data"], [])
                self.assertEqual(self.fake_session.loaded, expected_loads)
                self.answer.assert_called_once_with(reference_snapshot=reference, snapshot=snapshot)
                self.assert_active_state_unchanged()

    def test_a_candidate_snapshot_batfish_rejects_is_a_short_422_naming_its_role(self):
        response = self.post("fx-full", "fx-empty")

        self.assertEqual(response.status_code, 422, response.get_data(as_text=True)[:300])
        body = response.get_data(as_text=True)
        for marker in LOAD_FAILURE_MARKERS:
            self.assertNotIn(marker, body)
        payload = response.get_json()
        self.assertEqual(payload["code"], "snapshot_load_failed")
        self.assertEqual(
            payload["message"],
            "Batfish could not load snapshot 'fx-empty': No valid configurations found in snapshot",
        )
        self.assertEqual(payload["details"], {
            "snapshot": "fx-empty",
            "role": "snapshot",
            "reason": "No valid configurations found in snapshot",
        })
        self.assertEqual(self.fake_session.loaded, [("fx-full", "fx-full", True)])
        self.answer.assert_not_called()
        self.assert_active_state_unchanged()

    def test_a_rejected_reference_is_named_as_the_reference_when_a_candidate_is_given(self):
        response = self.post("fx-empty", "fx-full")

        self.assertEqual(response.status_code, 422, response.get_data(as_text=True)[:300])
        self.assertEqual(response.get_json()["details"]["role"], "reference")
        self.answer.assert_not_called()
        self.assert_active_state_unchanged()

    def test_an_unknown_candidate_snapshot_is_not_found(self):
        response = self.post("fx-full", "fx-missing")

        self.assertEqual(response.status_code, 404, response.get_data(as_text=True)[:300])
        self.assertEqual(self.fake_session.loaded, [])
        self.answer.assert_not_called()
        self.assert_active_state_unchanged()


if __name__ == "__main__":
    unittest.main()
