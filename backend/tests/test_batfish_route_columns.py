import inspect
import unittest

import numpy as np
import pandas as pd

from services.batfish_service import BatfishService


BGP_RIB_COLUMNS = [
    "Node",
    "VRF",
    "Network",
    "Status",
    "Next_Hop",
    "Next_Hop_IP",
    "Next_Hop_Interface",
    "Protocol",
    "AS_Path",
    "Metric",
    "Local_Pref",
    "Communities",
    "Origin_Protocol",
    "Origin_Type",
    "Originator_Id",
    "Received_From_IP",
    "Received_Path_Id",
    "Cluster_List",
    "Tunnel_Encapsulation_Attribute",
    "Weight",
    "Tag",
]

LPM_ROUTES_COLUMNS = ["Node", "VRF", "Ip", "Network", "Num_Routes"]


class _LpmQuestionApi:
    def __init__(self):
        self.parameters = None

    def lpmRoutes(self, **parameters):
        self.parameters = parameters
        return object()


class _LpmSession:
    def __init__(self):
        self.q = _LpmQuestionApi()


class BatfishRouteColumnContractTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()
        self.service._initialized = True

    @staticmethod
    def _bgp_frame(local_pref, metric, originator_id):
        row = {column: None for column in BGP_RIB_COLUMNS}
        row.update({
            "Node": "edge-rtr1",
            "VRF": "default",
            "Network": "203.0.113.0/24",
            "Protocol": "bgp",
            "AS_Path": [],
            "Metric": metric,
            "Local_Pref": local_pref,
            "Communities": [],
            "Originator_Id": originator_id,
            "Cluster_List": [],
        })
        return pd.DataFrame([row], columns=BGP_RIB_COLUMNS, dtype=object)

    def _get_bgp_rib(self, frame):
        self.service._execute_query_factory = lambda *args, **kwargs: frame
        return self.service.get_bgp_rib()

    def _get_lpm_routes(self, frame, request_ip="192.0.2.10"):
        session = _LpmSession()
        self.service._session = session
        self.service._execute_query = lambda *args, **kwargs: frame
        return self.service.get_lpm_routes(ip=request_ip), session.q.parameters

    def test_bgp_preserves_zero_and_converts_numpy_ints(self):
        frame = self._bgp_frame(np.int64(0), np.int64(0), "10.255.0.4")
        self.assertIsInstance(frame.iloc[0]["Local_Pref"], np.integer)

        result = self._get_bgp_rib(frame)[0]

        self.assertEqual(result["local_preference"], 0)
        self.assertEqual(result["med"], 0)
        self.assertIs(type(result["local_preference"]), int)
        self.assertIs(type(result["med"]), int)
        self.assertEqual(result["originator_id"], "10.255.0.4")

    def test_bgp_reads_non_default_values(self):
        result = self._get_bgp_rib(
            self._bgp_frame(np.int64(200), np.int64(15), "10.255.0.9")
        )[0]

        self.assertEqual(result["local_preference"], 200)
        self.assertEqual(result["med"], 15)
        self.assertEqual(result["originator_id"], "10.255.0.9")

    def test_bgp_normalizes_missing_values_and_keeps_originator_compatibility(self):
        result = self._get_bgp_rib(self._bgp_frame(np.nan, np.nan, pd.NA))[0]

        self.assertIsNone(result["local_preference"])
        self.assertIsNone(result["med"])
        # The existing public contract uses an empty string for a missing Originator_Id.
        self.assertEqual(result["originator_id"], "")

    def test_lpm_uses_frame_ip_and_route_count_with_legacy_empty_compatibility_fields(self):
        frame = pd.DataFrame([{
            "Node": "core-rtr1",
            "VRF": "default",
            "Ip": "10.0.0.1",
            "Network": "10.0.0.1/32",
            "Num_Routes": np.int64(1),
        }], columns=LPM_ROUTES_COLUMNS, dtype=object)
        self.assertIsInstance(frame.iloc[0]["Num_Routes"], np.integer)

        results, parameters = self._get_lpm_routes(frame)
        result = results[0]

        self.assertEqual(parameters["ip"], "192.0.2.10")
        self.assertEqual(result["ip"], "10.0.0.1")
        self.assertEqual(result["num_routes"], 1)
        self.assertIs(type(result["num_routes"]), int)
        self.assertEqual(result["next_hop"], "")
        self.assertIsNone(result["next_hop_interface"])
        self.assertEqual(result["protocol"], "")

    def test_lpm_normalizes_missing_route_count(self):
        frame = pd.DataFrame([{
            "Node": "core-rtr1",
            "VRF": "default",
            "Ip": "10.0.0.1",
            "Network": "10.0.0.1/32",
            "Num_Routes": np.nan,
        }], columns=LPM_ROUTES_COLUMNS)

        result = self._get_lpm_routes(frame)[0][0]

        self.assertIsNone(result["num_routes"])

    def test_wrong_column_names_are_not_reintroduced(self):
        bgp_source = inspect.getsource(BatfishService.get_bgp_rib)
        lpm_source = inspect.getsource(BatfishService.get_lpm_routes)

        for wrong_name in ('"Local_Preference"', '"MED"', '"Originator_ID"'):
            self.assertNotIn(wrong_name, bgp_source)
        self.assertNotIn('"IP"', lpm_source)


if __name__ == "__main__":
    unittest.main()
