import unittest
from unittest import mock

from pybatfish.datamodel.route import BgpRoute

import app as app_module

ROUTE = {
    "network": "192.0.2.0/24",
    "originatorIp": "0.0.0.0",
    "originType": "igp",
    "protocol": "bgp",
    "asPath": [],
    "communities": [],
    "localPreference": 100,
    "metric": 0,
    "nextHopIp": "198.51.100.1",
    "tag": 0,
    "weight": 0,
}


class TestRoutePoliciesRequestTest(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.batfish_service = app_module.batfish_service

    def post(self, body):
        with mock.patch.object(self.batfish_service, "test_route_policies", return_value=[]) as test_policies:
            response = self.client.post("/api/advanced/test-route-policies", json=body)
        return response, test_policies

    def assert_validation_error(self, response, field):
        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        payload = response.get_json()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "validation_error")
        self.assertEqual(payload["details"], {"field": field})
        return payload

    def test_direction_is_lowercased_and_a_single_route_becomes_a_bgp_route_list(self):
        response, test_policies = self.post({"direction": "IN", "inputRoutes": ROUTE, "policies": "P1"})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        kwargs = test_policies.call_args.kwargs
        self.assertEqual(kwargs["direction"], "in")
        self.assertEqual(kwargs["policies"], "P1")
        self.assertEqual(len(kwargs["inputRoutes"]), 1)
        route = kwargs["inputRoutes"][0]
        self.assertIsInstance(route, BgpRoute)
        self.assertEqual(route.network, "192.0.2.0/24")
        self.assertEqual(route.originatorIp, "0.0.0.0")
        self.assertEqual(route.localPreference, 100)
        self.assertEqual(route.nextHopIp, "198.51.100.1")

    def test_route_lists_are_converted_element_by_element(self):
        second = {**ROUTE, "network": "198.51.100.0/24", "srcProtocol": "ospf"}
        response, test_policies = self.post({"direction": " Out ", "inputRoutes": [ROUTE, second]})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        kwargs = test_policies.call_args.kwargs
        self.assertEqual(kwargs["direction"], "out")
        self.assertEqual([route.network for route in kwargs["inputRoutes"]], ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertTrue(all(isinstance(route, BgpRoute) for route in kwargs["inputRoutes"]))
        self.assertEqual(kwargs["inputRoutes"][1].sourceProtocol, "ospf")

    def test_minimal_route_uses_bgp_route_defaults(self):
        minimal = {"network": "192.0.2.0/24", "originatorIp": "0.0.0.0", "originType": "igp", "protocol": "bgp"}
        response, test_policies = self.post({"direction": "in", "inputRoutes": [minimal]})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        route = test_policies.call_args.kwargs["inputRoutes"][0]
        self.assertEqual((route.asPath, route.communities, route.localPreference), ([], [], 0))

    def test_missing_required_route_fields_are_a_structured_400(self):
        route = {key: value for key, value in ROUTE.items() if key not in ("originatorIp", "originType")}
        response, test_policies = self.post({"direction": "in", "inputRoutes": [route]})

        payload = self.assert_validation_error(response, "inputRoutes[0].originatorIp")
        self.assertIn("originatorIp", payload["message"])
        self.assertIn("originType", payload["message"])
        test_policies.assert_not_called()

    def test_invalid_route_shapes_are_structured_400s(self):
        cases = [
            ([], "inputRoutes"),
            ("192.0.2.0/24", "inputRoutes"),
            (["192.0.2.0/24"], "inputRoutes[0]"),
            ([{**ROUTE, "unknownField": 1}], "inputRoutes[0].unknownField"),
            ([{**ROUTE, "localPreference": "100"}], "inputRoutes[0].localPreference"),
            ([{**ROUTE, "localPreference": True}], "inputRoutes[0].localPreference"),
            ([{**ROUTE, "asPath": "65000"}], "inputRoutes[0].asPath"),
            ([{**ROUTE, "network": 1}], "inputRoutes[0].network"),
        ]
        for input_routes, field in cases:
            with self.subTest(field=field, input_routes=input_routes):
                response, test_policies = self.post({"direction": "in", "inputRoutes": input_routes})
                self.assert_validation_error(response, field)
                test_policies.assert_not_called()

    def test_invalid_route_addresses_are_structured_400s_before_batfish(self):
        cases = [
            ([{**ROUTE, "network": "bad"}], "inputRoutes[0].network"),
            ([{**ROUTE, "network": "192.0.2.0"}], "inputRoutes[0].network"),
            ([{**ROUTE, "network": "192.0.2.0/33"}], "inputRoutes[0].network"),
            ([{**ROUTE, "network": "192.0.2.0/255.255.255.0"}], "inputRoutes[0].network"),
            ([{**ROUTE, "network": "2001:db8::/32"}], "inputRoutes[0].network"),
            ([{**ROUTE, "originatorIp": "bad"}], "inputRoutes[0].originatorIp"),
            ([{**ROUTE, "originatorIp": "192.0.2.0/24"}], "inputRoutes[0].originatorIp"),
            ([{**ROUTE, "nextHopIp": "999.0.0.1"}], "inputRoutes[0].nextHopIp"),
            ([{**ROUTE, "nextHopIp": "2001:db8::1"}], "inputRoutes[0].nextHopIp"),
            ([ROUTE, {**ROUTE, "nextHopIp": "bad"}], "inputRoutes[1].nextHopIp"),
        ]
        for input_routes, field in cases:
            with self.subTest(field=field, input_routes=input_routes):
                response, test_policies = self.post({"direction": "in", "inputRoutes": input_routes})
                payload = self.assert_validation_error(response, field)
                self.assertIn(field, payload["message"])
                test_policies.assert_not_called()

    def test_prefixes_with_host_bits_are_passed_through(self):
        response, test_policies = self.post({"direction": "in", "inputRoutes": [{**ROUTE, "network": "192.0.2.1/24"}]})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertEqual(test_policies.call_args.kwargs["inputRoutes"][0].network, "192.0.2.1/24")

    def test_invalid_direction_is_a_structured_400(self):
        for direction in ("sideways", 1, ["in"]):
            with self.subTest(direction=direction):
                response, test_policies = self.post({"direction": direction, "inputRoutes": ROUTE})
                self.assert_validation_error(response, "direction")
                test_policies.assert_not_called()

    def test_missing_direction_keeps_the_existing_400(self):
        response, test_policies = self.post({"inputRoutes": [ROUTE]})

        self.assertEqual(response.status_code, 400)
        self.assertIn("direction", response.get_json()["message"])
        test_policies.assert_not_called()


class SearchRoutePoliciesPathOptionTest(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.batfish_service = app_module.batfish_service

    def post(self, body):
        with mock.patch.object(self.batfish_service, "get_search_route_policies", return_value=[]) as search:
            response = self.client.post("/api/advanced/search-route-policies", json=body)
        return response, search

    def test_per_path_true_with_path_option_is_a_structured_400(self):
        response, search = self.post({"nodes": "r1", "perPath": True, "pathOption": "NON_OVERLAP"})

        self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
        payload = response.get_json()
        self.assertEqual(payload["code"], "validation_error")
        self.assertEqual(payload["details"], {"field": "pathOption"})
        self.assertIn("perPath", payload["message"])
        search.assert_not_called()

    def test_per_path_false_is_dropped_when_path_option_is_set(self):
        response, search = self.post({"nodes": "r1", "perPath": False, "pathOption": "non_overlap"})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertIsNone(search.call_args.kwargs["perPath"])
        self.assertEqual(search.call_args.kwargs["pathOption"], "NON_OVERLAP")

    def test_per_path_alone_is_passed_through(self):
        response, search = self.post({"nodes": "r1", "perPath": True})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertTrue(search.call_args.kwargs["perPath"])
        self.assertIsNone(search.call_args.kwargs["pathOption"])

    def test_blank_path_option_is_treated_as_unset(self):
        response, search = self.post({"nodes": "r1", "perPath": True, "pathOption": "  "})

        self.assertEqual(response.status_code, 200, response.get_data(as_text=True)[:300])
        self.assertTrue(search.call_args.kwargs["perPath"])
        self.assertIsNone(search.call_args.kwargs["pathOption"])

    def test_unknown_path_option_is_a_structured_400(self):
        for path_option in ("EVERYTHING", 3):
            with self.subTest(path_option=path_option):
                response, search = self.post({"nodes": "r1", "pathOption": path_option})

                self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()["details"], {"field": "pathOption"})
                search.assert_not_called()


if __name__ == "__main__":
    unittest.main()
