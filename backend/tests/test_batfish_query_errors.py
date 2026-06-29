import unittest
from pathlib import Path

from services.batfish_service import BatfishQueryError, BatfishService


class BatfishQueryErrorClassificationTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()

    def test_route_policy_does_not_match_is_not_reported_as_generic_node_specifier(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError("Specifier 65000 does not match any strings"),
            query_params={"nodes": ".*", "policies": "EXPORT"},
        )

        self.assertEqual(error.error_type, "route_policy_specifier_no_match")
        self.assertEqual(error.status_code, 400)
        self.assertIn("parameters", error.details)
        self.assertTrue(any("AS-path" in hint for hint in error.hints))

    def test_route_policy_regex_failure_keeps_regex_specific_code(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError("AS-path regex .*8075.* does not match any strings"),
            query_params={"nodes": ".*"},
        )

        self.assertEqual(error.error_type, "route_policy_regex_conversion_error")
        self.assertTrue(any("AS-path regex" in hint for hint in error.hints))

    def test_node_specifier_preflight_keeps_generic_specifier_code(self):
        error = self.service._build_query_error(
            "searchRoutePolicies.resolveNodeSpecifier",
            RuntimeError("Specifier 65000 does not match any strings"),
            query_params={"nodes": "65000"},
        )

        self.assertEqual(error.error_type, "specifier_no_match")

    def test_node_specifier_parse_error_is_specifier_failure(self):
        error = self.service._build_query_error(
            "searchRoutePolicies.resolveNodeSpecifier",
            RuntimeError("Error parsing '65000' as nodeSpecifier after index 0. Valid continuations are NODE_SET_OP."),
            query_params={"nodes": "65000"},
        )

        self.assertEqual(error.error_type, "specifier_no_match")

    def test_route_policy_preflight_stops_asn_like_node_input_before_policy_query(self):
        def no_nodes(*args, **kwargs):
            return None

        self.service._execute_query_factory = no_nodes

        with self.assertRaises(BatfishQueryError) as raised:
            self.service._validate_route_policy_node_specifier("65000", "searchRoutePolicies")

        error = raised.exception
        self.assertEqual(error.error_type, "node_specifier_no_match")
        self.assertEqual(error.details["parameters"]["nodes"], "65000")
        self.assertTrue(any("ASN" in hint for hint in error.hints))

    def test_route_policy_preflight_converts_node_specifier_parse_error(self):
        preflight_error = self.service._build_query_error(
            "searchRoutePolicies.resolveNodeSpecifier",
            RuntimeError("Error parsing '65000' as nodeSpecifier after index 0. Valid continuations are NODE_SET_OP."),
            query_params={"nodes": "65000"},
        )

        def invalid_node_specifier(*args, **kwargs):
            raise preflight_error

        self.service._execute_query_factory = invalid_node_specifier

        with self.assertRaises(BatfishQueryError) as raised:
            self.service._validate_route_policy_node_specifier("65000", "searchRoutePolicies")

        error = raised.exception
        self.assertEqual(error.error_type, "node_specifier_no_match")
        self.assertEqual(error.details["parameters"]["nodes"], "65000")

    def test_aggregate_query_error_keeps_fallback_and_metadata(self):
        data = {}
        query_errors = []
        error = BatfishQueryError(
            query_name="bgpEdges",
            message="Timed out while running token='secret-value'",
            error_type="query_timeout",
            details={"query": "bgpEdges", "token": "secret-value"},
            hints=["Check Batfish service health if the query repeatedly times out."],
            status_code=504,
        )

        self.service._set_aggregate_query_result(
            data,
            query_errors,
            "bgp_edges",
            lambda: (_ for _ in ()).throw(error),
            [],
        )

        self.assertEqual(data["bgp_edges"], [])
        self.assertEqual(len(query_errors), 1)
        self.assertEqual(query_errors[0]["data_key"], "bgp_edges")
        self.assertEqual(query_errors[0]["query"], "bgpEdges")
        self.assertEqual(query_errors[0]["code"], "query_timeout")
        self.assertEqual(query_errors[0]["status_code"], 504)
        self.assertEqual(query_errors[0]["details"]["token"], "[redacted]")
        self.assertNotIn("secret-value", str(query_errors[0]))

    def test_aggregate_query_success_does_not_add_error_metadata(self):
        data = {}
        query_errors = []

        self.service._set_aggregate_query_result(
            data,
            query_errors,
            "bgp_edges",
            lambda: [{"node": "edge1"}],
            [],
        )

        self.assertEqual(data["bgp_edges"], [{"node": "edge1"}])
        self.assertEqual(query_errors, [])

    def test_sanitized_issue7973_fixture_is_used_by_regression_suite(self):
        fixture = Path(__file__).parent / "fixtures" / "issue7973_route_policy" / "configs" / "junos-edge1.conf"
        content = fixture.read_text(encoding="utf-8")

        self.assertIn('as-path Microsoft ".*8075.*"', content)
        self.assertIn("198.51.100.1/31", content)
        self.assertIn("192.0.2.1/32", content)
        self.assertIn("autonomous-system 65000", content)
        self.assertNotRegex(content.lower(), r"password|secret|token|private-key")


if __name__ == "__main__":
    unittest.main()
