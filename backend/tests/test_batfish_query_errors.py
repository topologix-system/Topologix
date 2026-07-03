import contextlib
import unittest
from pathlib import Path

from services.batfish_service import BatfishQueryError, BatfishService

# Sanitized reproduction of a failed Batfish work item (RFC 5737 style
# placeholders, synthetic ids, no real environment data). Matches the shape
# observed for searchRoutePolicies constraint-regex failures.
SANITIZED_WORK_LOG_FAILURE = (
    "Work terminated abnormally\n"
    'work_item: {"containerName": "example_network", '
    '"id": "00000000-0000-0000-0000-000000000000", '
    '"requestParams": {"answer": "", '
    '"questionname": "__searchRoutePolicies_test", "testrig": "example"}, '
    '"testrigName": "example"}\n'
    "\n"
    "log: Loading configurations for NetworkSnapshot{network=example, snapshot=example}\n"
    "Exception in container:example, testrig:example; "
    "exception:org.batfish.common.QuestionException: Exception answering question\n"
    "\tat org.batfish.datamodel.answers.Answer.append(Answer.java:46)\n"
    "Caused by: org.batfish.common.BatfishException: "
    "Failed to answer question SearchRoutePoliciesQuestion\n"
    "\tat org.batfish.main.Batfish.answer(Batfish.java:544)\n"
    "Caused by: org.batfish.common.BatfishException: "
    "Regex CommunityVar{type=REGEX, regex=^^65000:$$, literalValue=null} "
    "does not match any strings\n"
    "\tat org.batfish.minesweeper.RegexAtomicPredicates."
    "initAtomicPredicates(RegexAtomicPredicates.java:82)\n"
)

# Same failure as observed through the Flask API path, where Batfish embeds
# the stack trace as JSON-encoded strings on one physical line.
SANITIZED_WORK_LOG_FAILURE_JSON_LINE = (
    "Work terminated abnormally "
    'work_item: {"containerName": "example_network"} '
    '["Caused by: org.batfish.common.BatfishException: '
    "Regex CommunityVar{type=REGEX, regex=^^65000:$$, literalValue=null} "
    'does not match any strings","   at org.batfish.minesweeper.'
    'RegexAtomicPredicates.initAtomicPredicates(RegexAtomicPredicates.java:82)",'
    '"   at org.batfish.minesweeper.RegexAtomicPredicates.<init>'
    '(RegexAtomicPredicates.java:61)",""]}],"question":{"class":'
    '"org.batfish.minesweeper.question.searchroutepolicies.SearchRoutePoliciesQuestion"}'
)


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

    def test_work_log_failure_is_reduced_to_root_cause(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError(SANITIZED_WORK_LOG_FAILURE),
            query_params={"nodes": ".*", "policies": "EXPORT"},
        )

        self.assertIn("does not match any strings", error.message)
        self.assertNotIn("work_item", error.message)
        self.assertNotIn("\tat ", error.message)
        self.assertLess(len(error.message), 300)

    def test_single_line_json_work_log_is_reduced_to_root_cause(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError(SANITIZED_WORK_LOG_FAILURE_JSON_LINE),
            query_params={
                "nodes": ".*",
                "inputConstraints": {"communities": ["^65000:$"]},
            },
        )

        self.assertIn("does not match any strings", error.message)
        self.assertNotIn("   at ", error.message)
        self.assertNotIn('"question"', error.message)
        self.assertLess(len(error.message), 300)
        self.assertEqual(error.error_type, "route_policy_constraint_no_match")

    def test_constraint_failure_is_classified_as_constraint_no_match(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError(SANITIZED_WORK_LOG_FAILURE),
            query_params={
                "nodes": ".*",
                "policies": "EXPORT",
                "inputConstraints": {"communities": ["^65000:$"]},
            },
        )

        self.assertEqual(error.error_type, "route_policy_constraint_no_match")
        self.assertEqual(error.status_code, 400)
        self.assertTrue(any("constraint regex" in hint for hint in error.hints))

    def test_work_log_regex_failure_without_constraints_keeps_regex_conversion_code(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError(SANITIZED_WORK_LOG_FAILURE),
            query_params={"nodes": ".*", "policies": "EXPORT"},
        )

        self.assertEqual(error.error_type, "route_policy_regex_conversion_error")

    def test_retry_exhaustion_is_classified_as_coordinator_error(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            RuntimeError(
                "HTTPConnectionPool(host='batfish', port=9996): Max retries exceeded "
                "with url: /v2/networks/example/questions/__searchRoutePolicies_test "
                "(Caused by ResponseError('too many 500 error responses'))"
            ),
            query_params={"inputConstraints": {"asPath": ["x"]}},
        )

        self.assertEqual(error.error_type, "batfish_coordinator_error")
        self.assertEqual(error.status_code, 502)

    def test_gevent_timeout_error_is_classified_as_query_timeout(self):
        error = self.service._build_query_error(
            "searchRoutePolicies",
            TimeoutError("Batfish query 'searchRoutePolicies' timed out after 120 seconds"),
            query_params={"nodes": ".*"},
        )

        self.assertEqual(error.error_type, "query_timeout")
        self.assertEqual(error.status_code, 504)


class RoutePolicyConstraintPreflightTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()

    def assert_constraint_rejected(self, input_constraints, expected_fragment):
        with self.assertRaises(BatfishQueryError) as raised:
            self.service._validate_route_policy_constraints(
                "searchRoutePolicies", input_constraints, None
            )

        error = raised.exception
        self.assertEqual(error.error_type, "route_policy_constraint_invalid")
        self.assertEqual(error.status_code, 400)
        self.assertIn(expected_fragment, error.message)

    def test_as_path_regex_with_letters_is_rejected_before_batfish(self):
        self.assert_constraint_rejected({"asPath": ["x"]}, "asPath")
        self.assert_constraint_rejected({"asPath": ["abc"]}, "asPath")

    def test_broken_regex_constraints_are_rejected(self):
        self.assert_constraint_rejected({"asPath": ["("]}, "regular expression")
        self.assert_constraint_rejected({"communities": ["("]}, "regular expression")

    def test_out_of_range_community_literals_are_rejected(self):
        self.assert_constraint_rejected({"communities": ["999999999:1"]}, "0-65535")
        self.assert_constraint_rejected({"communities": ["4294967296:1:1"]}, "0-4294967295")

    def test_non_string_and_empty_constraint_values_are_rejected(self):
        self.assert_constraint_rejected({"asPath": [123]}, "non-empty")
        self.assert_constraint_rejected({"communities": [" "]}, "non-empty")

    def test_valid_constraints_pass_preflight(self):
        self.service._validate_route_policy_constraints(
            "searchRoutePolicies",
            {
                "communities": ["65000:1", "^65000:.*$", "4200000000:1:1"],
                "asPath": ["8075", "^$", r"\d+", ".*8075.*"],
            },
            {"communities": "65000:100", "asPath": "^8075$"},
        )

    def test_search_route_policies_rejects_invalid_constraints_before_session_use(self):
        self.service._initialized = True

        with self.assertRaises(BatfishQueryError) as raised:
            self.service.get_search_route_policies(
                inputConstraints={"asPath": ["x"]},
            )

        self.assertEqual(raised.exception.error_type, "route_policy_constraint_invalid")
        self.assertIsNone(self.service._session)


class BatfishVersionDiagnosticsTest(unittest.TestCase):
    def test_version_info_is_non_blocking_before_any_session_use(self):
        service = BatfishService()

        info = service.get_batfish_version_info()

        self.assertIsNone(service._session)
        self.assertIsNone(info["batfish_version"])
        self.assertIsInstance(info["pybatfish_version"], str)

    def test_version_info_returns_cached_server_version(self):
        service = BatfishService()
        service._batfish_version = "2025.07.07.2423"

        info = service.get_batfish_version_info()

        self.assertEqual(info["batfish_version"], "2025.07.07.2423")


class PybatfishHttpHardeningTest(unittest.TestCase):
    def test_pybatfish_retry_policy_is_capped(self):
        from pybatfish.client import restv2helper

        for http_session in (
            restv2helper._requests_session,
            restv2helper._requests_session_fail_fast,
        ):
            adapter = http_session.get_adapter("http://batfish:9996")
            self.assertEqual(adapter.max_retries.total, 3)
            self.assertLessEqual(adapter.max_retries.backoff_factor, 0.5)

    def test_query_timeout_context_matches_runtime_environment(self):
        context = BatfishService._query_timeout_context("searchRoutePolicies")

        try:
            from gevent import monkey as gevent_monkey
            gevent_patched = gevent_monkey.is_module_patched("socket")
        except ImportError:
            gevent_patched = False

        if gevent_patched:
            import gevent
            self.assertIsInstance(context, gevent.Timeout)
            context.close()
        else:
            self.assertIsInstance(context, contextlib.nullcontext)


if __name__ == "__main__":
    unittest.main()
