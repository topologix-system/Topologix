import unittest
from unittest import mock

import app as app_module
from services.batfish_service import BatfishQueryError, BatfishService


class _QuestionApi:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def question(**parameters):
            self.calls.append((name, parameters))
            return name
        return question


class _Session:
    def __init__(self):
        self.q = _QuestionApi()


class HeaderConstraintNormalizationTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()

    def normalize(self, headers):
        return self.service._normalize_header_constraints("traceroute", headers)

    def test_integer_lists_become_comma_separated_strings(self):
        headers = self.normalize({
            "dstIps": "192.0.2.1",
            "icmpTypes": [0, 8],
            "icmpCodes": [0],
            "dscps": [0, 46],
            "ecns": (0, 1),
            "packetLengths": [64, "100-1500"],
            "fragmentOffsets": 0,
        })

        self.assertEqual(headers, {
            "dstIps": "192.0.2.1",
            "icmpTypes": "0,8",
            "icmpCodes": "0",
            "dscps": "0,46",
            "ecns": "0,1",
            "packetLengths": "64,100-1500",
            "fragmentOffsets": "0",
        })

    def test_strings_and_ranges_pass_through(self):
        original = {"icmpTypes": "0,8", "dscps": "0-8", "srcPorts": "1024-65535", "dstPorts": "22,443"}

        self.assertEqual(self.normalize(original), original)

    def test_string_items_are_trimmed_and_blank_strings_are_dropped(self):
        headers = self.normalize({
            "dstPorts": " 22, 443 ,",
            "srcPorts": "1024 - 2048",
            "packetLengths": "",
            "fragmentOffsets": "  ",
            "icmpTypes": ["0,8", 3],
            "ecns": "１",
        })

        self.assertEqual(headers, {
            "dstPorts": "22,443",
            "srcPorts": "1024-2048",
            "icmpTypes": "0,8,3",
            "ecns": "1",
        })

    def test_batfish_exclusion_items_are_kept(self):
        self.assertEqual(self.normalize({"dstPorts": "!22,1-1024"}), {"dstPorts": "!22,1-1024"})

    def test_each_field_accepts_its_full_batfish_range(self):
        cases = {
            "srcPorts": 65535,
            "dstPorts": 65535,
            "icmpTypes": 255,
            "icmpCodes": 255,
            "dscps": 63,
            "ecns": 3,
            "packetLengths": 65535,
            "fragmentOffsets": 8191,
        }
        for field, maximum in cases.items():
            with self.subTest(field=field):
                self.assertEqual(self.normalize({field: f"0-{maximum}"}), {field: f"0-{maximum}"})
                self.assertEqual(self.normalize({field: [maximum]}), {field: str(maximum)})

    def test_values_above_the_field_range_are_rejected(self):
        cases = {
            "srcPorts": 65535,
            "dstPorts": 65535,
            "icmpTypes": 255,
            "icmpCodes": 255,
            "dscps": 63,
            "ecns": 3,
            "packetLengths": 65535,
            "fragmentOffsets": 8191,
        }
        for field, maximum in cases.items():
            for value in (maximum + 1, [maximum + 1], f"{maximum + 1}", f"0-{maximum + 1}", f"1,!{maximum + 1}"):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(BatfishQueryError) as raised:
                        self.normalize({field: value})
                    error = raised.exception
                    self.assertEqual(error.status_code, 400)
                    self.assertEqual(error.error_type, "header_constraint_invalid")
                    self.assertIn(f"headers.{field}", error.message)
                    self.assertIn(f"outside the allowed range 0-{maximum}", error.message)
                    self.assertEqual(error.details["allowed_range"], f"0-{maximum}")

    def test_malformed_string_items_are_rejected(self):
        for value in ("abc", "1-", "-1", "1-2-3", "8a", "0x10", "1.5", "!", "1;2", ["22", "ssh"]):
            with self.subTest(value=value):
                with self.assertRaises(BatfishQueryError) as raised:
                    self.normalize({"icmpTypes": value})
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(raised.exception.error_type, "header_constraint_invalid")
                self.assertIn("headers.icmpTypes", raised.exception.message)
                self.assertIn("is not a value or range", raised.exception.message)

    def test_values_longer_than_the_int_conversion_limit_are_outside_the_range(self):
        digits = "9" * 5000
        for value in (digits, f"1-{digits}", f"{digits}-1", f"!{digits}", ["22", digits]):
            with self.subTest(value=value if isinstance(value, list) else value[:12]):
                with self.assertRaises(BatfishQueryError) as raised:
                    self.normalize({"dstPorts": value})

                error = raised.exception
                self.assertEqual(error.status_code, 400)
                self.assertEqual(error.error_type, "header_constraint_invalid")
                self.assertIn("headers.dstPorts", error.message)
                self.assertIn("outside the allowed range 0-65535", error.message)
                self.assertLess(len(error.message), 200)

    def test_zero_padded_values_within_the_digit_limit_are_kept(self):
        self.assertEqual(self.normalize({"dstPorts": "0000000022"}), {"dstPorts": "22"})

    def test_leading_zeros_do_not_count_toward_the_digit_limit(self):
        cases = (
            ("icmpTypes", "00000000008", "8"),
            ("icmpTypes", "!00000000008", "!8"),
            ("dstPorts", "00000000001-000000000000022", "1-22"),
            ("dstPorts", "0" * 5000 + "443", "443"),
            ("dscps", "000000000000", "0"),
            ("ecns", ["00000000000", "000000000003"], "0,3"),
        )
        for field, value, expected in cases:
            with self.subTest(field=field, value=value if isinstance(value, list) else value[:30]):
                self.assertEqual(self.normalize({field: value}), {field: expected})

    def test_zero_padded_values_with_too_many_significant_digits_are_still_outside_the_range(self):
        for value in ("0" + "9" * 11, "1-00" + "1" * 11):
            with self.subTest(value=value):
                with self.assertRaises(BatfishQueryError) as raised:
                    self.normalize({"dstPorts": value})
                self.assertEqual(raised.exception.error_type, "header_constraint_invalid")
                self.assertIn("outside the allowed range 0-65535", raised.exception.message)

    def test_exclusions_that_leave_no_value_are_rejected(self):
        cases = (
            ("icmpTypes", "!0-255", 255),
            ("icmpTypes", "!0-100,!101-255", 255),
            ("icmpTypes", ["!128-255", "!0-127"], 255),
            ("icmpCodes", "!0-200,!100-255", 255),
            ("ecns", "!0,!1,!2,!3", 3),
            ("dscps", "!0-63", 63),
            ("srcPorts", "!0-65535", 65535),
            ("dstPorts", "22,!22", 65535),
            ("dstPorts", "1-10,!1-5,!6-10", 65535),
            ("packetLengths", "64-1500,!0-65535", 65535),
            ("fragmentOffsets", "!0-8191", 8191),
        )
        for field, value, maximum in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(BatfishQueryError) as raised:
                    self.normalize({field: value})

                error = raised.exception
                self.assertEqual(error.status_code, 400)
                self.assertEqual(error.error_type, "header_constraint_invalid")
                self.assertEqual(
                    error.message,
                    f"Invalid headers.{field}: no value within the allowed range 0-{maximum} remains after the exclusions",
                )
                self.assertEqual(error.details["allowed_range"], f"0-{maximum}")

    def test_exclusions_that_leave_a_value_are_kept(self):
        cases = {
            "icmpTypes": "!0-254",
            "icmpCodes": "!1-255",
            "ecns": "!0,!1,!3",
            "dscps": "!0-31,!33-63",
            "dstPorts": "1-10,!1-5,!7-10",
            "srcPorts": "!22",
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                self.assertEqual(self.normalize({field: value}), {field: value})

    def test_reversed_ranges_are_rejected(self):
        with self.assertRaises(BatfishQueryError) as raised:
            self.normalize({"dstPorts": "443-22"})

        self.assertIn("starts above its end", raised.exception.message)

    def test_list_strings_are_trimmed_and_blank_items_or_empty_lists_are_dropped(self):
        headers = self.normalize({"dstPorts": [" 22 ", "", 443], "icmpCodes": [], "ecns": ["  "]})

        self.assertEqual(headers, {"dstPorts": "22,443"})

    def test_non_integer_fields_and_non_dict_headers_are_untouched(self):
        headers = {"ipProtocols": ["TCP", "ICMP"], "applications": ["ssh"], "srcIps": "192.0.2.1"}

        self.assertEqual(self.normalize(headers), headers)
        self.assertIsNone(self.normalize(None))
        self.assertEqual(self.normalize("not-a-dict"), "not-a-dict")

    def test_the_caller_headers_are_not_mutated(self):
        headers = {"icmpTypes": [0, 8]}

        self.normalize(headers)

        self.assertEqual(headers, {"icmpTypes": [0, 8]})

    def test_invalid_values_are_rejected_before_batfish(self):
        for value in (True, 1.5, -1, {"a": 1}, [0, True], [0, 1.5], [-1], [[0]]):
            with self.subTest(value=value):
                with self.assertRaises(BatfishQueryError) as raised:
                    self.normalize({"icmpTypes": value})
                self.assertEqual(raised.exception.status_code, 400)
                self.assertEqual(raised.exception.error_type, "header_constraint_invalid")
                self.assertIn("headers.icmpTypes", raised.exception.message)


class TracerouteHeaderPassingTest(unittest.TestCase):
    def setUp(self):
        self.service = BatfishService()
        self.service._initialized = True
        self.service._session = _Session()
        self.service._execute_query = lambda query, query_name, **kwargs: None

    def test_traceroute_sends_normalized_headers(self):
        self.service.traceroute(headers={"dstIps": "192.0.2.1", "icmpTypes": [0, 8]}, startLocation="r1")

        name, parameters = self.service._session.q.calls[-1]
        self.assertEqual(name, "traceroute")
        self.assertEqual(parameters["headers"], {"dstIps": "192.0.2.1", "icmpTypes": "0,8"})

    def test_bidirectional_traceroute_sends_normalized_headers(self):
        self.service.bidirectional_traceroute(headers={"dstIps": "192.0.2.1", "dscps": [0, 46], "ecns": "0-1"})

        name, parameters = self.service._session.q.calls[-1]
        self.assertEqual(name, "bidirectionalTraceroute")
        self.assertEqual(parameters["headers"], {"dstIps": "192.0.2.1", "dscps": "0,46", "ecns": "0-1"})


class TracerouteRouteHeaderValidationTest(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.batfish_service = app_module.batfish_service
        self.original_initialized = self.batfish_service._initialized
        self.batfish_service._initialized = True

    def tearDown(self):
        self.batfish_service._initialized = self.original_initialized

    def test_invalid_integer_header_values_are_a_400_naming_the_field(self):
        for path in ("/api/path/traceroute", "/api/path/bidirectional-traceroute"):
            with self.subTest(path=path):
                response = self.client.post(path, json={"headers": {"dstIps": "192.0.2.1", "icmpTypes": [True]}})

                self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                self.assertIn("headers.icmpTypes", response.get_json()["message"])

    def test_invalid_header_values_keep_the_structured_error_fields(self):
        for path in ("/api/path/traceroute", "/api/path/bidirectional-traceroute"):
            with self.subTest(path=path):
                response = self.client.post(path, json={"headers": {"dstIps": "192.0.2.1", "dscps": [-1]}})

                self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                payload = response.get_json()
                self.assertEqual(payload["code"], "header_constraint_invalid")
                self.assertEqual(payload["details"]["parameters"], {"headers.dscps": [-1]})
                self.assertTrue(any("comma-separated" in hint for hint in payload["hints"]))

    def test_batfish_query_errors_keep_their_status_code(self):
        timeout = BatfishQueryError(
            query_name="traceroute",
            message="Batfish query 'traceroute' timed out",
            error_type="query_timeout",
            status_code=504,
        )
        for path, method in (
            ("/api/path/traceroute", "traceroute"),
            ("/api/path/bidirectional-traceroute", "bidirectional_traceroute"),
        ):
            with self.subTest(path=path):
                with mock.patch.object(self.batfish_service, method, side_effect=timeout):
                    response = self.client.post(path, json={"headers": {"dstIps": "192.0.2.1"}})

                self.assertEqual(response.status_code, 504, response.get_data(as_text=True)[:300])
                self.assertEqual(response.get_json()["code"], "query_timeout")


class HeaderConstraintQueriesTest(unittest.TestCase):
    QUERIES = (
        ("get_reachability", "reachability", {}),
        ("test_filters", "testFilters", {}),
        ("search_filters", "searchFilters", {}),
        ("find_matching_filter_lines", "findMatchingFilterLines", {}),
        ("get_differential_reachability", "differentialReachability", {"reference_snapshot": "base"}),
        ("get_bidirectional_reachability", "bidirectionalReachability", {}),
    )

    def setUp(self):
        self.service = BatfishService()
        self.service._initialized = True
        self.service._session = mock.MagicMock()
        self.service._execute_query = lambda query, query_name, **kwargs: None

    def test_headers_are_normalized_before_the_question_is_built(self):
        for method, question, kwargs in self.QUERIES:
            with self.subTest(method=method):
                getattr(self.service, method)(headers={"dstIps": "192.0.2.1", "dstPorts": [22, "443"]}, **kwargs)

                call = getattr(self.service._session.q, question).call_args
                self.assertEqual(call.kwargs["headers"], {"dstIps": "192.0.2.1", "dstPorts": "22,443"})

    def test_invalid_headers_never_reach_batfish(self):
        for method, question, kwargs in self.QUERIES:
            with self.subTest(method=method):
                with self.assertRaises(BatfishQueryError) as raised:
                    getattr(self.service, method)(headers={"dscps": [300]}, **kwargs)

                self.assertEqual(raised.exception.error_type, "header_constraint_invalid")
                self.assertEqual(raised.exception.query_name, question)
                getattr(self.service._session.q, question).assert_not_called()


class HeaderConstraintRouteValidationTest(unittest.TestCase):
    ROUTES = (
        ("/api/path/traceroute", {}),
        ("/api/path/bidirectional-traceroute", {}),
        ("/api/analysis/reachability", {}),
        ("/api/advanced/reduce-reachability", {}),
        ("/api/acl/test-filters", {}),
        ("/api/acl/search-filters", {}),
        ("/api/acl/find-matching-lines", {}),
        ("/api/advanced/differential-reachability", {"reference_snapshot": "fx-base"}),
        ("/api/advanced/bidirectional-reachability", {}),
    )

    def setUp(self):
        self.client = app_module.app.test_client()
        self.batfish_service = app_module.batfish_service
        self.original_initialized = self.batfish_service._initialized
        self.batfish_service._initialized = True
        self.patches = [
            mock.patch.object(self.batfish_service, "_session", mock.MagicMock()),
            mock.patch.object(app_module, "require_snapshot_access"),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        self.batfish_service._initialized = self.original_initialized

    def test_invalid_header_items_are_a_structured_400(self):
        cases = (
            ({"dstIps": "192.0.2.1", "icmpTypes": "abc"}, "headers.icmpTypes"),
            ({"dstIps": "192.0.2.1", "dscps": [300]}, "headers.dscps"),
        )
        for path, extra in self.ROUTES:
            for headers, parameter_key in cases:
                with self.subTest(path=path, headers=headers):
                    response = self.client.post(path, json={"headers": headers, **extra})

                    self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                    payload = response.get_json()
                    self.assertEqual(payload["code"], "header_constraint_invalid")
                    self.assertIn(parameter_key, payload["message"])
                    self.assertIn(parameter_key, payload["details"]["parameters"])
                    self.assertTrue(payload["hints"])

    def test_oversized_and_fully_excluded_header_items_are_a_structured_400(self):
        cases = (
            ({"dstIps": "192.0.2.1", "dstPorts": "9" * 5000}, "headers.dstPorts", "outside the allowed range 0-65535"),
            ({"dstIps": "192.0.2.1", "icmpTypes": "!0-255"}, "headers.icmpTypes", "remains after the exclusions"),
        )
        for path, extra in self.ROUTES:
            for headers, parameter_key, reason in cases:
                with self.subTest(path=path, field=parameter_key):
                    response = self.client.post(path, json={"headers": headers, **extra})

                    self.assertEqual(response.status_code, 400, response.get_data(as_text=True)[:300])
                    payload = response.get_json()
                    self.assertEqual(payload["code"], "header_constraint_invalid")
                    self.assertIn(parameter_key, payload["message"])
                    self.assertIn(reason, payload["message"])


if __name__ == "__main__":
    unittest.main()
