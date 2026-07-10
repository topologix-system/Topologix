import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import app as app_module
from services.snapshot_service import ConfigContentConflictError, MAX_FILE_SIZE


VALID_CONFIG = "hostname router1\ninterface Ethernet0\n ip address 192.0.2.1 255.255.255.0\n"


class SnapshotConfigContentTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshots_dir = Path(self.temp_dir.name)
        self.service = app_module.snapshot_service
        self.original_snapshots_dir = self.service.snapshots_dir
        self.service.snapshots_dir = self.snapshots_dir
        self.app = app_module.app

    def tearDown(self):
        self.service.snapshots_dir = self.original_snapshots_dir
        self.temp_dir.cleanup()

    def _create_snapshot_with_file(
        self,
        name: str = "owner_snapshot",
        filename: str = "router.cfg",
        content: str = VALID_CONFIG,
        owner_user_id: int = 7,
    ) -> Path:
        self.service.create_snapshot(
            name,
            owner_user_id=owner_user_id,
            owner_username="owner",
            auth_enabled=True,
        )
        file_path = self.snapshots_dir / name / "configs" / filename
        file_path.write_text(content, encoding="utf-8")
        return file_path

    @staticmethod
    def _sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def test_get_and_put_reuse_snapshot_owner_authorization(self):
        self._create_snapshot_with_file()

        owner_read = self.service.get_config_file_content(
            "owner_snapshot",
            "router.cfg",
            requester_user_id=7,
            auth_enabled=True,
        )
        self.assertEqual(owner_read["content"], VALID_CONFIG)
        self.assertEqual(owner_read["sha256"], self._sha256(VALID_CONFIG))

        updated_content = VALID_CONFIG + "router ospf 1\n network 192.0.2.0 0.0.0.255 area 0\n"
        owner_update = self.service.update_config_file_content(
            "owner_snapshot",
            "router.cfg",
            updated_content,
            owner_read["sha256"],
            requester_user_id=7,
            auth_enabled=True,
        )
        self.assertTrue(owner_update["requires_reinitialize"])

        with self.assertRaises(PermissionError):
            self.service.get_config_file_content(
                "owner_snapshot",
                "router.cfg",
                requester_user_id=8,
                auth_enabled=True,
            )

        with self.assertRaises(PermissionError):
            self.service.update_config_file_content(
                "owner_snapshot",
                "router.cfg",
                updated_content,
                owner_update.get("sha256", self._sha256(updated_content)),
                requester_user_id=8,
                auth_enabled=True,
            )

    def test_put_applies_upload_equivalent_validation(self):
        self._create_snapshot_with_file()
        current_hash = self._sha256(VALID_CONFIG)
        oversized_content = VALID_CONFIG + ("!" * (MAX_FILE_SIZE + 1))

        invalid_cases = [
            ("", "File is empty"),
            ("plain notes without enough network keywords", "valid network configuration"),
            (VALID_CONFIG + "\x00", "Binary files are not allowed"),
            (VALID_CONFIG + "<script>alert(1)</script>\n", "potentially malicious content"),
            (oversized_content, "exceeds maximum allowed size"),
        ]

        for content, message in invalid_cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    self.service.update_config_file_content(
                        "owner_snapshot",
                        "router.cfg",
                        content,
                        current_hash,
                        requester_user_id=7,
                        auth_enabled=True,
                    )

    def test_optimistic_concurrency_conflict_maps_to_409(self):
        self._create_snapshot_with_file()

        with self.assertRaises(ConfigContentConflictError):
            self.service.update_config_file_content(
                "owner_snapshot",
                "router.cfg",
                VALID_CONFIG + "router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n",
                "0" * 64,
                requester_user_id=7,
                auth_enabled=True,
            )

        with self.app.test_client() as client:
            response = client.put(
                "/api/snapshots/owner_snapshot/files/router.cfg/content",
                json={
                    "content": VALID_CONFIG + "router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n",
                    "expected_sha256": "0" * 64,
                },
            )

        self.assertEqual(response.status_code, 409)
        payload = response.get_json()
        self.assertEqual(payload["code"], "config_content_conflict")
        self.assertNotIn(VALID_CONFIG.strip(), payload["message"])

    def test_malformed_expected_sha_returns_400(self):
        self._create_snapshot_with_file()

        with self.app.test_client() as client:
            response = client.put(
                "/api/snapshots/owner_snapshot/files/router.cfg/content",
                json={
                    "content": VALID_CONFIG + "router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n",
                    "expected_sha256": "not-a-valid-hash",
                },
            )

        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIn("64-character lowercase hexadecimal", payload["message"])
        self.assertNotIn(VALID_CONFIG.strip(), payload["message"])

    def test_oversized_put_returns_json_413_when_auth_is_disabled(self):
        self.assertFalse(app_module.config.AUTH_ENABLED)
        oversized_body = b'{"content":"' + (
            b"x" * app_module.config.MAX_CONTENT_LENGTH
        ) + b'","expected_sha256":"' + (b"0" * 64) + b'"}'
        self.assertGreater(len(oversized_body), app_module.config.MAX_CONTENT_LENGTH)

        with self.app.test_client() as client:
            response = client.put(
                "/api/snapshots/owner_snapshot/files/router.cfg/content",
                data=oversized_body,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 413)
        self.assertTrue(response.is_json)
        payload = response.get_json()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["message"], "Request body exceeds the maximum allowed size")
        self.assertNotIn("x" * 100, payload["message"])

    def test_escaped_json_body_above_file_limit_reaches_content_validation(self):
        file_path = self._create_snapshot_with_file()
        newline_count = 1024 * 1024
        filler_count = MAX_FILE_SIZE - 1 - len(VALID_CONFIG.encode("utf-8")) - newline_count
        near_limit_content = VALID_CONFIG + ("\n" * newline_count) + ("!" * filler_count)
        request_body = json.dumps(
            {
                "content": near_limit_content,
                "expected_sha256": self._sha256(VALID_CONFIG),
            }
        ).encode("utf-8")

        self.assertEqual(len(near_limit_content.encode("utf-8")), MAX_FILE_SIZE - 1)
        self.assertGreater(len(request_body), MAX_FILE_SIZE)
        self.assertLess(len(request_body), app_module.config.MAX_CONTENT_LENGTH)

        with self.app.test_client() as client:
            response = client.put(
                "/api/snapshots/owner_snapshot/files/router.cfg/content",
                data=request_body,
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(file_path.stat().st_size, MAX_FILE_SIZE - 1)

    def test_filename_traversal_is_rejected_for_content_routes(self):
        self._create_snapshot_with_file()

        with self.assertRaises(ValueError):
            self.service.get_config_file_content(
                "owner_snapshot",
                "../router.cfg",
                requester_user_id=7,
                auth_enabled=True,
            )

        with self.assertRaises(ValueError):
            self.service.update_config_file_content(
                "owner_snapshot",
                "../router.cfg",
                VALID_CONFIG,
                self._sha256(VALID_CONFIG),
                requester_user_id=7,
                auth_enabled=True,
            )

    def test_put_response_carries_requires_reinitialize(self):
        file_path = self._create_snapshot_with_file()
        updated_content = VALID_CONFIG + "router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n"

        response = self.service.update_config_file_content(
            "owner_snapshot",
            "router.cfg",
            updated_content,
            self._sha256(VALID_CONFIG),
            requester_user_id=7,
            auth_enabled=True,
        )

        self.assertTrue(response["requires_reinitialize"])
        self.assertEqual(file_path.read_text(encoding="utf-8"), updated_content)
        self.assertEqual(response["size_bytes"], len(updated_content.encode("utf-8")))

    def test_batfish_lock_gating_for_content_routes(self):
        with self.app.test_request_context(
            "/api/snapshots/owner_snapshot/files/router.cfg/content",
            method="PUT",
        ):
            self.assertTrue(app_module.request_uses_batfish())

        with self.app.test_request_context(
            "/api/snapshots/owner_snapshot/files/router.cfg/content",
            method="GET",
        ):
            self.assertFalse(app_module.request_uses_batfish())


if __name__ == "__main__":
    unittest.main()
