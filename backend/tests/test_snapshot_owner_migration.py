import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security.validation import validate_positive_integer
from services.snapshot_service import METADATA_FILENAME, SnapshotService


class SnapshotOwnerMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.snapshots_dir = Path(self.temp_dir.name)
        self.service = SnapshotService()
        self.service.snapshots_dir = self.snapshots_dir

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_legacy_snapshot(self, name: str) -> Path:
        snapshot_path = self.snapshots_dir / name
        configs_dir = snapshot_path / "configs"
        configs_dir.mkdir(parents=True)
        (configs_dir / "router.cfg").write_text("hostname router\n", encoding="utf-8")
        return snapshot_path

    def test_list_unowned_snapshots_includes_legacy_snapshot(self):
        self._create_legacy_snapshot("legacy_snapshot")

        snapshots = self.service.list_unowned_snapshots()

        self.assertEqual([snapshot["name"] for snapshot in snapshots], ["legacy_snapshot"])
        self.assertTrue(snapshots[0]["legacy_unowned"])
        self.assertEqual(snapshots[0]["access_scope"], "legacy")

    def test_dry_run_does_not_create_owner_metadata(self):
        snapshot_path = self._create_legacy_snapshot("legacy_snapshot")

        result = self.service.assign_snapshot_owner(
            "legacy_snapshot",
            owner_user_id=7,
            owner_username="alice",
            folder_name="migrated",
            dry_run=True,
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["owner_user_id"], 7)
        self.assertFalse((snapshot_path / METADATA_FILENAME).exists())
        self.assertFalse((snapshot_path / f"{METADATA_FILENAME}.lock").exists())
        self.assertEqual(sorted(path.name for path in snapshot_path.iterdir()), ["configs"])

    def test_assign_owner_makes_snapshot_private_to_target_owner(self):
        snapshot_path = self._create_legacy_snapshot("legacy_snapshot")

        result = self.service.assign_snapshot_owner(
            "legacy_snapshot",
            owner_user_id=7,
            owner_username="alice",
            folder_name="migrated",
        )

        self.assertFalse(result["dry_run"])
        self.assertEqual(result["owner_username"], "alice")
        self.assertEqual(result["folder_name"], "migrated")
        metadata = json.loads((snapshot_path / METADATA_FILENAME).read_text(encoding="utf-8"))
        self.assertEqual(metadata["owner_user_id"], 7)
        self.assertEqual(metadata["access_scope"], "private")
        self.assertEqual(self.service.list_unowned_snapshots(), [])

        owner_visible = self.service.list_snapshots(requester_user_id=7, auth_enabled=True)
        other_visible = self.service.list_snapshots(requester_user_id=8, auth_enabled=True)
        open_visible = self.service.list_snapshots(auth_enabled=False)

        self.assertEqual([snapshot["name"] for snapshot in owner_visible], ["legacy_snapshot"])
        self.assertEqual(other_visible, [])
        self.assertEqual([snapshot["name"] for snapshot in open_visible], ["legacy_snapshot"])

    def test_assign_owner_rejects_already_owned_snapshot(self):
        self._create_legacy_snapshot("legacy_snapshot")
        self.service.assign_snapshot_owner("legacy_snapshot", 7, "alice")

        with self.assertRaises(ValueError):
            self.service.assign_snapshot_owner("legacy_snapshot", 8, "bob")

    def test_owner_user_id_validation_rejects_non_integer_values(self):
        invalid_values = [True, False, 1.0, 1.9, "1", [1], {"id": 1}, None, 0, -1]

        for invalid_value in invalid_values:
            with self.subTest(value=invalid_value):
                with self.assertRaisesRegex(ValueError, "owner_user_id must be a positive integer"):
                    validate_positive_integer(invalid_value, "owner_user_id")

        self.assertEqual(validate_positive_integer(7, "owner_user_id"), 7)

    def test_assignment_route_rejects_malformed_and_invalid_owner_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env = os.environ.copy()
            env.update({
                "AUTH_ENABLED": "true",
                "SECRET_KEY": "route-test-secret-key",
                "JWT_SECRET_KEY": "route-test-jwt-secret-key",
                "CSRF_SECRET_KEY": "route-test-csrf-secret-key",
                "AUTH_DEFAULT_ADMIN_PASS": "RouteTestPassword123!",
                "DATABASE_URL": f"sqlite:///{Path(temp_dir) / 'route-test.db'}",
            })
            script = r'''
import json
from app import app

with app.test_client() as client:
    with app.test_request_context("/"):
        token = app.jwt_manager.generate_tokens("1", "admin", ["admin"])["access_token"]
    csrf_base = "route-test-csrf"
    with client.session_transaction() as session:
        session["csrf_token"] = csrf_base
    headers = {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": app.csrf._sign_token(csrf_base),
    }
    invalid_owner = client.post(
        "/api/admin/snapshot-migrations/assign-owner",
        json={"snapshot_name": "legacy_snapshot", "owner_user_id": True},
        headers=headers,
    )
    malformed_json = client.post(
        "/api/admin/snapshot-migrations/assign-owner",
        data='{"snapshot_name":"legacy_snapshot","owner_user_id":',
        content_type="application/json",
        headers=headers,
    )
    text_plain = client.post(
        "/api/admin/snapshot-migrations/assign-owner",
        data="not json",
        content_type="text/plain",
        headers=headers,
    )
    missing_content_type = client.post(
        "/api/admin/snapshot-migrations/assign-owner",
        data='{"snapshot_name":"legacy_snapshot","owner_user_id":true}',
        headers=headers,
    )
    print(json.dumps({
        "invalid_owner": invalid_owner.status_code,
        "invalid_owner_message": (invalid_owner.get_json(silent=True) or {}).get("message"),
        "malformed_json": malformed_json.status_code,
        "malformed_json_message": (malformed_json.get_json(silent=True) or {}).get("message"),
        "text_plain": text_plain.status_code,
        "text_plain_message": (text_plain.get_json(silent=True) or {}).get("message"),
        "missing_content_type": missing_content_type.status_code,
        "missing_content_type_message": (missing_content_type.get_json(silent=True) or {}).get("message"),
    }))
'''
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

        result = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(result["invalid_owner"], 400)
        self.assertEqual(result["invalid_owner_message"], "owner_user_id must be a positive integer")
        self.assertEqual(result["malformed_json"], 400)
        self.assertEqual(result["malformed_json_message"], "Request body must be valid JSON")
        self.assertEqual(result["text_plain"], 400)
        self.assertEqual(result["text_plain_message"], "Request body must be valid JSON")
        self.assertEqual(result["missing_content_type"], 400)
        self.assertEqual(result["missing_content_type_message"], "Request body must be valid JSON")


if __name__ == "__main__":
    unittest.main()
