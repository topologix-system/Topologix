import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
ADMIN_PASSWORD = "SessionTestAdmin123!"

CLIENT_HELPERS = r'''
import json
import os

from app import app

ADMIN_PASSWORD = os.environ["AUTH_DEFAULT_ADMIN_PASS"]


def password_for(name):
    return f"Pw!{name}A9xyz12"


def login(username, password):
    client = app.test_client()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    data = (response.get_json(silent=True) or {}).get("data") or {}
    client.environ_base["HTTP_X_CSRF_TOKEN"] = data.get("csrf_token") or ""
    return client, response.status_code


def access_token(client):
    cookie = client.get_cookie("access_token")
    return cookie.value if cookie else None


def refresh_token(client):
    cookie = client.get_cookie("refresh_token", path="/api/auth/refresh")
    return cookie.value if cookie else None


def status_with_access(path, token):
    return app.test_client().get(path, headers={"Authorization": f"Bearer {token}"}).status_code


def status_with_refresh(token):
    client = app.test_client()
    client.set_cookie("refresh_token", token, path="/api/auth/refresh")
    return client.post("/api/auth/refresh").status_code


admin, admin_login_status = login("admin", ADMIN_PASSWORD)
admin_bearer = {"Authorization": f"Bearer {access_token(admin)}"}


def create_user(name, roles=None):
    body = {"username": name, "email": f"{name}@example.test", "password": password_for(name)}
    if roles is not None:
        body["roles"] = roles
    response = admin.post("/api/users", json=body, headers=admin_bearer)
    assert response.status_code == 201, (name, response.status_code, response.get_json(silent=True))
    return response.get_json()["data"]["id"]


def delete_user(user_id):
    return admin.delete(f"/api/users/{user_id}").status_code
'''

FRESH_DB_SCRIPT = CLIENT_HELPERS + r'''
from sqlalchemy import event

from database.models import PasswordResetToken
from database.session import get_db

results = {"admin_login": admin_login_status}

# User ids are never reused after deletion
first_id = create_user("idreuse_x")
x_client, _ = login("idreuse_x", password_for("idreuse_x"))
x_access = access_token(x_client)
results["delete_x"] = delete_user(first_id)
second_id = create_user("idreuse_y")
results["reuse_ids"] = [first_id, second_id]
results["deleted_x_token_after_y_created"] = status_with_access("/api/users/me", x_access)

# Logout ends the login session, including its refresh token
create_user("logout_a")
a_client, _ = login("logout_a", password_for("logout_a"))
a_other, _ = login("logout_a", password_for("logout_a"))
a_login_access = access_token(a_client)
a_refresh = refresh_token(a_client)
results["refresh_before_logout"] = a_client.post("/api/auth/refresh").status_code
a_refreshed_access = access_token(a_client)
results["logout"] = a_client.post("/api/auth/logout").status_code
results["logout_refresh_after"] = status_with_refresh(a_refresh)
results["logout_refreshed_access_after"] = status_with_access("/api/users/me", a_refreshed_access)
results["logout_login_access_after"] = status_with_access("/api/users/me", a_login_access)
results["logout_other_session_after"] = a_other.get("/api/users/me").status_code

# Logout succeeds without a valid token and revokes only a token that verifies
create_user("logout_h")
h_client, _ = login("logout_h", password_for("logout_h"))
h_client.set_cookie("access_token", "forged.token.value")
blacklist_size = len(app.jwt_manager.token_blacklist)
results["logout_forged_token"] = h_client.post("/api/auth/logout").status_code
results["logout_forged_token_blacklisted"] = len(app.jwt_manager.token_blacklist) - blacklist_size

# Password change invalidates tokens issued before the change
b_id = create_user("pwchange_b")
b_client, _ = login("pwchange_b", password_for("pwchange_b"))
b_other, _ = login("pwchange_b", password_for("pwchange_b"))
b_access = access_token(b_client)
b_refresh = refresh_token(b_client)
results["password_change"] = b_client.put(
    f"/api/users/{b_id}/password",
    json={"current_password": password_for("pwchange_b"), "new_password": "Changed!Passw0rd"},
).status_code
results["password_change_refresh_after"] = status_with_refresh(b_refresh)
results["password_change_access_after"] = status_with_access("/api/users/me", b_access)
results["password_change_other_session_after"] = b_other.get("/api/users/me").status_code
results["password_change_other_session_logout"] = b_other.post("/api/auth/logout").status_code
results["password_change_own_session_after"] = b_client.get("/api/users/me").status_code
results["password_change_own_refresh_after"] = b_client.post("/api/auth/refresh").status_code
results["password_change_own_new_access"] = access_token(b_client) not in (None, b_access)
b_new, results["password_change_relogin"] = login("pwchange_b", "Changed!Passw0rd")
results["password_change_new_session"] = b_new.get("/api/users/me").status_code

# Password reset invalidates tokens issued before the reset
c_id = create_user("pwreset_c")
c_client, _ = login("pwreset_c", password_for("pwreset_c"))
c_access = access_token(c_client)
c_refresh = refresh_token(c_client)
with app.app_context():
    with next(get_db()) as db:
        reset_row, reset_token = PasswordResetToken.create_for_user(c_id)
        db.add(reset_row)
        db.commit()
results["password_reset"] = app.test_client().post(
    "/api/auth/password-reset", json={"token": reset_token, "new_password": "Reset!Passw0rd1"}
).status_code
results["password_reset_refresh_after"] = status_with_refresh(c_refresh)
results["password_reset_access_after"] = status_with_access("/api/users/me", c_access)
c_new, results["password_reset_relogin"] = login("pwreset_c", "Reset!Passw0rd1")
results["password_reset_new_session"] = c_new.get("/api/users/me").status_code

# Deleted users' tokens are rejected
d_id = create_user("deleted_d")
d_client, _ = login("deleted_d", password_for("deleted_d"))
d_access = access_token(d_client)
d_refresh = refresh_token(d_client)
results["deleted_before"] = status_with_access("/api/snapshots", d_access)
results["delete_d"] = delete_user(d_id)
results["deleted_me_after"] = status_with_access("/api/users/me", d_access)
results["deleted_snapshots_after"] = status_with_access("/api/snapshots", d_access)
results["deleted_refresh_after"] = status_with_refresh(d_refresh)
results["deleted_logout"] = d_client.post("/api/auth/logout").status_code

# Deactivated users' tokens are rejected
e_id = create_user("inactive_e")
e_client, _ = login("inactive_e", password_for("inactive_e"))
e_other, _ = login("inactive_e", password_for("inactive_e"))
e_access = access_token(e_client)
e_refresh = refresh_token(e_client)
results["deactivate"] = admin.put(f"/api/users/{e_id}", json={"is_active": False}).status_code
results["inactive_me_after"] = status_with_access("/api/users/me", e_access)
results["inactive_snapshots_after"] = status_with_access("/api/snapshots", e_access)
results["inactive_refresh_after"] = status_with_refresh(e_refresh)
results["inactive_logout"] = e_other.post("/api/auth/logout").status_code
results["inactive_logout_clears_cookie"] = access_token(e_other) is None

# Reactivation does not revive tokens issued before the deactivation
results["reactivate"] = admin.put(f"/api/users/{e_id}", json={"is_active": True}).status_code
results["reactivated_old_access"] = status_with_access("/api/users/me", e_access)
results["reactivated_old_refresh"] = status_with_refresh(e_refresh)
e_new, results["reactivated_relogin"] = login("inactive_e", password_for("inactive_e"))
results["reactivated_new_session"] = e_new.get("/api/users/me").status_code

# Role-gated routes use the roles stored in the database
f_id = create_user("demoted_f", roles=["admin"])
f_client, _ = login("demoted_f", password_for("demoted_f"))
v_id = create_user("viewer_v")
v_client, _ = login("viewer_v", password_for("viewer_v"))
results["admin_security_logs"] = admin.get("/api/admin/security-logs").status_code
results["viewer_security_logs"] = v_client.get("/api/admin/security-logs").status_code
results["f_security_logs_before"] = f_client.get("/api/admin/security-logs").status_code
results["demote_f"] = admin.put(f"/api/users/{f_id}", json={"roles": ["viewer"]}).status_code
results["f_security_logs_after"] = f_client.get("/api/admin/security-logs").status_code
results["f_unowned_after"] = f_client.get("/api/admin/snapshot-migrations/unowned").status_code
results["promote_v"] = admin.put(f"/api/users/{v_id}", json={"roles": ["admin"]}).status_code
results["v_security_logs_after_promotion"] = v_client.get("/api/admin/security-logs").status_code

# The token user is loaded with a single users query per request
statements = []


@event.listens_for(app.db_manager.engine, "before_cursor_execute")
def capture_statement(conn, cursor, statement, parameters, context, executemany):
    statements.append(statement)


results["csrf_token_status"] = v_client.get("/api/auth/csrf-token").status_code
results["users_queries_per_request"] = sum(1 for statement in statements if "FROM users" in statement)

print(json.dumps(results))
'''

LEGACY_USERS_DDL = """
CREATE TABLE users (
    id INTEGER NOT NULL,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    is_active BOOLEAN NOT NULL,
    is_superuser BOOLEAN NOT NULL,
    email_verified BOOLEAN NOT NULL,
    force_password_change BOOLEAN NOT NULL,
    failed_login_attempts INTEGER NOT NULL,
    account_locked_until DATETIME,
    password_changed_at DATETIME,
    last_login_at DATETIME,
    last_login_ip VARCHAR(45),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_users_username ON users (username);
CREATE INDEX idx_users_email_active ON users (email, is_active);
CREATE UNIQUE INDEX ix_users_email ON users (email);
CREATE INDEX idx_users_created ON users (created_at);
"""

AUTOINCREMENT_USERS_DDL = LEGACY_USERS_DDL.replace(
    "id INTEGER NOT NULL,", "id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
).replace(",\n    PRIMARY KEY (id)\n", "\n")

LEGACY_DB_SCRIPT = r'''
import os

from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash

from database.models import Base

engine = create_engine(os.environ["DATABASE_URL"])
with engine.begin() as connection:
    for statement in os.environ["LEGACY_USERS_DDL"].split(";"):
        if statement.strip():
            connection.exec_driver_sql(statement)
Base.metadata.create_all(engine)
timestamp = "2026-01-01 00:00:00.000000"
with engine.begin() as connection:
    for user_id, username, superuser in ((1, "admin", 1), (2, "alice", 0), (3, "bob", 0)):
        connection.exec_driver_sql(
            "INSERT INTO users (id, username, email, password_hash, full_name, is_active, is_superuser, "
            "email_verified, force_password_change, failed_login_attempts, password_changed_at, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, '', 1, ?, 1, 0, 0, ?, ?, ?)",
            (user_id, username, f"{username}@topologix.local",
             generate_password_hash(os.environ["AUTH_DEFAULT_ADMIN_PASS"]), superuser,
             timestamp, timestamp, timestamp),
        )
    connection.exec_driver_sql(
        "INSERT INTO roles (id, name, description, is_system, created_at) VALUES "
        "(1, 'admin', 'admin', 1, ?), (2, 'viewer', 'viewer', 1, ?)", (timestamp, timestamp)
    )
    connection.exec_driver_sql("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1), (2, 2), (3, 2)")
engine.dispose()
''' + CLIENT_HELPERS + r'''
results = {"admin_login": admin_login_status}


def schema_state():
    with app.db_manager.engine.connect() as connection:
        return {
            "ddl": connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
            ).scalar(),
            "users": [list(row) for row in connection.exec_driver_sql("SELECT id, username FROM users ORDER BY id")],
            "user_roles": [
                list(row) for row in connection.exec_driver_sql(
                    "SELECT user_id, role_id FROM user_roles ORDER BY user_id, role_id"
                )
            ],
            "indexes": sorted(connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='users' AND sql IS NOT NULL"
            ).scalars()),
            "foreign_key_violations": [list(row) for row in connection.exec_driver_sql("PRAGMA foreign_key_check")],
            "foreign_keys": connection.exec_driver_sql("PRAGMA foreign_keys").scalar(),
            "sequence": connection.exec_driver_sql("SELECT seq FROM sqlite_sequence WHERE name='users'").scalar(),
        }


results["after_startup"] = schema_state()
new_id = create_user("legacy_new")
results["delete_new"] = delete_user(new_id)
next_id = create_user("legacy_next")
results["delete_bob"] = delete_user(3)
after_bob_id = create_user("legacy_after_bob")
results["created_ids"] = [new_id, next_id, after_bob_id]
app.db_manager.create_all()
results["after_second_create_all"] = schema_state()

print(json.dumps(results))
'''


def run_auth_app_script(script: str, temp_dir: str, extra_env: dict | None = None) -> dict:
    snapshots_dir = Path(temp_dir) / "snapshots"
    snapshots_dir.mkdir()
    env = os.environ.copy()
    env.update({
        "AUTH_ENABLED": "true",
        "SECRET_KEY": "session-test-secret-key",
        "JWT_SECRET_KEY": "session-test-jwt-secret-key",
        "CSRF_SECRET_KEY": "session-test-csrf-secret-key",
        "CSRF_MODE": "session",
        "ALLOW_REGISTRATION": "true",
        "AUTH_DEFAULT_ADMIN_USER": "admin",
        "AUTH_DEFAULT_ADMIN_PASS": ADMIN_PASSWORD,
        "DATABASE_URL": f"sqlite:///{Path(temp_dir) / 'auth-session-test.db'}",
        "SNAPSHOTS_DIR": str(snapshots_dir),
        "PYTHONPATH": str(BACKEND_DIR),
    })
    env.update(extra_env or {})
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        cwd=temp_dir,
    )
    if completed.returncode != 0:
        raise AssertionError(f"auth app script failed:\n{completed.stderr[-4000:]}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


class AuthSessionInvalidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            cls.results = run_auth_app_script(FRESH_DB_SCRIPT, temp_dir)

    def test_admin_login_succeeds(self):
        self.assertEqual(self.results["admin_login"], 200)

    def test_deleted_user_id_is_not_reused(self):
        first_id, second_id = self.results["reuse_ids"]
        self.assertEqual(self.results["delete_x"], 200)
        self.assertNotEqual(first_id, second_id)
        self.assertGreater(second_id, first_id)
        self.assertEqual(self.results["deleted_x_token_after_y_created"], 401)

    def test_logout_revokes_refresh_token_and_session_tokens(self):
        self.assertEqual(self.results["refresh_before_logout"], 200)
        self.assertEqual(self.results["logout"], 200)
        self.assertEqual(self.results["logout_refresh_after"], 401)
        self.assertEqual(self.results["logout_refreshed_access_after"], 401)
        self.assertEqual(self.results["logout_login_access_after"], 401)

    def test_logout_keeps_other_sessions(self):
        self.assertEqual(self.results["logout_other_session_after"], 200)

    def test_password_change_invalidates_existing_tokens(self):
        self.assertEqual(self.results["password_change"], 200)
        self.assertEqual(self.results["password_change_refresh_after"], 401)
        self.assertEqual(self.results["password_change_access_after"], 401)
        self.assertEqual(self.results["password_change_other_session_after"], 401)

    def test_login_after_password_change_is_usable_immediately(self):
        self.assertEqual(self.results["password_change_relogin"], 200)
        self.assertEqual(self.results["password_change_new_session"], 200)

    def test_password_reset_invalidates_existing_tokens(self):
        self.assertEqual(self.results["password_reset"], 200)
        self.assertEqual(self.results["password_reset_refresh_after"], 401)
        self.assertEqual(self.results["password_reset_access_after"], 401)
        self.assertEqual(self.results["password_reset_relogin"], 200)
        self.assertEqual(self.results["password_reset_new_session"], 200)

    def test_deleted_user_tokens_are_rejected(self):
        self.assertEqual(self.results["deleted_before"], 200)
        self.assertEqual(self.results["delete_d"], 200)
        self.assertEqual(self.results["deleted_me_after"], 401)
        self.assertEqual(self.results["deleted_snapshots_after"], 401)
        self.assertEqual(self.results["deleted_refresh_after"], 401)

    def test_deactivated_user_tokens_are_rejected(self):
        self.assertEqual(self.results["deactivate"], 200)
        self.assertEqual(self.results["inactive_me_after"], 401)
        self.assertEqual(self.results["inactive_snapshots_after"], 401)
        self.assertEqual(self.results["inactive_refresh_after"], 401)

    def test_reactivation_does_not_revive_tokens_issued_before_deactivation(self):
        self.assertEqual(self.results["reactivate"], 200)
        self.assertEqual(self.results["reactivated_old_access"], 401)
        self.assertEqual(self.results["reactivated_old_refresh"], 401)
        self.assertEqual(self.results["reactivated_relogin"], 200)
        self.assertEqual(self.results["reactivated_new_session"], 200)

    def test_logout_succeeds_without_a_valid_token(self):
        self.assertEqual(self.results["password_change_other_session_logout"], 200)
        self.assertEqual(self.results["deleted_logout"], 200)
        self.assertEqual(self.results["inactive_logout"], 200)
        self.assertTrue(self.results["inactive_logout_clears_cookie"])

    def test_logout_does_not_revoke_unverifiable_tokens(self):
        self.assertEqual(self.results["logout_forged_token"], 200)
        self.assertEqual(self.results["logout_forged_token_blacklisted"], 0)

    def test_password_change_keeps_the_changing_session_signed_in(self):
        self.assertEqual(self.results["password_change_own_session_after"], 200)
        self.assertEqual(self.results["password_change_own_refresh_after"], 200)
        self.assertTrue(self.results["password_change_own_new_access"])

    def test_unchanged_roles_keep_existing_access(self):
        self.assertEqual(self.results["admin_security_logs"], 200)
        self.assertEqual(self.results["viewer_security_logs"], 403)
        self.assertEqual(self.results["f_security_logs_before"], 200)

    def test_role_changes_apply_to_existing_tokens(self):
        self.assertEqual(self.results["demote_f"], 200)
        self.assertEqual(self.results["f_security_logs_after"], 403)
        self.assertEqual(self.results["f_unowned_after"], 403)
        self.assertEqual(self.results["promote_v"], 200)
        self.assertEqual(self.results["v_security_logs_after_promotion"], 200)

    def test_token_user_is_loaded_once_per_request(self):
        self.assertEqual(self.results["csrf_token_status"], 200)
        self.assertEqual(self.results["users_queries_per_request"], 1)


class LegacySqliteUsersTableMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            cls.results = run_auth_app_script(
                LEGACY_DB_SCRIPT, temp_dir, {"LEGACY_USERS_DDL": LEGACY_USERS_DDL}
            )

    def test_startup_rebuilds_users_table_with_autoincrement(self):
        state = self.results["after_startup"]
        self.assertIn("AUTOINCREMENT", state["ddl"].upper())
        self.assertEqual(state["sequence"], 3)

    def test_rebuild_adds_the_token_cutoff_column(self):
        self.assertIn("tokens_invalid_before", self.results["after_startup"]["ddl"])

    def test_rebuild_preserves_rows_relations_and_indexes(self):
        state = self.results["after_startup"]
        self.assertEqual(self.results["admin_login"], 200)
        self.assertEqual(state["users"], [[1, "admin"], [2, "alice"], [3, "bob"]])
        self.assertEqual(state["user_roles"], [[1, 1], [2, 2], [3, 2]])
        self.assertEqual(
            state["indexes"],
            ["idx_users_created", "idx_users_email_active", "ix_users_email", "ix_users_username"],
        )
        self.assertEqual(state["foreign_key_violations"], [])
        self.assertEqual(state["foreign_keys"], 1)

    def test_ids_are_not_reused_after_rebuild(self):
        self.assertEqual(self.results["delete_new"], 200)
        self.assertEqual(self.results["delete_bob"], 200)
        self.assertEqual(self.results["created_ids"], [4, 5, 6])

    def test_rebuild_is_idempotent(self):
        state = self.results["after_second_create_all"]
        self.assertEqual(state["ddl"], self.results["after_startup"]["ddl"])
        self.assertEqual(
            [row[0] for row in state["users"]],
            [1, 2, 5, 6],
        )


class ExistingSqliteUsersTableColumnMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temp_dir:
            cls.results = run_auth_app_script(
                LEGACY_DB_SCRIPT, temp_dir, {"LEGACY_USERS_DDL": AUTOINCREMENT_USERS_DDL}
            )

    def test_startup_adds_the_token_cutoff_column_without_a_rebuild(self):
        state = self.results["after_startup"]
        self.assertEqual(self.results["admin_login"], 200)
        self.assertIn("tokens_invalid_before", state["ddl"])
        self.assertTrue(state["ddl"].startswith("CREATE TABLE users ("), state["ddl"][:40])
        self.assertEqual(state["users"], [[1, "admin"], [2, "alice"], [3, "bob"]])
        self.assertEqual(state["user_roles"], [[1, 1], [2, 2], [3, 2]])
        self.assertEqual(state["foreign_key_violations"], [])

    def test_column_migration_is_idempotent(self):
        self.assertEqual(self.results["after_second_create_all"]["ddl"], self.results["after_startup"]["ddl"])


class TokenCutoffColumnPrecisionTest(unittest.TestCase):
    COLUMNS = ("password_changed_at", "tokens_invalid_before")

    def column_ddl(self, dialect):
        from sqlalchemy.schema import CreateTable
        from database.models import User

        create_sql = str(CreateTable(User.__table__).compile(dialect=dialect))
        return {
            name: (
                User.__table__.c[name].type.compile(dialect=dialect),
                next(line.strip().rstrip(",") for line in create_sql.splitlines() if line.strip().startswith(name)),
            )
            for name in self.COLUMNS
        }

    def test_mysql_columns_keep_microseconds(self):
        from sqlalchemy.dialects import mysql

        self.assertEqual(
            self.column_ddl(mysql.dialect()),
            {name: ("DATETIME(6)", f"{name} DATETIME(6)") for name in self.COLUMNS},
        )

    def test_sqlite_columns_keep_the_plain_datetime_type(self):
        from sqlalchemy.dialects import sqlite

        self.assertEqual(
            self.column_ddl(sqlite.dialect()),
            {name: ("DATETIME", f"{name} DATETIME") for name in self.COLUMNS},
        )


class ExistingTokenCutoffColumnPrecisionMigrationTest(unittest.TestCase):
    COLUMNS = ("password_changed_at", "tokens_invalid_before")

    def migration_statements(self, dialect, cutoff_type):
        from unittest import mock

        from database.models import User
        from database.session import DatabaseManager

        inspector = mock.Mock()
        inspector.get_columns.return_value = [
            {
                "name": column.name,
                "type": cutoff_type if column.name in self.COLUMNS else column.type,
                "nullable": column.nullable,
            }
            for column in User.__table__.columns
        ]
        manager = DatabaseManager.__new__(DatabaseManager)
        manager.engine = mock.MagicMock()
        manager.engine.dialect = dialect
        connection = manager.engine.begin.return_value.__enter__.return_value

        with mock.patch("sqlalchemy.inspect", return_value=inspector):
            manager._add_missing_nullable_columns(User.__table__)

        inspector.get_columns.assert_called_once_with("users")
        return [call.args[0] for call in connection.exec_driver_sql.call_args_list]

    def test_mysql_whole_second_columns_are_widened_to_microseconds(self):
        from sqlalchemy.dialects import mysql

        self.assertEqual(
            self.migration_statements(mysql.dialect(), mysql.DATETIME()),
            [f"ALTER TABLE users MODIFY {name} DATETIME(6) NULL" for name in self.COLUMNS],
        )

    def test_mysql_microsecond_columns_are_left_alone(self):
        from sqlalchemy.dialects import mysql

        self.assertEqual(self.migration_statements(mysql.dialect(), mysql.DATETIME(fsp=6)), [])

    def test_sqlite_and_postgresql_columns_are_left_alone(self):
        from sqlalchemy.dialects import postgresql, sqlite

        for dialect, cutoff_type in (
            (sqlite.dialect(), sqlite.DATETIME()),
            (postgresql.dialect(), postgresql.TIMESTAMP(timezone=True)),
        ):
            with self.subTest(dialect=dialect.name):
                self.assertEqual(self.migration_statements(dialect, cutoff_type), [])


if __name__ == "__main__":
    unittest.main()
