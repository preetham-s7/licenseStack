from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from license_platform.http import create_server


class PlatformHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.server = create_server(Path(self.temp_dir.name) / "licenses.sqlite3", "test-signing-secret-12345", "test-admin-token-12345", port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(self, route: str, body: dict, token: str | None = None, api_key: str | None = None) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if api_key:
            headers["X-API-Key"] = api_key
        request = urllib.request.Request(self.base_url + route, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def get_request(self, route: str, token: str | None = None, api_key: str | None = None) -> tuple[int, dict]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if api_key:
            headers["X-API-Key"] = api_key
        request = urllib.request.Request(self.base_url + route, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_one_time_activation_is_bound_to_first_device(self) -> None:
        status, created = self.request("/v1/licenses", {"app_id": "sample-app"}, "test-admin-token-12345")
        self.assertEqual(status, 201)
        key = created["license_key"]

        status, first = self.request("/v1/activate", {"app_id": "sample-app", "license_key": key, "device_id": "computer-a"})
        self.assertEqual(status, 200)
        self.assertEqual(first["status"], "active")

        status, repeated = self.request("/v1/activate", {"app_id": "sample-app", "license_key": key, "device_id": "computer-a"})
        self.assertEqual(status, 200)
        self.assertEqual(repeated["license_id"], first["license_id"])

        status, other = self.request("/v1/activate", {"app_id": "sample-app", "license_key": key, "device_id": "computer-b"})
        self.assertEqual(status, 409)
        self.assertEqual(other["error"]["code"], "LICENSE_BOUND")

        status, valid = self.request("/v1/validate", {"app_id": "sample-app", "token": first["token"], "device_id": "computer-a"})
        self.assertEqual(status, 200)
        self.assertTrue(valid["valid"])

        status, mismatch = self.request("/v1/validate", {"app_id": "sample-app", "token": first["token"], "device_id": "computer-b"})
        self.assertEqual(status, 403)
        self.assertEqual(mismatch["error"]["code"], "DEVICE_MISMATCH")

        tampered = first["token"][:-1] + ("a" if first["token"][-1] != "a" else "b")
        status, invalid = self.request("/v1/validate", {"app_id": "sample-app", "token": tampered, "device_id": "computer-a"})
        self.assertEqual(status, 401)
        self.assertEqual(invalid["error"]["code"], "INVALID_TOKEN")

    def test_admin_can_reset_then_reactivate_and_revoke(self) -> None:
        _, created = self.request("/v1/licenses", {"app_id": "other-app"}, "test-admin-token-12345")
        key = created["license_key"]
        self.assertEqual(self.request("/v1/activate", {"app_id": "other-app", "license_key": key, "device_id": "a"})[0], 200)
        self.assertEqual(self.request(f"/v1/licenses/{key}/reset", {}, "test-admin-token-12345")[0], 200)
        self.assertEqual(self.request("/v1/activate", {"app_id": "other-app", "license_key": key, "device_id": "b"})[0], 200)
        self.assertEqual(self.request(f"/v1/licenses/{key}/revoke", {}, "test-admin-token-12345")[0], 200)
        status, rejected = self.request("/v1/activate", {"app_id": "other-app", "license_key": key, "device_id": "b"})
        self.assertEqual(status, 403)
        self.assertEqual(rejected["error"]["code"], "LICENSE_REVOKED")

    def test_admin_is_required_for_management(self) -> None:
        status, body = self.request("/v1/licenses", {"app_id": "sample-app"})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "UNAUTHORIZED")
        with urllib.request.urlopen(self.base_url + "/dashboard", timeout=3) as response:
            dashboard = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("Developer Dashboard", dashboard)

    def test_application_api_key_isolated_to_its_application(self) -> None:
        status, created_app = self.request("/v1/apps", {"app_id": "vendor-tool", "name": "Vendor Tool"}, "test-admin-token-12345")
        self.assertEqual(status, 201)
        app_key = created_app["api_key"]

        status, created_license = self.request("/v1/licenses", {"app_id": "vendor-tool"}, api_key=app_key)
        self.assertEqual(status, 201)
        self.assertEqual(created_license["app_id"], "vendor-tool")

        status, denied = self.request("/v1/licenses", {"app_id": "another-tool"}, api_key=app_key)
        self.assertEqual(status, 401)
        self.assertEqual(denied["error"]["code"], "UNAUTHORIZED")

        status, listed = self.get_request("/v1/licenses?app_id=vendor-tool", api_key=app_key)
        self.assertEqual(status, 200)
        self.assertEqual(len(listed["licenses"]), 1)

        status, other_list = self.get_request("/v1/licenses?app_id=another-tool", api_key=app_key)
        self.assertEqual(status, 401)
        self.assertEqual(other_list["error"]["code"], "UNAUTHORIZED")

    def test_developer_dashboard_flow_and_key_rotation(self) -> None:
        status, registered = self.request("/v1/auth/register", {"name": "Developer", "email": "developer@example.com", "password": "secure-password"})
        self.assertEqual(status, 201)
        session = registered["session_token"]

        status, app = self.request("/v1/developer/apps", {"app_id": "developer-tool", "name": "Developer Tool"}, session)
        self.assertEqual(status, 201)
        self.assertEqual(app["app_id"], "developer-tool")

        status, license_result = self.request("/v1/developer/licenses", {"app_id": "developer-tool"}, session)
        self.assertEqual(status, 201)
        self.assertEqual(license_result["app_id"], "developer-tool")

        status, licenses = self.get_request("/v1/developer/licenses?app_id=developer-tool", session)
        self.assertEqual(status, 200)
        self.assertEqual(len(licenses["licenses"]), 1)

        status, rotated = self.request("/v1/developer/apps/developer-tool/rotate-key", {}, session)
        self.assertEqual(status, 200)
        self.assertNotEqual(rotated["api_key"], app["api_key"])

        status, old_key_denied = self.request("/v1/licenses", {"app_id": "developer-tool"}, api_key=app["api_key"])
        self.assertEqual(status, 401)
        self.assertEqual(old_key_denied["error"]["code"], "UNAUTHORIZED")

        status, new_key_works = self.request("/v1/licenses", {"app_id": "developer-tool"}, api_key=rotated["api_key"])
        self.assertEqual(status, 201)
        self.assertEqual(new_key_works["app_id"], "developer-tool")


if __name__ == "__main__":
    unittest.main()
