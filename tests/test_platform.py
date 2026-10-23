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

    def test_mobile_qr_pairing_is_one_time_and_repeatable(self) -> None:
        _, created = self.request("/v1/licenses", {"app_id": "qr-app"}, "test-admin-token-12345")
        key = created["license_key"]
        _, activation = self.request("/v1/activate", {"app_id": "qr-app", "license_key": key, "device_id": "desktop-a"})
        status, pairing = self.request("/v1/pairing/create", {"app_id": "qr-app", "token": activation["token"], "device_id": "desktop-a"})
        self.assertEqual(status, 201)
        self.assertEqual(pairing["status"], "pending")
        self.assertIn("/scan?code=", pairing["scan_path"])

        status, first_scan = self.request("/v1/pairing/scan", {"pairing_code": pairing["pairing_code"], "mobile_device_id": "phone-a"})
        self.assertEqual(status, 200)
        self.assertEqual(first_scan["status"], "activated")
        status, repeat_scan = self.request("/v1/pairing/scan", {"pairing_code": pairing["pairing_code"], "mobile_device_id": "phone-a"})
        self.assertEqual(status, 200)
        self.assertEqual(repeat_scan["status"], "already_activated")
        status, pairing_status = self.request("/v1/pairing/status", {"app_id": "qr-app", "pairing_id": pairing["pairing_id"], "token": activation["token"], "device_id": "desktop-a"})
        self.assertEqual(status, 200)
        self.assertTrue(pairing_status["paired"])
        status, no_new_pairing = self.request("/v1/pairing/create", {"app_id": "qr-app", "token": activation["token"], "device_id": "desktop-a"})
        self.assertEqual(status, 201)
        self.assertEqual(no_new_pairing["status"], "already_activated")

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


    def test_customer_dashboard_lifecycle_and_tenant_isolation(self) -> None:
        def developer(email):
            code, result = self.request('/v1/auth/register', {'name': 'Developer', 'email': email, 'password': 'secure-password'})
            self.assertEqual(code, 201)
            return result['session_token']

        owner = developer('owner@example.com')
        other = developer('other@example.com')
        _, app = self.request('/v1/developer/apps', {'app_id': 'customer-tool', 'name': 'Customer Tool'}, owner)
        code, customer = self.request('/v1/developer/customers', {'app_id': 'customer-tool', 'name': 'Alex Morgan', 'email': 'alex@example.com', 'notes': 'Enterprise customer'}, owner)
        self.assertEqual(code, 201)
        customer_id = customer['id']
        code, duplicate = self.request('/v1/developer/customers', {'app_id': 'customer-tool', 'name': 'Other Alex', 'email': 'alex@example.com'}, owner)
        self.assertEqual(code, 409)
        route = f'/v1/developer/customers/{customer_id}?app_id=customer-tool'
        self.assertEqual(self.get_request(route, other)[0], 403)
        self.assertEqual(self.get_request(route)[0], 401)
        code, customers = self.get_request('/v1/customers?app_id=customer-tool', api_key=app['api_key'])
        self.assertEqual(code, 200)
        self.assertEqual(customers['customers'][0]['name'], 'Alex Morgan')
        code, license_result = self.request('/v1/licenses', {'app_id': 'customer-tool', 'customer_id': customer_id, 'plan': 'Pro'}, api_key=app['api_key'])
        self.assertEqual(code, 201)
        license_id, key = license_result['id'], license_result['license_key']
        code, detail = self.get_request(route, owner)
        self.assertEqual(detail['licenses'][0]['plan'], 'Pro')
        self.assertNotIn('license_key', detail['licenses'][0])
        self.assertNotIn('key_hash', detail['licenses'][0])
        self.assertEqual(len(detail['events']), 1)
        _, activated = self.request('/v1/activate', {'app_id': 'customer-tool', 'license_key': key, 'device_id': 'alex-pc', 'device_label': 'Alex laptop'})
        validation = {'app_id': 'customer-tool', 'token': activated['token'], 'device_id': 'alex-pc'}
        self.assertEqual(self.request('/v1/validate', validation)[0], 200)
        code, usage = self.get_request('/v1/developer/usage?app_id=customer-tool', owner)
        self.assertEqual(code, 200)
        self.assertEqual(usage['totals']['activated'], 1)
        self.assertEqual(usage['totals']['validated'], 1)
        code, api_usage = self.get_request('/v1/usage?app_id=customer-tool', api_key=app['api_key'])
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(api_usage['recent']), 2)
        record_path = f'/v1/developer/license-records/{license_id}'
        self.assertEqual(self.request(record_path+'/revoke', {'app_id': 'customer-tool'}, other)[0], 403)
        self.assertEqual(self.request(record_path+'/revoke', {'app_id': 'customer-tool'}, owner)[0], 200)
        self.assertEqual(self.request('/v1/validate', validation)[0], 403)
        self.assertEqual(self.request('/v1/activate', {'app_id': 'customer-tool', 'license_key': key, 'device_id': 'alex-pc'})[0], 403)
        self.assertEqual(self.request(record_path+'/restore', {'app_id': 'customer-tool'}, owner)[0], 200)
        _, fresh = self.request('/v1/activate', {'app_id': 'customer-tool', 'license_key': key, 'device_id': 'alex-pc'})
        self.assertEqual(self.request('/v1/validate', validation)[0], 403)
        validation['token'] = fresh['token']
        self.assertEqual(self.request('/v1/validate', validation)[0], 200)
        self.assertEqual(self.request(record_path+'/update', {'app_id': 'customer-tool', 'plan': 'Enterprise', 'expires_at': '2030-01-01T00:00:00Z'}, owner)[0], 200)
        self.assertEqual(self.request('/v1/validate', validation)[0], 403)
        self.assertEqual(self.get_request(route, owner)[1]['licenses'][0]['plan'], 'Enterprise')
        self.assertEqual(self.request(record_path+'/reset', {'app_id': 'customer-tool'}, owner)[0], 200)
        _, renewed = self.request('/v1/activate', {'app_id': 'customer-tool', 'license_key': key, 'device_id': 'new-pc'})
        self.assertEqual(renewed['status'], 'active')
        self.request('/v1/developer/apps/customer-tool/revoke', {}, owner)
        self.assertEqual(self.request('/v1/validate', {'app_id':'customer-tool', 'token':renewed['token'], 'device_id':'new-pc'})[0], 403)

    def test_product_routes_and_assets_are_served(self) -> None:
        self.server.static_root = str(Path(__file__).resolve().parents[1] / 'site' / 'dist')
        for route in ['/', '/login', '/signup', '/dashboard', '/dashboard/', '/docs', '/docs/', '/scan', '/scan/', '/docs.html', '/workspace.css', '/dashboard.js', '/theme.js', '/scan.css', '/scan.js']:
            with self.subTest(route=route):
                with urllib.request.urlopen(self.base_url + route, timeout=3) as response:
                    self.assertEqual(response.status, 200)
                    self.assertGreater(len(response.read()), 50)
        with urllib.request.urlopen(self.base_url + '/docs/', timeout=3) as response:
            self.assertIn('href="/styles.css"', response.read().decode())

    def test_customer_api_key_cannot_cross_application_boundary(self) -> None:
        admin = 'test-admin-token-12345'
        _, first = self.request('/v1/apps', {'app_id': 'first-app', 'name': 'First'}, admin)
        _, second = self.request('/v1/apps', {'app_id': 'second-app', 'name': 'Second'}, admin)
        _, customer = self.request('/v1/customers', {'app_id':'first-app','name':'Jane','email':'jane@example.com'}, api_key=first['api_key'])
        self.assertEqual(self.get_request('/v1/customers?app_id=first-app', api_key=second['api_key'])[0], 401)
        self.assertEqual(self.get_request(f"/v1/customers/{customer['id']}?app_id=second-app", api_key=second['api_key'])[0], 404)
        self.assertEqual(self.request('/v1/licenses', {'app_id':'second-app','customer_id':customer['id']}, api_key=second['api_key'])[0], 404)
        _, license_result = self.request('/v1/licenses', {'app_id':'first-app','customer_id':customer['id']}, api_key=first['api_key'])
        self.assertEqual(self.request(f"/v1/license-records/{license_result['id']}/revoke", {'app_id':'second-app'}, api_key=second['api_key'])[0], 404)
        self.assertEqual(self.request(f"/v1/customers/{customer['id']}/update", {'app_id':'first-app','name':'Jane Updated','email':'jane@example.com','notes':'Saved'}, api_key=first['api_key'])[0], 200)
        self.assertEqual(self.get_request(f"/v1/customers/{customer['id']}?app_id=first-app", api_key=first['api_key'])[1]['customer']['name'], 'Jane Updated')

if __name__ == "__main__":
    unittest.main()
