"""Small standard-library HTTP adapter for the licensing service."""

from __future__ import annotations

import html
import hmac
import json
import os
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from .core import LicenseError, LicenseService


MAX_BODY = 64 * 1024


class LicenseRequestHandler(BaseHTTPRequestHandler):
    server_version = "LicensePlatform/0.1"

    def end_headers(self) -> None:  # noqa: N802
        origin = self.headers.get("Origin", "")
        allowed_origins = getattr(self.server, "cors_origins", set())  # type: ignore[attr-defined]
        if origin and ("*" in allowed_origins or origin in allowed_origins):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
        self.send_header("Access-Control-Max-Age", "600")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _service(self) -> LicenseService:
        return self.server.license_service  # type: ignore[attr-defined]

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, error: LicenseError) -> None:
        self._json(error.status, {"error": {"code": error.code, "message": error.message}})

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY:
            raise LicenseError("REQUEST_TOO_LARGE", "Request body is too large.", 413)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LicenseError("INVALID_JSON", "Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise LicenseError("INVALID_JSON", "Request body must be a JSON object.")
        return value

    def _admin_ok(self) -> bool:
        expected = self.server.admin_token  # type: ignore[attr-defined]
        provided = self.headers.get("Authorization", "")
        return bool(expected) and provided.startswith("Bearer ") and hmac.compare_digest(provided[7:], expected)

    def _require_admin(self) -> None:
        if not self._admin_ok():
            raise LicenseError("UNAUTHORIZED", "Admin authorization is required.", 401)

    def _developer_token(self) -> str:
        authorization = self.headers.get("Authorization", "")
        return authorization[7:] if authorization.startswith("Bearer ") else ""

    def _require_developer(self) -> dict:
        developer = self._service().authenticate_developer(self._developer_token())
        if not developer:
            raise LicenseError("UNAUTHORIZED", "A valid developer login is required.", 401)
        return developer

    def _require_app_or_admin(self, app_id: str) -> None:
        if self._admin_ok():
            return
        api_key = self.headers.get("X-API-Key", "")
        if not self._service().authenticate_application(app_id, api_key):
            raise LicenseError("UNAUTHORIZED", "A valid application API key is required.", 401)

    def _ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _customer_scope(self, app_id: str, developer_route: bool) -> None:
        if not app_id:
            raise LicenseError("APP_REQUIRED", "Choose an application.")
        if developer_route:
            self._service().assert_application_owner(app_id, self._require_developer()["id"])
        else:
            self._require_app_or_admin(app_id)

    def _serve_static(self, request_path: str) -> bool:
        """Serve the local product site when the API server is used directly."""
        root = getattr(self.server, "static_root", None)  # type: ignore[attr-defined]
        if not root:
            return False

        relative_name = "index.html" if request_path in {"", "/"} else unquote(request_path.lstrip("/"))
        root_path = Path(root).resolve()
        candidate = (root_path / relative_name).resolve()
        try:
            candidate.relative_to(root_path)
        except ValueError:
            return False
        if not candidate.is_file():
            return False

        content_types = {
            ".css": "text/css; charset=utf-8",
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_types.get(candidate.suffix.lower(), "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._json(200, {"ok": True, "service": "license-platform"})
                return
            if parsed.path == "/admin":
                self._admin_page()
                return
            if parsed.path.rstrip("/") in {"/dashboard", "/login", "/signup"}:
                self._developer_page()
                return
            if parsed.path.rstrip("/") == "/docs":
                if self._serve_static("/docs.html"):
                    return
            if parsed.path.rstrip("/") in {"/scan", "/pair"}:
                if self._serve_static("/scan.html"):
                    return
            if parsed.path == "/v1/me":
                self._json(200, {"developer": self._require_developer()})
                return
            if parsed.path.startswith(("/v1/developer/customers", "/v1/customers")):
                developer_route = parsed.path.startswith("/v1/developer/")
                prefix = "/v1/developer/customers" if developer_route else "/v1/customers"
                app_id = parse_qs(parsed.query).get("app_id", [""])[0]
                self._customer_scope(app_id, developer_route)
                suffix = unquote(parsed.path[len(prefix):]).strip("/")
                if not suffix:
                    self._json(200, {"customers": self._service().list_customers(app_id)})
                else:
                    self._json(200, self._service().customer_detail(app_id, suffix))
                return
            if parsed.path == "/v1/developer/apps":
                developer = self._require_developer()
                self._json(200, {"applications": self._service().list_developer_applications(developer["id"])})
                return
            if parsed.path == "/v1/developer/licenses":
                developer = self._require_developer()
                query = parse_qs(parsed.query)
                app_id = query.get("app_id", [None])[0]
                self._json(200, {"licenses": self._service().list_developer_licenses(developer["id"], app_id)})
                return
            if parsed.path == "/v1/developer/usage":
                developer = self._require_developer()
                app_id = parse_qs(parsed.query).get("app_id", [""])[0]
                if not app_id:
                    raise LicenseError("APP_REQUIRED", "Choose an application.")
                self._json(200, self._service().usage_summary(app_id, developer["id"]))
                return
            if parsed.path == "/v1/usage":
                app_id = parse_qs(parsed.query).get("app_id", [""])[0]
                if not app_id:
                    raise LicenseError("APP_REQUIRED", "Choose an application.")
                self._require_app_or_admin(app_id)
                self._json(200, self._service().usage_summary(app_id))
                return
            if parsed.path == "/v1/licenses":
                query = parse_qs(parsed.query)
                app_id = query.get("app_id", [None])[0]
                if not app_id:
                    self._require_admin()
                else:
                    self._require_app_or_admin(app_id)
                self._json(200, {"licenses": self._service().list_licenses(app_id)})
                return
            if parsed.path == "/v1/apps":
                self._require_admin()
                self._json(200, {"applications": self._service().list_applications()})
                return
            if self._serve_static(parsed.path):
                return
            raise LicenseError("NOT_FOUND", "The requested route was not found.", 404)
        except LicenseError as error:
            self._error(error)

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            data = self._body()
            if parsed.path == "/v1/auth/register":
                developer = self._service().register_developer(data.get("email", ""), data.get("password", ""), data.get("name", ""))
                login = self._service().login_developer(data.get("email", ""), data.get("password", ""))
                self._json(201, login)
                return
            if parsed.path == "/v1/auth/login":
                self._json(200, self._service().login_developer(data.get("email", ""), data.get("password", "")))
                return
            if parsed.path == "/v1/auth/logout":
                self._service().logout_developer(self._developer_token())
                self._json(200, {"ok": True})
                return
            if parsed.path.startswith(("/v1/developer/customers", "/v1/customers")):
                developer_route = parsed.path.startswith("/v1/developer/")
                prefix = "/v1/developer/customers" if developer_route else "/v1/customers"
                app_id = data.get("app_id", "")
                self._customer_scope(app_id, developer_route)
                suffix = unquote(parsed.path[len(prefix):]).strip("/")
                if not suffix:
                    self._json(201, self._service().create_customer(app_id, data))
                elif suffix.endswith("/update"):
                    self._json(200, self._service().update_customer(app_id, suffix.rsplit("/", 1)[0], data))
                else:
                    raise LicenseError("NOT_FOUND", "Unknown customer action.", 404)
                return
            if parsed.path.startswith(("/v1/developer/license-records/", "/v1/license-records/")):
                developer_route = parsed.path.startswith("/v1/developer/")
                prefix = "/v1/developer/license-records/" if developer_route else "/v1/license-records/"
                app_id = data.get("app_id", "")
                self._customer_scope(app_id, developer_route)
                parts = unquote(parsed.path[len(prefix):]).split("/")
                if len(parts) != 2:
                    raise LicenseError("NOT_FOUND", "Unknown license action.", 404)
                self._json(200, self._service().manage_license_record(app_id, parts[0], parts[1], data))
                return
            if parsed.path == "/v1/developer/apps":
                developer = self._require_developer()
                result = self._service().create_application(data.get("app_id", ""), data.get("name", ""), developer["id"])
                self._json(201, result)
                return
            if parsed.path == "/v1/developer/licenses":
                developer = self._require_developer()
                result = self._service().create_license_for_developer(data.get("app_id", ""), developer["id"], data.get("expires_at"), data.get("metadata"), data.get("customer_id"), data.get("plan", "Standard"))
                self._json(201, result)
                return
            if parsed.path.startswith("/v1/developer/apps/"):
                developer = self._require_developer()
                app_id = parsed.path.split("/v1/developer/apps/", 1)[1].rsplit("/", 1)[0]
                if parsed.path.endswith("/rotate-key"):
                    self._json(200, self._service().rotate_application_key(app_id, developer["id"]))
                    return
                if parsed.path.endswith("/revoke"):
                    self._json(200, self._service().revoke_application(app_id, developer["id"]))
                    return
            if parsed.path == "/v1/pairing/create":
                self._json(201, self._service().create_pairing_session(data.get("app_id", ""), data.get("token", ""), data.get("device_id", "")))
                return
            if parsed.path == "/v1/pairing/status":
                self._json(200, self._service().pairing_status(data.get("app_id", ""), data.get("pairing_id", ""), data.get("token", ""), data.get("device_id", "")))
                return
            if parsed.path == "/v1/pairing/scan":
                self._json(200, self._service().scan_pairing(data.get("pairing_code", ""), data.get("mobile_device_id", "")))
                return
            if parsed.path.startswith("/v1/developer/licenses/"):
                developer = self._require_developer()
                key = parsed.path.split("/v1/developer/licenses/", 1)[1].rsplit("/", 1)[0]
                app_id = data.get("app_id", "")
                if parsed.path.endswith("/reset"):
                    self._json(200, self._service().reset(key, app_id, self._ip(), developer["id"]))
                    return
                if parsed.path.endswith("/revoke"):
                    self._json(200, self._service().revoke(key, app_id, self._ip(), developer["id"]))
                    return
            if parsed.path == "/v1/activate":
                result = self._service().activate(data.get("app_id", ""), data.get("license_key", ""), data.get("device_id", ""), data.get("device_label"), self._ip())
                self._json(200, result)
                return
            if parsed.path == "/v1/validate":
                result = self._service().validate(data.get("app_id", ""), data.get("token", ""), data.get("device_id", ""), self._ip())
                self._json(200, result)
                return
            if parsed.path == "/v1/licenses":
                app_id = data.get("app_id", "")
                self._require_app_or_admin(app_id)
                result = self._service().create_license(data.get("app_id", ""), data.get("expires_at"), data.get("metadata"), data.get("customer_id"), data.get("plan", "Standard"))
                self._json(201, result)
                return
            if parsed.path == "/v1/apps":
                self._require_admin()
                result = self._service().create_application(data.get("app_id", ""), data.get("name", ""))
                self._json(201, result)
                return
            if parsed.path.startswith("/v1/licenses/"):
                app_id = data.get("app_id")
                if app_id:
                    self._require_app_or_admin(app_id)
                else:
                    self._require_admin()
                key = parsed.path.rsplit("/", 1)[-1]
                if parsed.path.endswith("/reset"):
                    key = parsed.path.split("/v1/licenses/", 1)[1].rsplit("/", 1)[0]
                    self._json(200, self._service().reset(key, app_id, self._ip()))
                    return
                if parsed.path.endswith("/revoke"):
                    key = parsed.path.split("/v1/licenses/", 1)[1].rsplit("/", 1)[0]
                    self._json(200, self._service().revoke(key, app_id, self._ip()))
                    return
            raise LicenseError("NOT_FOUND", "The requested route was not found.", 404)
        except LicenseError as error:
            self._error(error)
        except (TypeError, AttributeError) as error:
            self._error(LicenseError("INVALID_REQUEST", str(error)))

    def _developer_page(self) -> None:
        if self._serve_static("/dashboard.html"):
            return
        body = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Developer Dashboard</title><style>
body{font:16px system-ui,sans-serif;max-width:1000px;margin:32px auto;padding:0 20px;color:#18212f;background:#f6f8fb}
main{background:#fff;border:1px solid #dbe2ea;border-radius:12px;padding:24px;box-shadow:0 4px 20px #15223812}
section{border-top:1px solid #e4e9ef;margin-top:22px;padding-top:18px}label{display:block;margin-top:10px;font-weight:600}input,button{font:inherit;padding:9px;border:1px solid #aeb9c7;border-radius:6px}input{width:100%;box-sizing:border-box}button{margin:12px 8px 0 0;background:#1f5eff;color:#fff;border:0;cursor:pointer}.danger{background:#b42318}.muted{color:#5d6b7c}pre{background:#111827;color:#d1fae5;padding:14px;overflow:auto;border-radius:8px;min-height:80px;white-space:pre-wrap}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:700px){.grid{display:block}}
</style></head><body><main><h1>Universal License Platform</h1><p class="muted">Register your application, create customer license keys, and manage activations.</p>
<section id="auth"><h2>Developer login</h2><div class="grid"><div><label>Name<input id="name" placeholder="Your name"></label><label>Email<input id="email" type="email" placeholder="you@example.com"></label><label>Password<input id="password" type="password" placeholder="At least 10 characters"></label><button onclick="register()">Create account</button><button onclick="login()">Log in</button></div><div><p class="muted">Create a developer account to manage only your applications and licenses.</p></div></div></section>
<section id="workspace" hidden><p>Signed in as <strong id="who"></strong> <button onclick="logout()">Log out</button></p>
<h2>Applications</h2><label>Application ID<input id="appId" placeholder="my-application"></label><label>Application name<input id="appName" placeholder="My Application"></label><button onclick="registerApp()">Register application</button><button onclick="loadApps()">Refresh applications</button><pre id="appsOut">No applications loaded.</pre>
<h2>Licenses</h2><label>Application ID<input id="licenseAppId" placeholder="my-application"></label><label>Expiry (optional ISO-8601)<input id="expiry" placeholder="2030-01-01T00:00:00+00:00"></label><button onclick="createLicense()">Create license key</button><button onclick="loadLicenses()">Refresh licenses</button><pre id="licensesOut">No licenses loaded.</pre>
<h2>Application key controls</h2><label>Application ID<input id="controlAppId" placeholder="my-application"></label><button onclick="rotateKey()">Regenerate API key</button><button class="danger" onclick="revokeApp()">Revoke application</button></section>
<pre id="out">Ready.</pre></main><script>
let session=localStorage.getItem('license_platform_session')||'';const out=document.getElementById('out');
const value=(id)=>document.getElementById(id).value.trim();
const text=(id,value)=>{document.getElementById(id).textContent=value};
async function api(path,options={}){options.headers=Object.assign({'Content-Type':'application/json'},options.headers||{});if(session)options.headers.Authorization='Bearer '+session;const r=await fetch(path,options);const data=await r.json();if(!r.ok)throw new Error(data.error?.message||'Request failed');return data}
function show(value){out.textContent=JSON.stringify(value,null,2)}
async function register(){try{const data=await api('/v1/auth/register',{method:'POST',body:JSON.stringify({name:value('name'),email:value('email'),password:document.getElementById('password').value})});session=data.session_token;localStorage.setItem('license_platform_session',session);await openWorkspace()}catch(e){show({error:e.message})}}
async function login(){try{const data=await api('/v1/auth/login',{method:'POST',body:JSON.stringify({email:value('email'),password:document.getElementById('password').value})});session=data.session_token;localStorage.setItem('license_platform_session',session);await openWorkspace()}catch(e){show({error:e.message})}}
async function openWorkspace(){document.getElementById('auth').hidden=true;document.getElementById('workspace').hidden=false;const me=await api('/v1/me');text('who',me.developer.email);await loadApps();await loadLicenses()}
async function logout(){try{await api('/v1/auth/logout',{method:'POST',body:'{}'})}finally{session='';localStorage.removeItem('license_platform_session');location.reload()}}
async function loadApps(){try{show(await api('/v1/developer/apps'))}catch(e){show({error:e.message})}}
async function registerApp(){try{show(await api('/v1/developer/apps',{method:'POST',body:JSON.stringify({app_id:value('appId'),name:value('appName')})}));await loadApps()}catch(e){show({error:e.message})}}
async function createLicense(){try{const body={app_id:value('licenseAppId')};const expires=value('expiry');if(expires)body.expires_at=expires;show(await api('/v1/developer/licenses',{method:'POST',body:JSON.stringify(body)}));await loadLicenses()}catch(e){show({error:e.message})}}
async function loadLicenses(){try{const appId=value('licenseAppId');const id=appId?('?app_id='+encodeURIComponent(appId)):'';text('licensesOut',JSON.stringify(await api('/v1/developer/licenses'+id),null,2))}catch(e){text('licensesOut',JSON.stringify({error:e.message},null,2))}}
async function rotateKey(){try{show(await api('/v1/developer/apps/'+encodeURIComponent(value('controlAppId'))+'/rotate-key',{method:'POST',body:'{}'}))}catch(e){show({error:e.message})}}
async function revokeApp(){if(!confirm('Revoke this application and its API key?'))return;try{show(await api('/v1/developer/apps/'+encodeURIComponent(value('controlAppId'))+'/revoke',{method:'POST',body:'{}'}));await loadApps()}catch(e){show({error:e.message})}}
if(session)openWorkspace().catch(()=>{session='';localStorage.removeItem('license_platform_session')});
</script></body></html>"""
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _admin_page(self) -> None:
        if self._serve_static("/admin.html"):
            return
        body = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>License Platform Admin</title><style>
body{font:16px system-ui,sans-serif;max-width:980px;margin:40px auto;padding:0 20px;color:#18212f;background:#f6f8fb}
main{background:white;border:1px solid #dbe2ea;border-radius:12px;padding:24px;box-shadow:0 4px 20px #15223812}
label{display:block;margin-top:12px;font-weight:600}input,button{font:inherit;padding:9px;border:1px solid #aeb9c7;border-radius:6px}input{width:100%;box-sizing:border-box}button{margin-top:16px;background:#1f5eff;color:white;border:0;cursor:pointer}.muted{color:#5d6b7c}pre{background:#111827;color:#d1fae5;padding:14px;overflow:auto;border-radius:8px;min-height:80px}code{font-family:ui-monospace,monospace}.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:700px){.row{display:block}}
</style></head><body><main><h1>License Platform</h1><p class="muted">Local admin console for creating and inspecting licenses. Keep this endpoint behind HTTPS and authentication in production.</p>
<label>Admin token<input id="token" type="password" placeholder="Bearer token value"></label>
<div class="row"><div><label>Application ID<input id="app" value="my-app"></label></div><div><label>Expiry (optional ISO-8601)<input id="expiry" placeholder="2030-01-01T00:00:00+00:00"></label></div></div>
<button onclick="createApp()">Register application</button> <button onclick="createLicense()">Create one-time license</button> <button onclick="listLicenses()">List licenses</button><pre id="out">Ready.</pre>
<script>
const out=document.getElementById('out'); const auth=()=>({'Authorization':'Bearer '+document.getElementById('token').value,'Content-Type':'application/json'});
async function createApp(){const body={app_id:document.getElementById('app').value,name:document.getElementById('app').value};const r=await fetch('/v1/apps',{method:'POST',headers:auth(),body:JSON.stringify(body)});out.textContent=JSON.stringify(await r.json(),null,2)}
async function createLicense(){const body={app_id:document.getElementById('app').value};const exp=document.getElementById('expiry').value;if(exp)body.expires_at=exp;const r=await fetch('/v1/licenses',{method:'POST',headers:auth(),body:JSON.stringify(body)});out.textContent=JSON.stringify(await r.json(),null,2)}
async function listLicenses(){const r=await fetch('/v1/licenses?app_id='+encodeURIComponent(document.getElementById('app').value),{headers:auth()});out.textContent=JSON.stringify(await r.json(),null,2)}
</script></main></body></html>"""
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def create_server(
    db_path: str,
    signing_secret: str,
    admin_token: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    static_root: str | None = None,
    cors_origins: str = "",
) -> ThreadingHTTPServer:
    if not admin_token or len(admin_token) < 16:
        raise ValueError("admin_token must contain at least 16 characters")
    server = ThreadingHTTPServer((host, port), LicenseRequestHandler)
    server.license_service = LicenseService(db_path, signing_secret)  # type: ignore[attr-defined]
    server.admin_token = admin_token  # type: ignore[attr-defined]
    server.static_root = static_root  # type: ignore[attr-defined]
    server.cors_origins = {origin.strip() for origin in cors_origins.split(",") if origin.strip()}  # type: ignore[attr-defined]
    return server
