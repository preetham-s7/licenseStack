# License Platform

Standalone, universal license activation service for desktop software. Any application can integrate through the language-neutral REST API or an SDK.

## What is implemented

- One-time license-key generation. Raw keys are returned at creation and are never stored.
- First-device activation using an app-scoped machine fingerprint.
- Repeated activation on the original computer is idempotent.
- Activation on another computer is rejected with `LICENSE_BOUND`.
- Signed license tokens and online validation.
- Admin operations to list, reset, and revoke licenses.
- A minimal browser admin console at `/admin`.
- Platform-admin application registration with one-time developer API keys.
- A dependency-free Python client SDK under `sdk/python`.
- SQLite persistence and an audit trail.

## Run locally

```powershell
$env:LICENSE_ADMIN_TOKEN = "local-admin-token-change-this"
$env:LICENSE_SIGNING_SECRET = "local-signing-secret-change-this"
python run_server.py
```

Open `http://127.0.0.1:8080/admin`, enter the admin token, register an application, and create licenses for that application.
Developers use `http://127.0.0.1:8080/dashboard` to create an account, register their own application, rotate API keys, and manage licenses.

For production, put the server behind HTTPS, use long random secrets, restrict the admin route, and back up the database. The default development values are intentionally not production credentials.

## API summary

- `POST /v1/apps` — platform admin: register an application; the response contains its one-time developer API key.
- `GET /v1/apps` — platform admin: list registered applications; secret keys are not returned.
- `POST /v1/licenses` — platform admin or application API key: create a license; the response contains the one-time customer key.
- `GET /v1/licenses?app_id=your-app` — platform admin or that application's API key: list license metadata.
- `POST /v1/activate` — client: bind a key to the first device.
- `POST /v1/validate` — client: validate a signed token for its device.
- `POST /v1/licenses/{key}/reset` — admin: release a key for a computer replacement.
- `POST /v1/licenses/{key}/revoke` — admin: permanently disable a key.
- `GET /health` — service health check.

See [docs/API.md](docs/API.md) for request and response examples.
See [DEPLOYMENT.md](DEPLOYMENT.md) for container and HTTPS deployment.

## Universal developer integration

The platform owner registers an application with `POST /v1/apps` and gives the developer the returned `app_id` and `api_key`. The developer uses `X-API-Key` for license-management calls. The secret API key must remain on the developer's server or admin tooling and must not be embedded in a downloadable desktop application. A desktop application uses the public `app_id` plus its customer's one-time license key for `/v1/activate` and `/v1/validate`.

The service deliberately does not use an IP address as the device identity because IP addresses change frequently.

## Verification

```powershell
python -m unittest discover -v
```
