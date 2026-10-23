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
- Developer sign-in and account registration with a unified light/dark workspace.
- Application switcher, one-time API-key delivery, and key regeneration.
- Searchable customer profiles with plan, expiry, device information, and activity.
- Customer license creation, revoke/restore access, and device reset by record ID.

## Run locally

```powershell
$env:LICENSE_ADMIN_TOKEN = "local-admin-token-change-this"
$env:LICENSE_SIGNING_SECRET = "local-signing-secret-change-this"
python run_server.py
```

Open `http://127.0.0.1:8080/admin`, enter the admin token, register an application, and create licenses for that application.
Developers use `http://127.0.0.1:8080/dashboard` to create an account, register their own application, rotate API keys, and manage licenses.

### Developer workflow

1. Open `/signup` and create an account, or sign in at `/login`.
2. Select **Register application**, enter a product name and unique application ID, and save the API key shown in the dialog.
3. Select **Customers → Add customer**, enter their name and email, then open their profile.
4. Select **Issue license**, choose a plan and optional expiry, and save the customer license key.
5. Send the license key to the customer for device activation. Your server uses the application's API key; customer software uses its license key.
6. Click a customer name to edit their profile, change a license's plan/expiry, revoke or restore access, or reset its device. Access history records these changes.

The API & integration page contains the app ID, local API URL, a customer-list request example, and key regeneration controls. See `/docs` or `docs/API.md` for endpoint details. This local version does not send customer emails automatically.

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
