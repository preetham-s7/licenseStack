# License Platform API

All JSON endpoints use `Content-Type: application/json`. Admin endpoints require:

```text
Authorization: Bearer <LICENSE_ADMIN_TOKEN>
```

Application license-management endpoints can instead use the application's secret:

```text
X-API-Key: <application-api-key>
```

An application API key is restricted to its own `app_id`.

## Developer dashboard and customers

Open `/signup` to create a developer account or `/login` to sign in. The dashboard guides you through registering an application, saving its API key, adding customers, and issuing licenses. Click a customer name to view their licenses, change a plan or expiry, revoke or restore access, reset a device, and see activity.

The API key authenticates your server; it does not contain customer data. Customer software uses a separate license key for device activation. Keep management API keys on your server.

These customer routes require `X-API-Key` for the selected application (or the admin token):

| Method | Route | Input |
| --- | --- | --- |
| GET | `/v1/customers?app_id=your-app` | List customer profiles and access counts |
| POST | `/v1/customers` | `app_id`, `name`, `email`, optional `notes` |
| GET | `/v1/customers/{id}?app_id=your-app` | Customer, licenses, and recent activity |
| POST | `/v1/customers/{id}/update` | `app_id`, `name`, `email`, `notes` |
| POST | `/v1/licenses` | `app_id`, optional `customer_id`, `plan`, `expires_at` |
| POST | `/v1/license-records/{id}/update` | `app_id`, `plan`, `expires_at` (null removes expiry) |
| POST | `/v1/license-records/{id}/revoke` | `app_id` |
| POST | `/v1/license-records/{id}/restore` | `app_id` |
| POST | `/v1/license-records/{id}/reset` | `app_id` |
| GET | `/v1/usage?app_id=your-app` | Activation, validation, and access activity metrics |

Developer-session equivalents use `/v1/developer/customers` and `/v1/developer/license-records`, with `Authorization: Bearer <session_token>`. Every operation checks application ownership. Customer IDs cannot be used across applications.

Changing a plan or expiry invalidates previous tokens; the same device can activate again to refresh its token. Revocation stops the next online validation and activation. Restore and device reset clear the old binding and invalidate old tokens, allowing a new activation. Disabling an application stops both management API-key access and customer activation/validation. Raw API keys and customer license keys are returned only at creation or key regeneration, never in lists.

`GET /v1/usage?app_id=your-app` returns real totals, last-30-day totals, and recent audit events. Use `X-API-Key` from your server, or use `/v1/developer/usage` with the developer session token in the dashboard.

## Register an application

```http
POST /v1/apps
Authorization: Bearer ...
Content-Type: application/json

{"app_id":"vendor-tool","name":"Vendor Tool"}
```

The response contains `api_key` exactly once. Store it securely. It is not returned by the list endpoint.

## Create a license

```http
POST /v1/licenses
Authorization: Bearer ...
Content-Type: application/json

{"app_id":"vendor-tool","expires_at":null}
```

The `license_key` appears only in this response. Store it securely. The request can use either the platform admin token or the registered application's `X-API-Key`.

## Mobile QR pairing

After activation, the desktop software can create a short-lived QR challenge using the signed activation token:

```http
POST /v1/pairing/create
Content-Type: application/json

{"app_id":"vendor-tool","token":"<signed-token>","device_id":"app-scoped-fingerprint"}
```

The response contains `scan_path` and `pairing_code`. Encode `scan_path` (or the pairing code) as a QR image and show it in the customer software. The customer opens `/scan` on their phone and scans it. The first valid scan returns `status: "activated"`; later scans return `status: "already_activated"` and do not create another activation.

The desktop software can poll the result with `POST /v1/pairing/status`. QR codes expire after ten minutes and contain no API key or raw license key.

## Activate

```http
POST /v1/activate

{"app_id":"vendor-tool","license_key":"LIC-ABCD-EFGH-IJKL-MNOP","device_id":"app-scoped-fingerprint","device_label":"Customer computer"}
```

The first successful request changes the license from `unused` to `active`. The same device can repeat the request. A different device receives HTTP `409` with error code `LICENSE_BOUND`.

## Validate

```http
POST /v1/validate

{"app_id":"vendor-tool","token":"<signed-token>","device_id":"app-scoped-fingerprint"}
```

The server verifies the token signature, application ID, device binding, status, and expiry.

## Management

```http
GET  /v1/licenses?app_id=vendor-tool
POST /v1/licenses/{license-key}/reset
POST /v1/licenses/{license-key}/revoke
```

Reset is for an approved computer replacement. Revoke is for permanently disabling a license.
