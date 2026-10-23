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
