# Public HTTPS deployment

The application is ready to package, but it cannot be published automatically
without a hosting provider, domain name, and deployment credentials. This file
is the provider-neutral production procedure.

## Required production values

Set long random values for:

```text
LICENSE_ADMIN_TOKEN
LICENSE_SIGNING_SECRET
LICENSE_DB_PATH=/app/data/licenses.sqlite3
LICENSE_HOST=0.0.0.0
LICENSE_PORT=8080
```

Do not use the development defaults from `run_server.py` in production.

## Docker

Build and run the service on a VPS or container host:

```bash
docker build -t universal-license-platform .
docker volume create license-platform-data
docker run -d --name license-platform \
  -p 127.0.0.1:8080:8080 \
  -v license-platform-data:/app/data \
  -e LICENSE_ADMIN_TOKEN='replace-with-random-admin-token' \
  -e LICENSE_SIGNING_SECRET='replace-with-random-signing-secret' \
  universal-license-platform
```

Keep the data volume backed up. The database contains license state and audit
records.

## HTTPS reverse proxy

Point a DNS record such as `licenses.example.com` at the server and put Caddy,
Nginx, or a managed HTTPS load balancer in front of port 8080. A minimal Caddy
configuration is:

```text
licenses.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy will obtain and renew the TLS certificate. The public API URL becomes:

```text
https://licenses.example.com
```

Developers use that URL in the SDK or REST API. The dashboards are:

- `https://licenses.example.com/dashboard` — developer accounts and application management
- `https://licenses.example.com/admin` — platform-owner administration

## Render deployment

The repository includes `render.yaml` for the API service. In Render, choose
**New → Blueprint**, connect this GitHub repository, and apply the blueprint.
It creates a Docker web service with a persistent disk at `/app/data`, a
health check at `/health`, generated signing/admin secrets, and CORS for the
Vercel frontend. Persistent disks require a paid Render service plan.

After Render creates the service, copy its HTTPS URL into
`site/dist/runtime-config.js`:

```js
window.LICENSE_PLATFORM_URL = "https://your-service.onrender.com";
```

Commit and redeploy the frontend after setting that URL. Then verify:

```text
https://your-service.onrender.com/health
```

It must return `{"ok":true,"service":"license-platform"}` before testing
developer login, licenses, or QR activation from the Vercel site.

## Production checklist

- Use HTTPS only; do not expose the raw HTTP port publicly.
- Replace both development secrets.
- Restrict `/admin` access at the proxy or network layer.
- Back up `/app/data/licenses.sqlite3`.
- Add rate limiting and monitoring before public launch.
- Store developer API keys outside downloadable desktop applications.
