"""Run the standalone license platform locally or in a container."""

from __future__ import annotations

import os
from pathlib import Path

from license_platform.http import create_server


def main() -> None:
    server = create_server(
        db_path=os.environ.get("LICENSE_DB_PATH", "data/licenses.sqlite3"),
        signing_secret=os.environ.get("LICENSE_SIGNING_SECRET", "local-development-signing-secret"),
        admin_token=os.environ.get("LICENSE_ADMIN_TOKEN", "local-development-admin-token"),
        host=os.environ.get("LICENSE_HOST", "127.0.0.1"),
        port=int(os.environ.get("LICENSE_PORT", "8080")),
        static_root=os.environ.get("LICENSE_WEB_ROOT", str(Path(__file__).resolve().parent / "site" / "dist")),
    )
    print(f"License Platform listening on http://{server.server_address[0]}:{server.server_address[1]}")
    print("Admin console: /admin")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping license platform.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
