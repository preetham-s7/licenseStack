"""Core license storage, activation, and signed-token logic.

The module intentionally has no web-server dependencies.  It can be embedded
in another service or used by the included HTTP adapter.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import string
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
APP_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical_key(value: str) -> str:
    return "".join(value.upper().split())


def _key_hash(key: str, secret: bytes) -> str:
    return hmac.new(secret, _canonical_key(key).encode("utf-8"), hashlib.sha256).hexdigest()


def _credential_hash(value: str, secret: bytes) -> str:
    return hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()


def _device_hash(device_id: str, secret: bytes) -> str:
    return hmac.new(secret, device_id.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def _signed_token(payload: dict[str, Any], secret: bytes) -> str:
    header = {"alg": "HS256", "typ": "LIC1"}
    encoded_header = _b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_payload = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    message = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = _b64(hmac.new(secret, message, hashlib.sha256).digest())
    return f"{encoded_header}.{encoded_payload}.{signature}"


def _read_signed_token(token: str, secret: bytes) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise LicenseError("INVALID_TOKEN", "The license token format is invalid.", 401)
    message = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = _b64(hmac.new(secret, message, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise LicenseError("INVALID_TOKEN", "The license token signature is invalid.", 401)
    try:
        header = json.loads(_unb64(parts[0]))
        payload = json.loads(_unb64(parts[1]))
    except (ValueError, UnicodeError) as exc:
        raise LicenseError("INVALID_TOKEN", "The license token is not valid JSON.", 401) from exc
    if header != {"alg": "HS256", "typ": "LIC1"}:
        raise LicenseError("INVALID_TOKEN", "The license token header is invalid.", 401)
    if payload.get("exp") is not None and int(payload["exp"]) < int(time.time()):
        raise LicenseError("LICENSE_EXPIRED", "The license token has expired.", 403)
    return payload


class LicenseError(Exception):
    """A user-facing licensing error with a stable API error code."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class LicenseRecord:
    id: str
    app_id: str
    key_prefix: str
    status: str
    created_at: str
    activated_at: Optional[str]
    expires_at: Optional[str]
    device_label: Optional[str]
    last_seen_at: Optional[str]


class LicenseService:
    """SQLite-backed license service.

    Raw license keys are never stored.  The key is returned only when created;
    later operations use a keyed digest.  Device identifiers are also stored as
    keyed digests so the service does not retain raw hardware identifiers.
    """

    def __init__(self, db_path: str | Path, signing_secret: str):
        if not signing_secret or len(signing_secret) < 16:
            raise ValueError("signing_secret must contain at least 16 characters")
        self.db_path = str(db_path)
        self.secret = signing_secret.encode("utf-8")
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS applications (
                    app_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL UNIQUE,
                    api_key_prefix TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    created_at TEXT NOT NULL,
                    developer_id TEXT
                );
                CREATE TABLE IF NOT EXISTS developers (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS developer_sessions (
                    token_hash TEXT PRIMARY KEY,
                    developer_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    FOREIGN KEY(developer_id) REFERENCES developers(id)
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_developer ON developer_sessions(developer_id);
                CREATE TABLE IF NOT EXISTS licenses (
                    id TEXT PRIMARY KEY,
                    app_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    key_prefix TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('unused', 'active', 'revoked')),
                    created_at TEXT NOT NULL,
                    activated_at TEXT,
                    expires_at TEXT,
                    device_hash TEXT,
                    device_label TEXT,
                    last_seen_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_licenses_app_id ON licenses(app_id);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_id TEXT,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    device_hash TEXT,
                    created_at TEXT NOT NULL,
                    details_json TEXT,
                    FOREIGN KEY(license_id) REFERENCES licenses(id)
                );
                """
            )
            application_columns = {row["name"] for row in connection.execute("PRAGMA table_info(applications)").fetchall()}
            if "developer_id" not in application_columns:
                connection.execute("ALTER TABLE applications ADD COLUMN developer_id TEXT")

    @staticmethod
    def _developer_public(row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "email": row["email"], "name": row["name"]}

    @staticmethod
    def _password_hash(password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return "scrypt$16384$8$1$" + _b64(salt) + "$" + _b64(digest)

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, n, r, p, salt, expected = encoded.split("$")
            if algorithm != "scrypt":
                return False
            digest = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r), p=int(p))
            return hmac.compare_digest(_b64(digest), expected)
        except (ValueError, TypeError):
            return False

    def register_developer(self, email: str, password: str, name: str) -> dict[str, Any]:
        email = email.strip().lower() if isinstance(email, str) else ""
        name = name.strip() if isinstance(name, str) else ""
        if not EMAIL_PATTERN.fullmatch(email):
            raise LicenseError("INVALID_EMAIL", "Enter a valid email address.")
        if len(password) < 10:
            raise LicenseError("WEAK_PASSWORD", "Password must contain at least 10 characters.")
        if not name or len(name) > 120:
            raise LicenseError("INVALID_NAME", "Name is required and must be at most 120 characters.")
        developer_id = str(uuid.uuid4())
        created_at = utc_now()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO developers(id, email, name, password_hash, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)",
                    (developer_id, email, name, self._password_hash(password), created_at),
                )
            return {"id": developer_id, "email": email, "name": name}
        except sqlite3.IntegrityError as exc:
            raise LicenseError("EMAIL_EXISTS", "An account with this email already exists.", 409) from exc

    def login_developer(self, email: str, password: str) -> dict[str, Any]:
        email = email.strip().lower() if isinstance(email, str) else ""
        with self._session() as connection:
            row = connection.execute("SELECT * FROM developers WHERE email=?", (email,)).fetchone()
            if row is None or row["status"] != "active" or not self._verify_password(password, row["password_hash"]):
                raise LicenseError("INVALID_LOGIN", "Email or password is incorrect.", 401)
            token = secrets.token_urlsafe(32)
            now = int(time.time())
            connection.execute(
                "INSERT INTO developer_sessions(token_hash, developer_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (_credential_hash(token, self.secret), row["id"], now, now + 7 * 24 * 60 * 60),
            )
            return {"session_token": token, "expires_at": now + 7 * 24 * 60 * 60, "developer": self._developer_public(row)}

    def authenticate_developer(self, token: str) -> Optional[dict[str, Any]]:
        if not isinstance(token, str) or not token:
            return None
        with self._session() as connection:
            row = connection.execute(
                "SELECT d.* FROM developer_sessions s JOIN developers d ON d.id=s.developer_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?",
                (_credential_hash(token, self.secret), int(time.time())),
            ).fetchone()
            return self._developer_public(row) if row else None

    def logout_developer(self, token: str) -> None:
        with self._session() as connection:
            connection.execute("UPDATE developer_sessions SET revoked_at=? WHERE token_hash=?", (int(time.time()), _credential_hash(token, self.secret)))

    def _application_owned(self, connection: sqlite3.Connection, app_id: str, developer_id: str) -> bool:
        row = connection.execute("SELECT 1 FROM applications WHERE app_id=? AND developer_id=? AND status='active'", (app_id, developer_id)).fetchone()
        return row is not None

    def assert_application_owner(self, app_id: str, developer_id: str) -> None:
        with self._session() as connection:
            if not self._application_owned(connection, app_id, developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)

    @staticmethod
    def _validate_app_id(app_id: str) -> None:
        if not isinstance(app_id, str) or not APP_ID_PATTERN.fullmatch(app_id):
            raise LicenseError("INVALID_APP_ID", "app_id must use lowercase letters, numbers, dot, underscore, or hyphen.")

    def _audit(self, connection: sqlite3.Connection, license_id: Optional[str], event_type: str,
               ip_address: Optional[str], device_hash: Optional[str], details: Optional[dict[str, Any]] = None) -> None:
        connection.execute(
            "INSERT INTO audit_events(license_id, event_type, ip_address, device_hash, created_at, details_json) VALUES (?, ?, ?, ?, ?, ?)",
            (license_id, event_type, ip_address, device_hash, utc_now(), json.dumps(details or {}, sort_keys=True)),
        )

    @staticmethod
    def generate_key() -> str:
        groups = ["".join(secrets.choice(KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
        return "LIC-" + "-".join(groups)

    @staticmethod
    def generate_api_key() -> str:
        return "lp_app_" + secrets.token_urlsafe(32)

    def create_application(self, app_id: str, name: str, developer_id: Optional[str] = None) -> dict[str, Any]:
        self._validate_app_id(app_id)
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 160:
            raise LicenseError("INVALID_APP_NAME", "name is required and must be at most 160 characters.")
        api_key = self.generate_api_key()
        created_at = utc_now()
        try:
            with self._session() as connection:
                connection.execute(
                    "INSERT INTO applications(app_id, name, api_key_hash, api_key_prefix, status, created_at, developer_id) VALUES (?, ?, ?, ?, 'active', ?, ?)",
                    (app_id, name.strip(), _key_hash(api_key, self.secret), api_key[:15], created_at, developer_id),
                )
            return {"app_id": app_id, "name": name.strip(), "api_key": api_key, "status": "active", "created_at": created_at}
        except sqlite3.IntegrityError as exc:
            raise LicenseError("APP_ID_EXISTS", "An application with this app_id already exists.", 409) from exc

    def authenticate_application(self, app_id: str, api_key: str) -> bool:
        if not isinstance(app_id, str) or not isinstance(api_key, str) or not api_key:
            return False
        with self._session() as connection:
            row = connection.execute("SELECT api_key_hash, status FROM applications WHERE app_id=?", (app_id,)).fetchone()
            return bool(row and row["status"] == "active" and hmac.compare_digest(row["api_key_hash"], _key_hash(api_key, self.secret)))

    def list_applications(self) -> list[dict[str, Any]]:
        with self._session() as connection:
            rows = connection.execute("SELECT app_id, name, api_key_prefix, status, created_at FROM applications ORDER BY created_at DESC").fetchall()
            return [dict(row) for row in rows]

    def list_developer_applications(self, developer_id: str) -> list[dict[str, Any]]:
        with self._session() as connection:
            rows = connection.execute("SELECT app_id, name, api_key_prefix, status, created_at FROM applications WHERE developer_id=? ORDER BY created_at DESC", (developer_id,)).fetchall()
            return [dict(row) for row in rows]

    def rotate_application_key(self, app_id: str, developer_id: str) -> dict[str, Any]:
        new_key = self.generate_api_key()
        with self._session() as connection:
            if not self._application_owned(connection, app_id, developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            connection.execute("UPDATE applications SET api_key_hash=?, api_key_prefix=? WHERE app_id=?", (_key_hash(new_key, self.secret), new_key[:15], app_id))
            return {"app_id": app_id, "api_key": new_key, "status": "active"}

    def revoke_application(self, app_id: str, developer_id: str) -> dict[str, Any]:
        with self._session() as connection:
            if not self._application_owned(connection, app_id, developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            connection.execute("UPDATE applications SET status='revoked' WHERE app_id=?", (app_id,))
            return {"app_id": app_id, "status": "revoked"}

    @staticmethod
    def _expiry_timestamp(expires_at: Optional[str]) -> Optional[int]:
        if not expires_at:
            return None
        try:
            return int(datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp())
        except ValueError as exc:
            raise LicenseError("INVALID_EXPIRY", "expires_at must be an ISO-8601 timestamp.") from exc

    def create_license(self, app_id: str, expires_at: Optional[str] = None,
                       metadata: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        self._validate_app_id(app_id)
        expiry = self._expiry_timestamp(expires_at)
        if expiry is not None and expiry <= int(time.time()):
            raise LicenseError("INVALID_EXPIRY", "expires_at must be in the future.")
        created_at = utc_now()
        for _ in range(5):
            key = self.generate_key()
            license_id = str(uuid.uuid4())
            try:
                with self._session() as connection:
                    connection.execute(
                        "INSERT INTO licenses(id, app_id, key_hash, key_prefix, status, created_at, expires_at) VALUES (?, ?, ?, ?, 'unused', ?, ?)",
                        (license_id, app_id, _key_hash(key, self.secret), key[:8], created_at, expires_at),
                    )
                    self._audit(connection, license_id, "created", None, None, metadata)
                return {"id": license_id, "app_id": app_id, "license_key": key, "status": "unused", "created_at": created_at, "expires_at": expires_at}
            except sqlite3.IntegrityError:
                continue
        raise LicenseError("KEY_GENERATION_FAILED", "Could not generate a unique license key.", 500)

    def create_license_for_developer(self, app_id: str, developer_id: str, expires_at: Optional[str] = None,
                                     metadata: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        self.assert_application_owner(app_id, developer_id)
        return self.create_license(app_id, expires_at, metadata)

    def _find_by_key(self, connection: sqlite3.Connection, license_key: str) -> Optional[sqlite3.Row]:
        return connection.execute("SELECT * FROM licenses WHERE key_hash = ?", (_key_hash(license_key, self.secret),)).fetchone()

    def activate(self, app_id: str, license_key: str, device_id: str,
                 device_label: Optional[str] = None, ip_address: Optional[str] = None) -> dict[str, Any]:
        if not license_key or not device_id:
            raise LicenseError("INVALID_ACTIVATION", "license_key and device_id are required.")
        hashed_device = _device_hash(device_id, self.secret)
        with self._session() as connection:
            record = self._find_by_key(connection, license_key)
            if record is None or record["app_id"] != app_id:
                self._audit(connection, None, "activation_rejected", ip_address, hashed_device, {"reason": "unknown_key"})
                raise LicenseError("INVALID_LICENSE", "The license key is invalid for this application.", 403)
            if record["expires_at"] and self._expiry_timestamp(record["expires_at"]) <= int(time.time()):
                self._audit(connection, record["id"], "activation_rejected", ip_address, hashed_device, {"reason": "expired"})
                raise LicenseError("LICENSE_EXPIRED", "The license has expired.", 403)
            if record["status"] == "revoked":
                raise LicenseError("LICENSE_REVOKED", "The license has been revoked.", 403)
            if record["status"] == "active" and record["device_hash"] != hashed_device:
                self._audit(connection, record["id"], "activation_rejected", ip_address, hashed_device, {"reason": "different_device"})
                raise LicenseError("LICENSE_BOUND", "This license is already activated on another computer.", 409)
            now = utc_now()
            if record["status"] == "unused":
                connection.execute(
                    "UPDATE licenses SET status='active', activated_at=?, device_hash=?, device_label=?, last_seen_at=? WHERE id=?",
                    (now, hashed_device, device_label, now, record["id"]),
                )
                event = "activated"
            else:
                connection.execute("UPDATE licenses SET last_seen_at=? WHERE id=?", (now, record["id"]))
                event = "activation_repeated"
            self._audit(connection, record["id"], event, ip_address, hashed_device)
            payload = {
                "license_id": record["id"],
                "app_id": app_id,
                "device_hash": hashed_device,
                "iat": int(time.time()),
                "exp": self._expiry_timestamp(record["expires_at"]),
            }
            token = _signed_token(payload, self.secret)
            return {"license_id": record["id"], "app_id": app_id, "status": "active", "token": token, "expires_at": record["expires_at"]}

    def validate(self, app_id: str, token: str, device_id: str,
                 ip_address: Optional[str] = None) -> dict[str, Any]:
        payload = _read_signed_token(token, self.secret)
        if payload.get("app_id") != app_id or payload.get("device_hash") != _device_hash(device_id, self.secret):
            raise LicenseError("DEVICE_MISMATCH", "The token is not valid for this application or computer.", 403)
        with self._session() as connection:
            record = connection.execute("SELECT * FROM licenses WHERE id=?", (payload.get("license_id"),)).fetchone()
            if record is None or record["app_id"] != app_id:
                raise LicenseError("INVALID_LICENSE", "The license no longer exists.", 403)
            if record["status"] != "active":
                raise LicenseError("LICENSE_INACTIVE", "The license is not active.", 403)
            if record["device_hash"] != payload["device_hash"]:
                raise LicenseError("DEVICE_MISMATCH", "The license is bound to another computer.", 403)
            if record["expires_at"] and self._expiry_timestamp(record["expires_at"]) <= int(time.time()):
                raise LicenseError("LICENSE_EXPIRED", "The license has expired.", 403)
            now = utc_now()
            connection.execute("UPDATE licenses SET last_seen_at=? WHERE id=?", (now, record["id"]))
            self._audit(connection, record["id"], "validated", ip_address, payload["device_hash"])
            return {"valid": True, "license_id": record["id"], "app_id": app_id, "expires_at": record["expires_at"]}

    def reset(self, license_key: str, app_id: Optional[str] = None, ip_address: Optional[str] = None, developer_id: Optional[str] = None) -> dict[str, Any]:
        with self._session() as connection:
            record = self._find_by_key(connection, license_key)
            if record is None:
                raise LicenseError("INVALID_LICENSE", "The license key was not found.", 404)
            if app_id and record["app_id"] != app_id:
                raise LicenseError("APP_ACCESS_DENIED", "This license belongs to another application.", 403)
            if developer_id and not self._application_owned(connection, record["app_id"], developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            connection.execute("UPDATE licenses SET status='unused', activated_at=NULL, device_hash=NULL, device_label=NULL, last_seen_at=NULL WHERE id=?", (record["id"],))
            self._audit(connection, record["id"], "reset", ip_address, None)
            return {"license_id": record["id"], "status": "unused"}

    def revoke(self, license_key: str, app_id: Optional[str] = None, ip_address: Optional[str] = None, developer_id: Optional[str] = None) -> dict[str, Any]:
        with self._session() as connection:
            record = self._find_by_key(connection, license_key)
            if record is None:
                raise LicenseError("INVALID_LICENSE", "The license key was not found.", 404)
            if app_id and record["app_id"] != app_id:
                raise LicenseError("APP_ACCESS_DENIED", "This license belongs to another application.", 403)
            if developer_id and not self._application_owned(connection, record["app_id"], developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            connection.execute("UPDATE licenses SET status='revoked' WHERE id=?", (record["id"],))
            self._audit(connection, record["id"], "revoked", ip_address, record["device_hash"])
            return {"license_id": record["id"], "status": "revoked"}

    def list_licenses(self, app_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._session() as connection:
            if app_id:
                rows = connection.execute("SELECT * FROM licenses WHERE app_id=? ORDER BY created_at DESC", (app_id,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
            return [
                {"id": row["id"], "app_id": row["app_id"], "key_prefix": row["key_prefix"], "status": row["status"],
                 "created_at": row["created_at"], "activated_at": row["activated_at"], "expires_at": row["expires_at"],
                 "device_label": row["device_label"], "last_seen_at": row["last_seen_at"]}
                for row in rows
            ]

    def list_developer_licenses(self, developer_id: str, app_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._session() as connection:
            if app_id:
                if not self._application_owned(connection, app_id, developer_id):
                    raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
                rows = connection.execute("SELECT * FROM licenses WHERE app_id=? ORDER BY created_at DESC", (app_id,)).fetchall()
            else:
                rows = connection.execute("SELECT l.* FROM licenses l JOIN applications a ON a.app_id=l.app_id WHERE a.developer_id=? ORDER BY l.created_at DESC", (developer_id,)).fetchall()
            return [
                {"id": row["id"], "app_id": row["app_id"], "key_prefix": row["key_prefix"], "status": row["status"],
                 "created_at": row["created_at"], "activated_at": row["activated_at"], "expires_at": row["expires_at"],
                 "device_label": row["device_label"], "last_seen_at": row["last_seen_at"]}
                for row in rows
            ]
