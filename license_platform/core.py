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
from datetime import datetime, timedelta, timezone
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
                CREATE TABLE IF NOT EXISTS pairing_sessions (
                    id TEXT PRIMARY KEY,
                    app_id TEXT NOT NULL,
                    license_id TEXT NOT NULL,
                    desktop_device_hash TEXT NOT NULL,
                    code_hash TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'paired', 'expired')),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    paired_at TEXT,
                    mobile_device_hash TEXT,
                    FOREIGN KEY(license_id) REFERENCES licenses(id)
                );
                CREATE INDEX IF NOT EXISTS idx_pairing_license ON pairing_sessions(license_id);
                """
            )
            application_columns = {row["name"] for row in connection.execute("PRAGMA table_info(applications)").fetchall()}
            if "developer_id" not in application_columns:
                connection.execute("ALTER TABLE applications ADD COLUMN developer_id TEXT")
            connection.execute("""CREATE TABLE IF NOT EXISTS customers (
                id TEXT PRIMARY KEY, app_id TEXT NOT NULL, name TEXT NOT NULL,
                email TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                UNIQUE(app_id, email), FOREIGN KEY(app_id) REFERENCES applications(app_id))""")
            license_columns = {row["name"] for row in connection.execute("PRAGMA table_info(licenses)")}
            for column, definition in {"customer_id": "TEXT", "plan": "TEXT NOT NULL DEFAULT 'Standard'",
                                       "version": "INTEGER NOT NULL DEFAULT 0", "mobile_device_hash": "TEXT",
                                       "paired_at": "TEXT"}.items():
                if column not in license_columns:
                    connection.execute(f"ALTER TABLE licenses ADD COLUMN {column} {definition}")

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
                       metadata: Optional[dict[str, Any]] = None, customer_id: Optional[str] = None,
                       plan: str = "Standard") -> dict[str, Any]:
        self._validate_app_id(app_id)
        if not isinstance(plan, str) or not plan.strip() or len(plan) > 80:
            raise LicenseError("INVALID_PLAN", "Plan must contain 1 to 80 characters.")
        expiry = self._expiry_timestamp(expires_at)
        if expiry is not None and expiry <= int(time.time()):
            raise LicenseError("INVALID_EXPIRY", "expires_at must be in the future.")
        created_at = utc_now()
        for _ in range(5):
            key = self.generate_key()
            license_id = str(uuid.uuid4())
            try:
                with self._session() as connection:
                    if customer_id and not connection.execute("SELECT 1 FROM customers WHERE id=? AND app_id=?", (customer_id, app_id)).fetchone():
                        raise LicenseError("CUSTOMER_NOT_FOUND", "Customer does not belong to this application.", 404)
                    connection.execute(
                        "INSERT INTO licenses(id, app_id, key_hash, key_prefix, status, created_at, expires_at, customer_id, plan) VALUES (?, ?, ?, ?, 'unused', ?, ?, ?, ?)",
                        (license_id, app_id, _key_hash(key, self.secret), key[:8], created_at, expires_at, customer_id, plan.strip()),
                    )
                    self._audit(connection, license_id, "created", None, None, metadata)
                return {"id": license_id, "app_id": app_id, "license_key": key, "status": "unused", "created_at": created_at, "expires_at": expires_at, "customer_id": customer_id, "plan": plan.strip()}
            except sqlite3.IntegrityError:
                continue
        raise LicenseError("KEY_GENERATION_FAILED", "Could not generate a unique license key.", 500)

    def create_license_for_developer(self, app_id: str, developer_id: str, expires_at: Optional[str] = None,
                                     metadata: Optional[dict[str, Any]] = None, customer_id: Optional[str] = None,
                                     plan: str = "Standard") -> dict[str, Any]:
        self.assert_application_owner(app_id, developer_id)
        return self.create_license(app_id, expires_at, metadata, customer_id, plan)

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
            app = connection.execute("SELECT status FROM applications WHERE app_id=?", (app_id,)).fetchone()
            if app and app["status"] != "active":
                raise LicenseError("APP_REVOKED", "This application is disabled.", 403)
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
                "version": record["version"],
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
            app = connection.execute("SELECT status FROM applications WHERE app_id=?", (app_id,)).fetchone()
            if app and app["status"] != "active":
                raise LicenseError("APP_REVOKED", "This application is disabled.", 403)
            if payload.get("version", 0) != record["version"]:
                raise LicenseError("TOKEN_OUTDATED", "Access changed. Activate again to refresh this license.", 403)
            if record["status"] != "active":
                raise LicenseError("LICENSE_INACTIVE", "The license is not active.", 403)
            if record["device_hash"] != payload["device_hash"]:
                raise LicenseError("DEVICE_MISMATCH", "The license is bound to another computer.", 403)
            if record["expires_at"] and self._expiry_timestamp(record["expires_at"]) <= int(time.time()):
                raise LicenseError("LICENSE_EXPIRED", "The license has expired.", 403)
            now = utc_now()
            connection.execute("UPDATE licenses SET last_seen_at=? WHERE id=?", (now, record["id"]))
            self._audit(connection, record["id"], "validated", ip_address, payload["device_hash"])
            return {"valid": True, "license_id": record["id"], "app_id": app_id, "expires_at": record["expires_at"], "plan": record["plan"], "customer_id": record["customer_id"]}

    def create_pairing_session(self, app_id: str, token: str, device_id: str) -> dict[str, Any]:
        """Create a short-lived QR pairing challenge for an activated desktop."""
        validation = self.validate(app_id, token, device_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = now + timedelta(minutes=10)
        pairing_id = str(uuid.uuid4())
        pairing_code = f"ls_pair_{pairing_id}_{secrets.token_urlsafe(24)}"
        device_hash = _device_hash(device_id, self.secret)
        with self._session() as connection:
            record = connection.execute(
                "SELECT mobile_device_hash, paired_at FROM licenses WHERE id=? AND app_id=?",
                (validation["license_id"], app_id),
            ).fetchone()
            if not record:
                raise LicenseError("INVALID_LICENSE", "The license no longer exists.", 403)
            if record["mobile_device_hash"]:
                return {
                    "pairing_id": None,
                    "pairing_code": None,
                    "scan_path": None,
                    "status": "already_activated",
                    "paired_at": record["paired_at"],
                }
            connection.execute(
                "UPDATE pairing_sessions SET status='expired' WHERE license_id=? AND status='pending'",
                (validation["license_id"],),
            )
            connection.execute(
                "INSERT INTO pairing_sessions(id, app_id, license_id, desktop_device_hash, code_hash, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
                (pairing_id, app_id, validation["license_id"], device_hash,
                 _credential_hash(pairing_code, self.secret), now.isoformat(), expires.isoformat()),
            )
        return {
            "pairing_id": pairing_id,
            "pairing_code": pairing_code,
            "scan_path": f"/scan?code={pairing_code}",
            "status": "pending",
            "expires_at": expires.isoformat(),
        }

    def scan_pairing(self, pairing_code: str, mobile_device_id: str) -> dict[str, Any]:
        """Consume a QR challenge once and pair the mobile authenticator."""
        if not isinstance(pairing_code, str) or not pairing_code.startswith("ls_pair_"):
            raise LicenseError("INVALID_PAIRING", "The QR pairing code is invalid.")
        if not isinstance(mobile_device_id, str) or not mobile_device_id.strip():
            raise LicenseError("INVALID_PAIRING", "A mobile device identifier is required.")
        mobile_hash = _device_hash(mobile_device_id, self.secret)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with self._session() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute(
                "SELECT * FROM pairing_sessions WHERE code_hash=?", (_credential_hash(pairing_code, self.secret),)
            ).fetchone()
            if not session:
                raise LicenseError("INVALID_PAIRING", "The QR pairing code is invalid or expired.", 404)
            if session["status"] == "paired":
                return {"status": "already_activated", "app_id": session["app_id"], "license_id": session["license_id"], "paired_at": session["paired_at"]}
            if session["status"] == "expired" or session["expires_at"] <= now.isoformat():
                connection.execute("UPDATE pairing_sessions SET status='expired' WHERE id=?", (session["id"],))
                raise LicenseError("PAIRING_EXPIRED", "This QR pairing code has expired. Generate a new one.", 410)
            license_row = connection.execute("SELECT * FROM licenses WHERE id=?", (session["license_id"],)).fetchone()
            if not license_row or license_row["status"] != "active" or license_row["device_hash"] != session["desktop_device_hash"]:
                raise LicenseError("PAIRING_INACTIVE", "The desktop license is no longer active.", 409)
            if license_row["mobile_device_hash"]:
                connection.execute("UPDATE pairing_sessions SET status='paired', paired_at=? WHERE id=?", (license_row["paired_at"] or now.isoformat(), session["id"]))
                return {"status": "already_activated", "app_id": session["app_id"], "license_id": session["license_id"], "paired_at": license_row["paired_at"]}
            connection.execute(
                "UPDATE licenses SET mobile_device_hash=?, paired_at=? WHERE id=?",
                (mobile_hash, now.isoformat(), session["license_id"]),
            )
            connection.execute(
                "UPDATE pairing_sessions SET status='paired', paired_at=?, mobile_device_hash=? WHERE id=?",
                (now.isoformat(), mobile_hash, session["id"]),
            )
            self._audit(connection, session["license_id"], "mobile_paired", None, session["desktop_device_hash"])
            return {"status": "activated", "app_id": session["app_id"], "license_id": session["license_id"], "paired_at": now.isoformat()}

    def pairing_status(self, app_id: str, pairing_id: str, token: str, device_id: str) -> dict[str, Any]:
        validation = self.validate(app_id, token, device_id)
        with self._session() as connection:
            session = connection.execute(
                "SELECT status, expires_at, paired_at FROM pairing_sessions WHERE id=? AND app_id=? AND license_id=?",
                (pairing_id, app_id, validation["license_id"]),
            ).fetchone()
            if not session:
                raise LicenseError("PAIRING_NOT_FOUND", "The pairing session was not found.", 404)
            if session["status"] == "pending" and session["expires_at"] <= utc_now():
                connection.execute("UPDATE pairing_sessions SET status='expired' WHERE id=?", (pairing_id,))
                return {"status": "expired", "paired": False}
            return {"status": "activated" if session["status"] == "paired" else session["status"], "paired": session["status"] == "paired", "paired_at": session["paired_at"]}

    def reset(self, license_key: str, app_id: Optional[str] = None, ip_address: Optional[str] = None, developer_id: Optional[str] = None) -> dict[str, Any]:
        with self._session() as connection:
            record = self._find_by_key(connection, license_key)
            if record is None:
                raise LicenseError("INVALID_LICENSE", "The license key was not found.", 404)
            if app_id and record["app_id"] != app_id:
                raise LicenseError("APP_ACCESS_DENIED", "This license belongs to another application.", 403)
            if developer_id and not self._application_owned(connection, record["app_id"], developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            connection.execute("UPDATE licenses SET status='unused', activated_at=NULL, device_hash=NULL, device_label=NULL, last_seen_at=NULL, version=version+1 WHERE id=?", (record["id"],))
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
            connection.execute("UPDATE licenses SET status='revoked', version=version+1 WHERE id=?", (record["id"],))
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
                 "device_label": row["device_label"], "last_seen_at": row["last_seen_at"], "customer_id": row["customer_id"], "plan": row["plan"]}
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
                 "device_label": row["device_label"], "last_seen_at": row["last_seen_at"], "customer_id": row["customer_id"], "plan": row["plan"]}
                for row in rows
            ]

    def usage_summary(self, app_id: str, developer_id: Optional[str] = None) -> dict[str, Any]:
        """Return real activation, validation, and access activity for one app.

        The audit trail is the source of truth, so dashboard metrics never use
        placeholder numbers and remain useful after a server restart.
        """
        with self._session() as connection:
            if developer_id and not self._application_owned(connection, app_id, developer_id):
                raise LicenseError("APP_ACCESS_DENIED", "You do not have access to this application.", 403)
            application = connection.execute("SELECT app_id FROM applications WHERE app_id=?", (app_id,)).fetchone()
            if not application:
                raise LicenseError("APP_NOT_FOUND", "The application was not found.", 404)
            since = (datetime.now(timezone.utc) - timedelta(days=30)).replace(microsecond=0).isoformat()
            totals = {"activated": 0, "activation_repeated": 0, "validated": 0,
                      "revoked": 0, "reset": 0, "restore": 0, "activation_rejected": 0}
            rows = connection.execute("""
                SELECT e.event_type, COUNT(*) AS count
                FROM audit_events e JOIN licenses l ON l.id=e.license_id
                WHERE l.app_id=?
                GROUP BY e.event_type
            """, (app_id,)).fetchall()
            for row in rows:
                totals[row["event_type"]] = row["count"]
            recent_rows = connection.execute("""
                SELECT e.id, e.event_type, e.created_at, e.ip_address, l.id AS license_id,
                       l.key_prefix, l.customer_id, l.plan
                FROM audit_events e JOIN licenses l ON l.id=e.license_id
                WHERE l.app_id=? AND e.created_at>=?
                ORDER BY e.id DESC LIMIT 100
            """, (app_id, since)).fetchall()
            recent = [dict(row) for row in recent_rows]
            last_30 = {"activated": 0, "activation_repeated": 0, "validated": 0,
                       "revoked": 0, "reset": 0, "restore": 0, "activation_rejected": 0}
            for row in recent:
                last_30[row["event_type"]] = last_30.get(row["event_type"], 0) + 1
            return {"app_id": app_id, "totals": totals, "last_30_days": last_30, "recent": recent}

    @staticmethod
    def _customer_fields(data: dict) -> tuple[str, str, str]:
        name, email, notes = data.get("name", ""), data.get("email", ""), data.get("notes", "")
        if not isinstance(name, str) or not name.strip() or len(name) > 120:
            raise LicenseError("INVALID_NAME", "Enter a customer name (up to 120 characters).")
        if not isinstance(email, str) or len(email) > 254 or not EMAIL_PATTERN.fullmatch(email.strip()):
            raise LicenseError("INVALID_EMAIL", "Enter a valid customer email.")
        if not isinstance(notes, str) or len(notes) > 4000:
            raise LicenseError("INVALID_NOTES", "Notes must be at most 4000 characters.")
        return name.strip(), email.strip().lower(), notes.strip()

    def create_customer(self, app_id: str, data: dict) -> dict:
        name, email, notes = self._customer_fields(data)
        customer_id, created = str(uuid.uuid4()), utc_now()
        try:
            with self._session() as connection:
                app = connection.execute("SELECT status FROM applications WHERE app_id=?", (app_id,)).fetchone()
                if not app or app["status"] != "active":
                    raise LicenseError("APP_ACCESS_DENIED", "Choose an active application.", 403)
                connection.execute("INSERT INTO customers(id,app_id,name,email,notes,created_at) VALUES (?,?,?,?,?,?)",
                                   (customer_id, app_id, name, email, notes, created))
        except sqlite3.IntegrityError as exc:
            raise LicenseError("CUSTOMER_EXISTS", "A customer with this email already exists in this app.", 409) from exc
        return {"id": customer_id, "app_id": app_id, "name": name, "email": email, "notes": notes, "created_at": created}

    def list_customers(self, app_id: str) -> list[dict]:
        with self._session() as connection:
            rows = connection.execute("""SELECT c.*, COUNT(l.id) AS license_count,
                COALESCE(SUM(CASE WHEN l.status!='revoked' AND (l.expires_at IS NULL OR l.expires_at>?) THEN 1 ELSE 0 END),0) AS access_count,
                MAX(l.last_seen_at) AS last_seen_at FROM customers c
                LEFT JOIN licenses l ON l.customer_id=c.id WHERE c.app_id=?
                GROUP BY c.id ORDER BY c.created_at DESC, c.name""", (utc_now(), app_id)).fetchall()
            return [dict(row) for row in rows]

    def customer_detail(self, app_id: str, customer_id: str) -> dict:
        with self._session() as connection:
            customer = connection.execute("SELECT * FROM customers WHERE id=? AND app_id=?", (customer_id, app_id)).fetchone()
            if not customer:
                raise LicenseError("CUSTOMER_NOT_FOUND", "Customer was not found in this app.", 404)
            events = connection.execute("""SELECT e.id,e.event_type,e.created_at,e.ip_address,l.key_prefix
                FROM audit_events e JOIN licenses l ON l.id=e.license_id
                WHERE l.customer_id=? AND l.app_id=? ORDER BY e.id DESC LIMIT 50""", (customer_id, app_id)).fetchall()
        return {"customer": dict(customer), "licenses": [l for l in self.list_licenses(app_id) if l["customer_id"] == customer_id],
                "events": [dict(row) for row in events]}

    def update_customer(self, app_id: str, customer_id: str, data: dict) -> dict:
        name, email, notes = self._customer_fields(data)
        try:
            with self._session() as connection:
                updated = connection.execute("UPDATE customers SET name=?,email=?,notes=? WHERE id=? AND app_id=?",
                                             (name, email, notes, customer_id, app_id))
                if not updated.rowcount:
                    raise LicenseError("CUSTOMER_NOT_FOUND", "Customer was not found in this app.", 404)
        except sqlite3.IntegrityError as exc:
            raise LicenseError("CUSTOMER_EXISTS", "A customer with this email already exists in this app.", 409) from exc
        return self.customer_detail(app_id, customer_id)

    def manage_license_record(self, app_id: str, license_id: str, action: str, data: dict) -> dict:
        """Manage by record ID so dashboard users need not retain raw license keys."""
        with self._session() as connection:
            record = connection.execute("SELECT * FROM licenses WHERE id=? AND app_id=?", (license_id, app_id)).fetchone()
            if not record:
                raise LicenseError("INVALID_LICENSE", "License was not found in this app.", 404)
            if action == "update":
                plan = data.get("plan", record["plan"])
                expiry = data.get("expires_at", record["expires_at"])
                if not isinstance(plan, str) or not plan.strip() or len(plan) > 80:
                    raise LicenseError("INVALID_PLAN", "Plan must contain 1 to 80 characters.")
                timestamp = self._expiry_timestamp(expiry)
                if timestamp is not None and timestamp <= int(time.time()):
                    raise LicenseError("INVALID_EXPIRY", "Choose a future expiry date.")
                connection.execute("UPDATE licenses SET plan=?,expires_at=?,version=version+1 WHERE id=?", (plan.strip(), expiry, license_id))
            elif action == "revoke":
                connection.execute("UPDATE licenses SET status='revoked',version=version+1 WHERE id=?", (license_id,))
            elif action in {"reset", "restore"}:
                connection.execute("""UPDATE licenses SET status='unused',activated_at=NULL,device_hash=NULL,
                    device_label=NULL,last_seen_at=NULL,version=version+1 WHERE id=?""", (license_id,))
            else:
                raise LicenseError("INVALID_ACTION", "Unknown license action.", 404)
            self._audit(connection, license_id, action, None, None, {"plan": data.get("plan")})
        return next(l for l in self.list_licenses(app_id) if l["id"] == license_id)
