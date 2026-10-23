"""Dependency-free client SDK for any desktop application."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional


class LicenseClientError(Exception):
    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


def _stable_machine_value() -> str:
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                if value:
                    return str(value)
        except (ImportError, OSError):
            pass
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
    if platform.system() == "Darwin":
        try:
            output = subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True, timeout=2)
            match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', output)
            if match:
                return match.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    return "|".join((platform.node(), platform.system(), platform.machine(), platform.processor()))


def machine_fingerprint(app_id: str) -> str:
    """Return an app-scoped one-way device identifier."""
    return hashlib.sha256(f"license-platform-v1|{app_id}|{_stable_machine_value()}".encode()).hexdigest()


class LicenseClient:
    def __init__(self, base_url: str, app_id: str, storage_path: Optional[str] = None, timeout: float = 10.0,
                 device_id: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id
        self.timeout = timeout
        self.device_id = device_id or machine_fingerprint(app_id)
        self.storage_path = Path(storage_path) if storage_path else None

    def _request(self, route: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.base_url + route,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                body = json.loads(error.read())
                detail = body.get("error", {})
            except (ValueError, json.JSONDecodeError):
                detail = {}
            finally:
                error.close()
            raise LicenseClientError(detail.get("code", "HTTP_ERROR"), detail.get("message", str(error)), error.code) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise LicenseClientError("NETWORK_ERROR", str(error)) from error

    def activate(self, license_key: str, device_label: Optional[str] = None) -> dict[str, Any]:
        result = self._request("/v1/activate", {"app_id": self.app_id, "license_key": license_key, "device_id": self.device_id, "device_label": device_label})
        self._save_token(result["token"])
        return result

    def validate_online(self) -> dict[str, Any]:
        token = self._load_token()
        if not token:
            raise LicenseClientError("NOT_ACTIVATED", "This application has not been activated.")
        return self._request("/v1/validate", {"app_id": self.app_id, "token": token, "device_id": self.device_id})

    def is_activated(self) -> bool:
        try:
            self.validate_online()
            return True
        except LicenseClientError:
            return False

    def _save_token(self, token: str) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.storage_path.write_text(json.dumps({"token": token}), encoding="utf-8")
        try:
            os.chmod(self.storage_path, 0o600)
        except OSError:
            pass

    def _load_token(self) -> Optional[str]:
        if not self.storage_path or not self.storage_path.exists():
            return None
        try:
            return json.loads(self.storage_path.read_text(encoding="utf-8")).get("token")
        except (OSError, ValueError):
            return None
