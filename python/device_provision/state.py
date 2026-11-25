"""Local owner-only setup authorization, independent of network availability."""
from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path
import stat
import tempfile
import time

from .framing import decode_message, encode_message
from .protocol import valid_network


class StateError(RuntimeError):
    pass


class ProvisioningState:
    def __init__(self, path: Path, clock=time.time):
        self.path, self.clock = Path(path), clock

    @contextlib.contextmanager
    def _lock(self):
        fd = os.open(str(self.path) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self._private(fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @staticmethod
    def _private(fd):
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.geteuid()):
            raise StateError("Provisioning state must be a regular owner-only file owned by this user")

    def read(self) -> dict:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return {"version": 1, "provisioned": False, "reopen_until": 0, "network": None}
        try:
            with os.fdopen(fd, "rb") as source:
                self._private(source.fileno())
                value = decode_message(source.read(8193))
            if (value.get("version") != 1 or type(value.get("provisioned")) is not bool
                    or type(value.get("reopen_until")) not in (int, float)
                    or value["reopen_until"] < 0
                    or (value.get("network") is not None and not valid_network(value["network"], True))
                    or (value["provisioned"] and value.get("network") is None)):
                raise ValueError()
            return value
        except (ValueError, KeyError) as exc:
            raise StateError("Invalid provisioning state; local maintenance is required (setup remains closed)") from exc

    def allowed(self, value=None) -> bool:
        value = self.read() if value is None else value
        return not value["provisioned"] or self.clock() < value["reopen_until"]

    def _write(self, value: dict) -> None:
        fd, name = tempfile.mkstemp(prefix=".provisioning-state-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(encode_message(value) + b"\n")
                target.flush()
                os.fsync(target.fileno())
            os.replace(name, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name)

    def reopen(self) -> float:
        with self._lock():
            value = self.read()
            value["reopen_until"] = self.clock() + 300
            self._write(value)
            return value["reopen_until"]

    def provisioned(self, network: dict) -> None:
        if not valid_network(network, True):
            raise StateError("Cannot save provisioning state without verified Wi-Fi addresses")
        with self._lock():
            self.read()  # Refuse to replace a corrupt/shared/unowned state file.
            self._write({"version": 1, "provisioned": True, "reopen_until": 0,
                         "network": network})
