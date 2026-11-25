"""Persistent device credentials and sensitive QR preparation."""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import io
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .framing import decode_message, encode_message


class IdentityError(ValueError):
    pass


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: object, length: int = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Expected base64 string")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid base64") from exc
    if b64(result) != value or (length is not None and len(result) != length):
        raise ValueError("Invalid base64 length or encoding")
    return result


def validate_id(device_id: str) -> None:
    if not isinstance(device_id, str) or re.fullmatch(r"[a-z0-9-]{1,32}", device_id) is None:
        raise IdentityError("Device ID must be 1..32 lowercase ASCII letters, digits or hyphens")


@dataclass(frozen=True)
class QRIdentity:
    device_id: str
    public_key: bytes = field(repr=False)
    setup_secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        validate_id(self.device_id)
        if len(self.public_key) != 32 or len(self.setup_secret) != 32:
            raise IdentityError("Identity keys must be exactly 32 bytes")

    def to_dict(self) -> dict:
        return {"version": 1, "device_id": self.device_id,
                "public_key": b64(self.public_key), "setup_secret": b64(self.setup_secret)}

    @classmethod
    def from_dict(cls, value: dict) -> QRIdentity:
        try:
            if type(value.get("version")) is not int or value["version"] != 1:
                raise ValueError("Invalid version")
            return cls(value["device_id"], unb64(value["public_key"], 32),
                       unb64(value["setup_secret"], 32))
        except (KeyError, ValueError, TypeError) as exc:
            raise IdentityError("Invalid version-1 QR identity; import the original QR JSON") from exc

    @classmethod
    def load(cls, path: Path) -> QRIdentity:
        try:
            return cls.from_dict(decode_message(Path(path).read_bytes()))
        except ValueError as exc:
            raise IdentityError("Invalid QR JSON; import the original QR JSON") from exc


@dataclass(frozen=True)
class DeviceIdentity(QRIdentity):
    private_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if len(self.private_key) != 32:
            raise IdentityError("Private key must be exactly 32 bytes")
        public = X25519PrivateKey.from_private_bytes(self.private_key).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        if public != self.public_key:
            raise IdentityError("Identity public and private keys do not match")

    @property
    def qr(self) -> QRIdentity:
        return QRIdentity(self.device_id, self.public_key, self.setup_secret)

    @classmethod
    def generate(cls, device_id: str) -> DeviceIdentity:
        validate_id(device_id)
        key = X25519PrivateKey.generate()
        return cls(device_id, key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                   secrets.token_bytes(32), key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))

    def to_dict(self) -> dict:
        value = super().to_dict()
        value["private_key"] = b64(self.private_key)
        return value

    @classmethod
    def from_dict(cls, value: dict) -> DeviceIdentity:
        qr = QRIdentity.from_dict(value)
        try:
            return cls(qr.device_id, qr.public_key, qr.setup_secret, unb64(value["private_key"], 32))
        except (KeyError, ValueError, TypeError) as exc:
            raise IdentityError("Invalid device private identity") from exc

    @classmethod
    def load(cls, path: Path) -> DeviceIdentity:
        # Refuse symlinks and shared permission bits rather than silently exposing credentials.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise IdentityError("Private identity must be a regular owner-only file; run chmod 600 on it")
            data = source.read(4097)
        try:
            return cls.from_dict(decode_message(data))
        except ValueError as exc:
            raise IdentityError("Invalid device identity JSON; use the file created by init") from exc


def create_identity(device_id: str, identity_path: Path, qr_json_path: Path, qr_png_path: Path) -> DeviceIdentity:
    """Create all three sensitive artifacts exclusively, with owner-only permissions."""
    import qrcode
    from qrcode.image.pure import PyPNGImage

    identity = DeviceIdentity.generate(device_id)
    qr_data = encode_message(identity.qr.to_dict())
    image = qrcode.make(qr_data.decode("utf-8"), image_factory=PyPNGImage)
    png = io.BytesIO()
    image.save(png)
    outputs = [(Path(identity_path), encode_message(identity.to_dict()) + b"\n"),
               (Path(qr_json_path), qr_data + b"\n"), (Path(qr_png_path), png.getvalue())]
    created = []
    try:
        for path, data in outputs:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
    except BaseException:
        # Only remove artifacts created by this call; never overwrite an existing identity.
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return identity
