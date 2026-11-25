#!/usr/bin/env python3
"""Own only BlueZ General.ReverseServiceDiscovery, never the whole configuration."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile

DEFAULT_CONFIG = Path("/etc/bluetooth/main.conf")
DEFAULT_RECORD = Path("/var/lib/karaali-provisioning/bluetooth-policy.json")
KEY = "ReverseServiceDiscovery"


def _read(path: Path, *, private: bool = False) -> tuple[str, os.stat_result | None]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "", None
    with os.fdopen(fd, "r", encoding="utf-8", newline="") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Policy input must be a regular file")
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError("Policy record must be owned by this administrator and mode 0600")
        if not private and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError("BlueZ configuration must be administrator-owned and not publicly writable")
        return source.read(), info


def _parse(text: str) -> tuple[list[str], int | None, int | None]:
    lines = text.splitlines(keepends=True)
    section = None
    general = key = None
    sections: set[str] = set()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"\[([^\[\]\r\n]+)\]", stripped)
        if match:
            section = match.group(1)
            if section in sections:
                raise ValueError("Ambiguous duplicate BlueZ configuration section")
            sections.add(section)
            if section == "General":
                general = index
            continue
        if section is None or "=" not in stripped:
            raise ValueError("Invalid BlueZ configuration; refusing to rewrite it")
        name, value = stripped.split("=", 1)
        if section == "General" and name.strip() == KEY:
            if key is not None or value.strip().lower() not in ("true", "false"):
                raise ValueError("Ambiguous or invalid ReverseServiceDiscovery setting")
            key = index
    return lines, general, key


def _atomic(path: Path, text: str, info: os.stat_result | None, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as target:
            os.fchmod(target.fileno(), stat.S_IMODE(info.st_mode) if info else mode)
            if info:
                os.fchown(target.fileno(), info.st_uid, info.st_gid)
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _load_record(record: Path, config: Path) -> dict | None:
    text, info = _read(record, private=True)
    if info is None:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid Bluetooth policy ownership record") from exc
    fields = {"version", "config", "original", "installed", "changed", "added_section", "separator", "status", "restored_changed"}
    if (not isinstance(data, dict) or set(data) != fields
            or type(data["version"]) is not int or data["version"] != 1
            or data["config"] != str(config.absolute())
            or type(data["changed"]) is not bool or type(data["added_section"]) is not bool
            or data["status"] not in ("pending", "active", "restored") or type(data["restored_changed"]) is not bool
            or data["separator"] not in ("", "\n")
            or data["installed"] != KEY + "=false\n"
            or (data["original"] is not None and not isinstance(data["original"], str))):
        raise ValueError("Invalid Bluetooth policy ownership record")
    original = data["original"]
    if original is not None:
        original_lines, _, original_key = _parse("[General]\n" + original)
        if original_key != 1 or len(original_lines) != 2:
            raise ValueError("Invalid original Bluetooth policy setting")
        if data["changed"] == (original.split("=", 1)[1].strip().lower() == "false"):
            raise ValueError("Inconsistent original Bluetooth policy setting")
    if data["added_section"] and original is not None:
        raise ValueError("Inconsistent Bluetooth policy ownership record")
    if not data["changed"] and original is None:
        raise ValueError("Inconsistent Bluetooth policy ownership record")
    return data


def apply_policy(config: Path, record: Path) -> bool:
    """Apply the single role setting, remembering its original line exactly once."""
    config, record = Path(config), Path(record)
    text, info = _read(config)
    lines, general, key = _parse(text)
    data = _load_record(record, config)
    if data is not None and data["status"] == "restored":
        data = None
    current = lines[key] if key is not None else None
    if data is not None:
        if not data["changed"]:
            if current is None or current.split("=", 1)[1].strip().lower() != "false":
                raise ValueError("Bluetooth policy changed outside this installer; resolve it explicitly")
            return False
        if current == data["installed"]:
            if data["status"] == "pending":
                data["status"] = "active"
                _atomic(record, json.dumps(data, indent=2) + "\n", None, 0o600)
            return False
        if (data["status"] != "pending" or current != data["original"]
                or (general is None) != data["added_section"]):
            raise ValueError("Bluetooth policy changed outside this installer; refusing to overwrite it")
    else:
        unchanged = current is not None and current.split("=", 1)[1].strip().lower() == "false"
        data = {"version": 1, "config": str(config.absolute()), "original": current,
                "status": "active" if unchanged else "pending", "restored_changed": False,
                "installed": KEY + "=false\n", "changed": not unchanged,
                "added_section": general is None,
                "separator": "\n" if text and not text.endswith("\n") else ""}
        # Commit ownership before the setting; interrupted installs remain recoverable.
        _atomic(record, json.dumps(data, indent=2) + "\n", None, 0o600)
        if unchanged:
            return False
    if key is not None:
        lines[key] = data["installed"]
    elif general is not None:
        if not lines[general].endswith("\n"):
            lines[general] += "\n"
        lines.insert(general + 1, data["installed"])
    else:
        lines.append(data["separator"] + "[General]\n" + data["installed"])
    _atomic(config, "".join(lines), info, 0o644)
    data["status"] = "active"
    _atomic(record, json.dumps(data, indent=2) + "\n", None, 0o600)
    return True


def restore_policy(config: Path, record: Path) -> bool:
    """Restore only our unchanged owned line; leave subsequent administrator edits alone."""
    config, record = Path(config), Path(record)
    data = _load_record(record, config)
    if data is None or data["status"] == "restored":
        return False
    text, info = _read(config)
    lines, general, key = _parse(text)
    changed = False
    if data["changed"] and key is not None and lines[key] == data["installed"]:
        if data["original"] is None:
            del lines[key]
            if data["added_section"] and general is not None:
                # Remove only the empty section that we introduced, not later additions.
                end = general + 1
                while end < len(lines) and not lines[end].lstrip().startswith("["):
                    end += 1
                if end == general + 1:
                    del lines[general]
                    if data["separator"] and general and lines[general - 1].endswith("\n"):
                        lines[general - 1] = lines[general - 1][:-1]
            elif data["separator"] and general is not None and general == len(lines) - 1:
                # The original final [General] header had no newline.
                if lines[general].endswith("\n"):
                    lines[general] = lines[general][:-1]
        else:
            lines[key] = data["original"]
        _atomic(config, "".join(lines), info, 0o644)
        changed = True
    data["status"] = "restored"
    data["restored_changed"] = changed
    # Keep a tombstone so maintenance can retry a failed Bluetooth restart.
    _atomic(record, json.dumps(data, indent=2) + "\n", None, 0o600)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "restore"))
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--record", type=Path, default=DEFAULT_RECORD)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Policy administration requires root.\n")
    try:
        changed = (apply_policy if args.action == "apply" else restore_policy)(args.config, args.record)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Bluetooth policy not completed: {exc}\n")
    print("Bluetooth policy changed." if changed else "Bluetooth policy unchanged.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
