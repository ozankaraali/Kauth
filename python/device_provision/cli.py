"""Private identity preparation, BLE provisioning commands and local maintenance."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
from pathlib import Path
import sys

from .ble import TransportError, request, serve
from .identity import DeviceIdentity, IdentityError, QRIdentity, create_identity
from .network import NetworkError
from .protocol import ProtocolError, validate_command
from .state import ProvisioningState, StateError


def _positive(value: str) -> float:
    result = float(value)
    if not 0 < result <= 300:
        raise argparse.ArgumentTypeError("Timeout must be greater than zero and at most 300 seconds")
    return result


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes rejected arguments, possibly an accidental
        # password or QR secret. Never reflect those values to terminal/log output.
        self.print_usage(sys.stderr)
        self.exit(2, "Error: invalid command arguments. Use --help; configure prompts privately for the password.\n")


def parser() -> argparse.ArgumentParser:
    root = PrivateArgumentParser(prog="device-provision",
                                 description="Karaali QR-authenticated BLE Linux Wi-Fi setup and Diagnostics")
    commands = root.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create private identity and sensitive QR artifacts")
    init.add_argument("--device-id", required=True, help="Device label, e.g. demodevice1 (1..32 lowercase ASCII letters, digits or hyphens)")
    init.add_argument("--identity", type=Path, default=Path("identity.json"))
    init.add_argument("--qr-json", type=Path, default=Path("qr.json"))
    init.add_argument("--qr-png", type=Path, default=Path("qr.png"))
    peripheral = commands.add_parser("serve", help="Run BLE provisioning; Linux requires root and NetworkManager")
    peripheral.add_argument("--identity", type=Path, default=Path("identity.json"))
    peripheral.add_argument("--state", type=Path, help="Private state (default: provisioning-state.json beside identity)")
    peripheral.add_argument("--adapter", help="Linux BlueZ Bluetooth adapter name, e.g. hci0")
    peripheral.add_argument("--interface", help="NetworkManager Wi-Fi interface; required if multiple managed adapters exist")
    reopen = commands.add_parser("reopen", help="Local private-state maintenance: allow setup for five minutes")
    reopen.add_argument("--identity", type=Path, default=Path("identity.json"))
    reopen.add_argument("--state", type=Path, help="Private state (default: provisioning-state.json beside identity)")
    for name, description in (("echo", "Authenticate exact UTF-8 diagnostic echo"),
                              ("scan", "Scan Wi-Fi networks on the device"),
                              ("status", "Read authenticated provisioning and current Wi-Fi status"),
                              ("configure", "Join WPA2-Personal Wi-Fi; password prompted privately")):
        central = commands.add_parser(name, help=description)
        central.add_argument("--qr", type=Path, required=True, help="Sensitive QR JSON created by init")
        central.add_argument("--address", help="BLE address/macOS UUID for transport selection, not trust")
        central.add_argument("--timeout", type=_positive, default=150.0 if name == "configure" else 45.0,
                             help="Whole authenticated exchange deadline in seconds")
        central.add_argument("--scan-timeout", type=_positive, default=5.0, help="BLE discovery seconds")
        if name == "echo":
            central.add_argument("--text", default="hello world", help="Exact 1..512 UTF-8 bytes; never trimmed")
        if name == "configure":
            central.add_argument("--ssid", required=True, help="Exact 1..32 UTF-8 bytes; never trimmed")
            central.add_argument("--hidden", action="store_true", help="Probe for a hidden WPA2-Personal network")
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    # Never enable BLE/D-Bus dependency debug logs: their payloads include credentials.
    logging.basicConfig(level=logging.WARNING)
    try:
        if args.command == "init":
            create_identity(args.device_id, args.identity, args.qr_json, args.qr_png)
            print("Created owner-only identity and QR JSON/PNG. Keep all three private; the QR contains the setup secret.")
        elif args.command in ("serve", "reopen"):
            if sys.platform == "linux" and os.geteuid() != 0:
                raise NetworkError("permission_denied")
            identity = DeviceIdentity.load(args.identity)
            state = ProvisioningState(args.state or args.identity.with_name("provisioning-state.json"))
            state.read()
            if args.command == "reopen":
                state.reopen()
                print("Local setup window opened for five minutes. Saved Wi-Fi profiles and identity are unchanged.")
            else:
                asyncio.run(serve(identity, state, adapter=args.adapter, interface=args.interface,
                                  ready=lambda: print("Karaali provisioning daemon ready for " + identity.device_id
                                      + "; advertises only while setup is allowed. Ctrl-C to stop.", flush=True)))
        else:
            qr = QRIdentity.load(args.qr)
            command = {"op": args.command}
            if args.command == "echo":
                command["text"] = args.text
            if args.command == "configure":
                if not sys.stdin.isatty():
                    raise ProtocolError("Configure requires an interactive terminal for private password entry")
                command.update(ssid=args.ssid, hidden=args.hidden,
                               password=getpass.getpass("WPA2 passphrase (not echoed): "))
            validate_command(command)
            try:
                reply = asyncio.run(request(qr, command, args.address, args.timeout, args.scan_timeout,
                    progress=lambda event: print(json.dumps({"authenticated": True, **event}, ensure_ascii=False), flush=True)))
            finally:
                command.pop("password", None)
            return 1 if reply["event"] == "error" else 0
        return 0
    except KeyboardInterrupt:
        print("Stopped watching. An in-flight device join may continue; no unfinished attempt is a verified success.", file=sys.stderr)
        return 130
    except FileExistsError:
        print("Error: output already exists. Preserve the identity or choose new paths; init never overwrites.", file=sys.stderr)
    except FileNotFoundError:
        print("Error: file or directory does not exist. Check identity, QR and state paths.", file=sys.stderr)
    except PermissionError:
        print("Error: permission denied. Check private files and Bluetooth access. Linux serve/reopen require root; macOS does not.", file=sys.stderr)
    except (IdentityError, ProtocolError, TransportError, NetworkError, StateError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
    except OSError:
        print("Error: unable to access private files. Check paths, disk space and owner-only permissions.", file=sys.stderr)
    except Exception:
        print("Error: operation failed; check dependencies and arguments locally. No verified success was obtained.", file=sys.stderr)
    return 1
