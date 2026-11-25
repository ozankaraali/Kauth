#!/usr/bin/env python3
"""Render an existing device QR as a self-contained, private A5 setup card.

Run from a checkout with the project's Python dependencies installed. This does
not generate or change device keys, provisioning state, or the wire protocol.
"""
from __future__ import annotations

import html
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import qrcode
from qrcode.util import pattern_position

from device_provision.cli import PrivateArgumentParser
from device_provision.framing import encode_message
from device_provision.identity import IdentityError, QRIdentity


def logo_path() -> str:
    # Reuse the supplied vector artwork without copying its provenance metadata
    # into a credential-bearing document or depending on external resources.
    root = ET.parse(Path(__file__).with_name("k-glyph-final.svg")).getroot()
    return html.escape(root.find("{http://www.w3.org/2000/svg}path").attrib["d"], quote=True)


def qr_svg(identity: QRIdentity, glyph: str, inset: bool) -> str:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, border=4)
    qr.add_data(encode_message(identity.to_dict()), optimize=0)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    extent = len(matrix)
    modules = qr.modules_count
    paths = "".join(f"M{x},{y}h1v1h-1z" for y, row in enumerate(matrix)
                    for x, dark in enumerate(row) if dark)
    logo = ""
    if inset:
        # Keep the four-module quiet zone and every finder/timing/version pattern.
        # The logo is at most 9 modules square; shift it near the centre when a
        # central alignment pattern occupies the exact centre. ECC is not a
        # guarantee of scanning: qualify the finished print on the actual phone.
        size = 9
        centres = pattern_position(qr.version)
        protected = [(x - 2, y - 2, x + 3, y + 3) for x in centres for y in centres]
        candidates = []
        for y in range(9, modules - size - 8):
            for x in range(9, modules - size - 8):
                if all(x + size <= left or x >= right or y + size <= top or y >= bottom
                       for left, top, right, bottom in protected):
                    distance = (2 * x + size - modules) ** 2 + (2 * y + size - modules) ** 2
                    candidates.append((distance, y, x))
        if not candidates:
            raise ValueError("No safe inset position; use --plain-qr")
        _, y, x = min(candidates)
        x, y = x + 4, y + 4
        logo = (f'<rect x="{x}" y="{y}" width="{size}" height="{size}" fill="white"/>'
                f'<svg x="{x}" y="{y}" width="{size}" height="{size}" viewBox="0 0 1024 1024">'
                f'<path fill="black" d="{glyph}"/></svg>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Private device setup QR" '
            f'class="qr" viewBox="0 0 {extent} {extent}">'
            f'<rect width="{extent}" height="{extent}" fill="white"/>'
            f'<path fill="black" shape-rendering="crispEdges" d="{paths}"/>{logo}</svg>')


def render(identity: QRIdentity, serial: str | None, inset: bool, preview: bool) -> str:
    glyph = logo_path()
    serial_row = (f'<div><dt>Device serial number</dt><dd>{html.escape(serial)}</dd></div>'
                  if serial else "")
    preview_label = '<p class="preview">Design preview · Not for installation</p>' if preview else ""
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Private setup card — {identity.device_id}</title>
<style>
@page {{ size: A5 portrait; margin: 0; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; color: #172725; background: #edf1ef; font: 10pt/1.4 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
.card {{ width: 148mm; min-height: 210mm; margin: 16px auto; padding: 8mm 13mm; background: white; }}
header {{ display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #dce5e1; padding-bottom: 3mm; }}
.brand {{ display: flex; align-items: center; gap: 2mm; font-weight: 750; font-size: 21pt; letter-spacing: -.8px; }}
.mark {{ width: 11mm; height: 11mm; }}
.tag {{ font-size: 8pt; letter-spacing: 1.2px; text-transform: uppercase; color: #41615a; }}
h1 {{ font-size: 25pt; line-height: 1.08; letter-spacing: -.9px; margin: 5mm 0 2mm; }}
.intro {{ margin: 0; color: #52645f; font-size: 9pt; }}
dl {{ margin: 4mm 0 2mm; display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 4mm; }}
dt {{ font-size: 8pt; color: #52645f; }}
dd {{ margin: 0; font-size: 9pt; line-height: 1.25; font-weight: 650; overflow-wrap: anywhere; }}
.qr {{ display: block; width: 65mm; height: 65mm; margin: 0 auto; }}
.caption {{ text-align: center; margin: 0 0 3mm; font-size: 8pt; color: #52645f; }}
ol {{ padding-left: 5mm; margin: 0 0 3mm; font-size: 9pt; }}
li {{ padding-left: 1mm; margin: 1mm 0; }}
.warning {{ padding: 3mm; background: #eff6f2; border-left: 3px solid #35715f; }}
.warning strong {{ display: block; font-size: 11pt; margin-bottom: 1mm; }}
.warning p {{ margin: 0; font-size: 9pt; }}
footer {{ margin-top: 3mm; color: #52645f; font-size: 7.5pt; }}
.preview {{ margin: 0 0 3mm; text-align: center; color: #7d391d; font-size: 8pt; text-transform: uppercase; letter-spacing: .5px; }}
@media print {{ body {{ background: white; }} .card {{ margin: 0; }} * {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }} }}
@media screen and (max-width: 560px) {{ .card {{ width: 100%; margin: 0; padding: 8mm; }} }}
</style></head><body><main class="card">
{preview_label}
<header><div class="brand"><svg class="mark" viewBox="0 0 1024 1024" aria-hidden="true"><path fill="currentColor" d="{glyph}"/></svg>Kauth</div><span class="tag">Private setup card</span></header>
<h1>Your setup key.</h1>
<p class="intro">For authorised installation staff. Keep this card with the device's installation records.</p>
<dl><div><dt>Device ID · matches the setup app</dt><dd>{identity.device_id}</dd></div>{serial_row}</dl>
{qr_svg(identity, glyph, inset)}
<p class="caption">Scan in Kauth, not the Camera app.</p>
<ol><li>Power on the device and keep your phone nearby.</li><li>Scan this card. Let the app verify the device.</li><li>Choose the installation Wi-Fi network and join.</li></ol>
<section class="warning"><strong>Keep safe. Do not lose or share.</strong><p>This QR authorises setup while the device's setup window is open. Do not photograph, upload, or include it in a recording.</p></section>
<footer>Keep inside the box, not on the outside of the device.<br>Missing card or setup closed? Contact your installation administrator.</footer>
</main></body></html>'''


def main() -> int:
    parser = PrivateArgumentParser(description="Render a private Kauth A5 setup card from an existing device QR JSON. No keys are changed.")
    parser.add_argument("--qr", type=Path, required=True, help="Private version-1 QR JSON from device-provision init")
    parser.add_argument("--output", type=Path, required=True, help="New private .html file; existing files are never overwritten")
    parser.add_argument("--serial", help="Optional actual inventory serial, not cryptographically verified by this POC")
    parser.add_argument("--plain-qr", action="store_true", help="Keep the header logo but leave QR modules unmodified")
    parser.add_argument("--preview", action="store_true", help="Mark a design preview as not for installation; still treat its QR as sensitive")
    args = parser.parse_args()
    created = False
    try:
        if args.serial is not None and (not args.serial.strip() or len(args.serial) > 80 or not args.serial.isprintable()):
            raise ValueError("Invalid serial number")
        if args.output.suffix.lower() != ".html":
            raise ValueError("Output must be an HTML file")
        identity = QRIdentity.load(args.qr)
        document = render(identity, args.serial, not args.plain_qr, args.preview).encode("utf-8")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(document)
            target.flush()
            os.fsync(target.fileno())
    except (OSError, ValueError, IdentityError):
        if created:
            args.output.unlink(missing_ok=True)
        print("Card not created. Check the QR JSON, serial, and unused output path; no existing file was overwritten.", file=sys.stderr)
        return 1
    print("Created owner-only setup card. Open locally and print A5 at 100%, without browser headers/footers. Keep HTML, PDF and paper private.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
