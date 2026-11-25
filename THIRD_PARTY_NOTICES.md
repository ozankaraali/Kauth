# Third-party notices

This file acknowledges third-party material that Kauth uses or redistributes. The GNU Affero General Public License v3.0 or later in [LICENSE](LICENSE) applies to the author's own material; it does not override the rights or licenses of third parties described here.

## Python dependencies (not included)

This source archive does not vendor installed third-party packages, platform SDKs or system daemons. `pip` installs the packages pinned in `pyproject.toml` from their own distributions, and their licenses remain in those distributions.

| Package | Version | License | Source | Used for |
| --- | --- | --- | --- | --- |
| pyhpke | 0.6.3 | MIT | https://github.com/dajiaji/pyhpke | HPKE |
| cryptography | 46.0.3 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography | X25519 keys, ChaCha20-Poly1305 |
| bless | 0.2.6 | MIT (installed LICENSE: Copyright (c) 2020 Kevin Davis) | https://github.com/kevincar/bless | BLE GATT peripheral on the device |
| bleak | 0.22.3 | MIT | https://github.com/hbldh/bleak | BLE central in the Python configurator |
| qrcode | 8.2 | BSD-3-Clause, with an inherited MIT-licensed QR code implementation | https://github.com/lincolnloop/python-qrcode | Setup QR codes and cards |
| pypng | 0.20220715.0 | MIT | https://gitlab.com/drj11/pypng | QR PNG output |
| dbus-next | 0.2.3 | MIT | https://github.com/altdesktop/python-dbus-next | NetworkManager D-Bus client |
| pytest | 8.4.2 | MIT | https://github.com/pytest-dev/pytest | Tests only |

Transitive dependencies are resolved by `pip` and vary by platform; they are not listed. This file is not a software bill of materials for any installed environment or binary.

## Platform components (not redistributed)

The Linux service relies on BlueZ and NetworkManager supplied by the operating system. The iOS app is built with Xcode against Apple SDK frameworks, including CryptoKit, CoreBluetooth and Security. These components are separately licensed by their providers and are not redistributed here.

## IETF HPKE test vector (redistributed)

`fixtures/rfc9180-psk.json` is the complete test vector for mode 1 (PSK), KEM 32 (DHKEM(X25519, HKDF-SHA256)), KDF 1 (HKDF-SHA256) and AEAD 3 (ChaCha20Poly1305), with 257 encryptions and 3 exports. It was selected without content changes from:

- [`test-vectors.json` at commit `5f503c564da00b0687b3de75f1dfbdfc4079ad31`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json) (2021) of the IETF CFRG HPKE draft repository; the draft was later published as [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
- Contribution terms at that commit: [`CONTRIBUTING.md`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/CONTRIBUTING.md) and [`LICENSE.md`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/LICENSE.md), which refers to those contribution guidelines.

`CONTRIBUTING.md` states that the repository's material is a Contribution to the IETF Standards Process under BCP 78, BCP 79 and the IETF Trust Legal Provisions (TLP), including the TLP rules regarding code components, which it describes as being subject to a "Simplified BSD License". Section 4 of the [IETF Trust Legal Provisions (TLP 5)](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/) licenses code components under the Revised BSD License reproduced below. This vector is redistributed as such a code component. These terms cover that code component only; this notice does not claim that the RFC 9180 document as a whole is BSD-licensed.

Attribution: this test vector is taken from an IETF Contribution, the IETF CFRG `draft-irtf-cfrg-hpke` repository (HPKE, published as RFC 9180).

```text
Copyright (c) 2021 IETF Trust and the persons identified as authors of the
code. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

- Neither the name of Internet Society, IETF or IETF Trust, nor the names of
  specific contributors, may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Interoperability fixture

`fixtures/interop.json` was generated independently for Kauth with PyHPKE and cryptography, using deterministic test-only secrets that are deliberately public. It is not copied from a third-party vector set, and its keys and secret are never device defaults. No generator script is included.

## Artwork

`k-icon-final.svg` and `k-glyph-final.svg` were supplied by the author and created with AI assistance. Each file embeds C2PA provenance metadata referencing Claude (Anthropic), which is preserved unchanged. The iOS app icon (`ios/Kauth/Assets.xcassets/AppIcon.appiconset/AppIcon.png`) shows the same mark as a raster image without embedded provenance metadata. No claim is made of exclusive rights in this artwork or of clearance of third-party rights.
