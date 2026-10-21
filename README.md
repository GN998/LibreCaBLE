# Passkey Bridge
![Vibe Coded](https://img.shields.io/badge/LLM-Vibe_Coded-orange)

A lightweight, GMS-free FIDO2 hybrid transport (caBLE v2) bridge for Android 14+ (API 34+). It intercepts `fido:/` QR intents and bridges PC WebAuthn requests over BLE and encrypted WebSockets to Android's `CredentialManager` API.

## Core Features

* **URI Parsing**: Decodes `fido:/` URIs via CTAP 2.3 base-10 and canonical CBOR.
* **Hybrid Transport**: Implements `0xFFF9` BLE advertising, `Noise_KNpsk0` handshakes, and CTAP 2.3 tunnel domain derivation (build-time or runtime Tunnel IDs: `0` or `256–65535`).
* **CTAP2 Bridging**: Zero-dependency CBOR codec supporting `GetInfo`, `MakeCredential`, and `GetAssertion`, forwarding PC `origin` and `clientDataHash` to `CredentialManager`.

## Requirements

1. **System**: Android 14+ with Bluetooth enabled and `BLUETOOTH_ADVERTISE` / `BLUETOOTH_CONNECT` granted.
2. **Provider Trust**: App signing certificate must be allowlisted in your credential provider (e.g., Bitwarden) to permit `setOrigin` forwarding (untrusted calls return `0x27`).
3. **QR Scanner**: External camera or QR scanner app that dispatches system `Intent`s.
4. **Build**: Specify `TUNNEL_ID` in `local.properties` or the `CUSTOM_TUNNEL_ID` environment variable.

## License & Acknowledgments

Licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).

* **[microG GmsCore](https://github.com/microg/GmsCore/)**: Protocol logic inspired by microG GmsCore ([Apache 2.0](https://github.com/microg/GmsCore/blob/master/LICENSE)).
* **[FIDO Alliance](https://fidoalliance.org/)**: CTAP 2.3 and WebAuthn specifications.
* **[Bitwarden](https://github.com/bitwarden/android)**: Open-source Android `CredentialManager` and local trust integration.
* **[Cloudflare](https://www.cloudflare.com/)**: WebSocket tunnel relay infrastructure.