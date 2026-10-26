# Passkey Bridge
![Vibe Coded](https://img.shields.io/badge/LLM-Vibe_Coded-orange)

A lightweight, GMS-free FIDO2 hybrid transport (`caBLE v2` / CTAP 2.3 §11.5) implementation for Android 14+ (API 34+). It enables an Android device to operate as both a **Credential Manager Hosting Device (CMHD / Roaming Authenticator)** and a **Client Platform** for QR-initiated cross-device WebAuthn ceremonies.

## Core Features

* **CMHD / Roaming Authenticator Mode**: Handles `FIDO:/` URIs for QR-initiated transactions (CTAP 2.3 §11.5.1), broadcasts `0xFFF9` BLE proximity advertisements, and dispatches CTAP2 commands to Android's `CredentialManager` with privileged `origin` and `clientDataHash` binding.
* **Client Platform Mode**: Implements Android's `CredentialProviderService` to initiate hybrid ceremonies, rendering digit-encoded `FIDO:/` QR payloads, scanning for `0xFFF9` BLE advertisements, and assembling WebAuthn responses (`COSE_Key` to SPKI conversion, `credProps`, and `privileged_apps.json` origin verification).
* **CTAP 2.3 Hybrid Transport & Encoding**: Full `Noise_KNpsk0_P256_AESGCM_SHA256` handshakes, WebSocket tunnel domain derivation (assigned ID `0` or hashed IDs `256–65535`), and a zero-dependency **CTAP2 canonical CBOR** codec supporting `authenticatorMakeCredential (0x01)`, `authenticatorGetAssertion (0x02)`, `authenticatorGetInfo (0x04)`, and `authenticatorSelection (0x0B)`.

## Requirements

1. **System**: Android 14+ with Bluetooth enabled and `BLUETOOTH_ADVERTISE`, `BLUETOOTH_SCAN`, and `BLUETOOTH_CONNECT` granted.
2. **CMHD (Authenticator) Mode**:
   * App signing certificate SHA-256 fingerprint must be allowlisted in your local credential provider (e.g., Bitwarden) to permit `CREDENTIAL_MANAGER_SET_ORIGIN` (untrusted calls return `CTAP2_ERR_OPERATION_DENIED` / `0x27`).
   * An external camera or QR scanner app that dispatches `VIEW` intents for `FIDO:/` URIs.
3. **Client Platform Mode**: Enable **Passkey Bridge** in Android *Settings > Passwords & passkeys* (or via the in-app menu).

## License & Acknowledgments

Licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).

* **[microG GmsCore](https://github.com/microg/GmsCore/)**: Protocol logic inspired by microG GmsCore ([Apache 2.0](https://github.com/microg/GmsCore/blob/master/LICENSE)).
* **[FIDO Alliance](https://fidoalliance.org/)**: CTAP 2.3 and WebAuthn specifications.
* **[Bitwarden](https://github.com/bitwarden/android)**: Open-source Android `CredentialManager` and local trust integration.
* **[Cloudflare](https://www.cloudflare.com/)**: WebSocket tunnel relay infrastructure. 

* **GitHub** & **linux.do**