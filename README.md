# LibreCaBLE (Proof of Concept)
![Vibe Coded](https://img.shields.io/badge/LLM-Vibe_Coded-orange) 

LibreCaBLE is a lightweight, GMS-free FIDO2 hybrid transport (caBLE v2 / CTAP 2.3 §11.5) and Proximity Exchange Protocol (PXP) implementation for Android 14+ (API 34+). It enables an Android device to operate as both a Credential Manager Hosting Device (CMHD / Roaming Authenticator) and a Client Platform for QR-initiated cross-device WebAuthn ceremonies over BLE L2CAP and WebSocket relay tunnels.

## Core Features

* **CMHD / Roaming Authenticator Mode**: Handles `FIDO:/` URIs for QR-initiated transactions (CTAP 2.3 §11.5.1), broadcasts `0xFFF9` BLE proximity advertisements, and dispatches CTAP2 commands (including pre-hashed `prf` inputs) to Android's `CredentialManager` with privileged `origin` and `clientDataHash` binding.
* **Client Platform Mode**: Implements Android's `CredentialProviderService` to initiate hybrid ceremonies, rendering digit-encoded `FIDO:/` QR payloads, scanning for `0xFFF9` BLE advertisements, and assembling WebAuthn responses (`COSE_Key` to SPKI conversion, `credProps`, `prf`, and `privileged_apps.json` origin verification).
* **CTAP 2.3 Hybrid Transport & Encoding**: Full `Noise_KNpsk0_P256_AESGCM_SHA256` handshakes, direct BLE L2CAP CoC channels with automatic WebSocket tunnel fallback (assigned ID `0` or hashed IDs `256–65535`), and a zero-dependency **CTAP2 canonical CBOR** codec supporting `authenticatorMakeCredential (0x01)`, `authenticatorGetAssertion (0x02)`, `authenticatorGetInfo (0x04)`, and `authenticatorSelection (0x0B)`.

## Requirements

1. **Android 14+ (API 34+)** with Bluetooth enabled.
2. **CMHD (Authenticator) Mode**:
   * App signing certificate SHA-256 fingerprint must be allowlisted in or directly trusted by your local credential provider (e.g., Bitwarden) to permit `CREDENTIAL_MANAGER_SET_ORIGIN`.
   * An external camera or QR scanner app that dispatches `VIEW` intents for `FIDO:/` URIs.
   * *(Optional)* Custom tunnel domain ID can be configured via **⋮ > Extended Domain Settings** .
3. **Client Platform Mode**: Enable **LibreCaBLE** in Android *Settings > Passwords & passkeys* (or via **⋮ > Enable Client Provider**).

## License & Acknowledgments

Licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).

* **[microG GmsCore](https://github.com/microg/GmsCore/)**: Protocol logic inspired by microG GmsCore ([Apache 2.0](https://github.com/microg/GmsCore/blob/master/LICENSE)).
* **[FIDO Alliance](https://fidoalliance.org/)**: CTAP and WebAuthn specifications.
* **[Bitwarden](https://github.com/bitwarden/android)**: Open-source Android `CredentialManager` and local trust integration.
* **[Cloudflare](https://www.cloudflare.com/)**: WebSocket tunnel relay infrastructure. 

* GitHub & LinuxDo