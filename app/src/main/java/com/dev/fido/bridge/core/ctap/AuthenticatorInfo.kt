package com.dev.fido.bridge.core.ctap

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.Ctap2Response

object AuthenticatorInfo {
    fun getInfo(): Ctap2Response.GetInfoResponse {
        return Ctap2Response.GetInfoResponse(
            // Advertise FIDO_2_0 and FIDO_2_1 with built-in UV (uv = true, alwaysUv = true) and no pinUvAuthProtocols
            // so CTAP 2.1+ platforms delegate user verification directly to Android CredentialManager per CTAP 2.3 §6.1.1
            versions = listOf("FIDO_2_0", "FIDO_2_1"),
            extensions = emptyList(),
            aaguid = ByteArray(16),
            options = mapOf(
                "plat" to false,
                "rk" to true,
                // Use standard CTAP option key "uv" instead of WebAuthn parameter name "userVerification" per CTAP 2.3 §6.4
                "uv" to true,
                "up" to true,
                "alwaysUv" to true
            ),
            maxMsgSize = 2048,
            pinUvAuthProtocols = emptyList(),
            algorithms = CtapCodec.SUPPORTED_COSE_ALGORITHMS.map { alg ->
                mapOf("type" to "public-key", "alg" to alg)
            }
        )
    }

    /**
     * Serialize GetInfoResponse into its canonical CTAP2 CBOR map representation.
     * Share across pre-flight caBLE post-handshake messages and 0x04 GetInfo commands to prevent capability drift.
     */
    fun toCborMap(info: Ctap2Response.GetInfoResponse = getInfo()): Map<Long, Any> {
        // Omit optional empty collections (extensions, pinUvAuthProtocols, algorithms) to satisfy CTAP 2.3 §6.4 non-empty array constraints
        return buildMap {
            put(1L, info.versions)
            if (info.extensions.isNotEmpty()) {
                put(2L, info.extensions)
            }
            put(3L, info.aaguid)
            put(4L, info.options)
            put(5L, info.maxMsgSize.toLong())
            if (info.pinUvAuthProtocols.isNotEmpty()) {
                put(6L, info.pinUvAuthProtocols.map { it.toLong() })
            }
            // Advertise both hardware security key and platform transports so relying parties permit subsequent direct USB/NFC or hybrid authentication
            put(9L, listOf("usb", "nfc", "internal", "hybrid"))
            if (info.algorithms.isNotEmpty()) {
                put(10L, info.algorithms)
            }
        }
    }
}