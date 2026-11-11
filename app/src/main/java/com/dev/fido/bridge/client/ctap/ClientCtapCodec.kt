package com.dev.fido.bridge.client.ctap

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.codec.CtapCodec.requireField
import com.dev.fido.bridge.core.ctap.codec.CtapCodecException
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.ctap.model.PrfExtensionInput
import com.dev.fido.bridge.core.ctap.model.PrfValues

/**
 * Client-side CTAP2 encoder (for outbound commands) and decoder (for inbound authenticator responses)
 * per CTAP 2.3 §6 & §8.
 */
object ClientCtapCodec {

    /**
     * Inspect the authenticator's raw GetInfo response bytes from the post-handshake message
     * and return whether built-in user verification (options["uv"]) is supported per CTAP 2.3 §6.4.
     */
    fun supportsBuiltInUv(getInfoBytes: ByteArray): Boolean {
        return runCatching {
            val cborSlice = if (getInfoBytes.isNotEmpty() && getInfoBytes[0] == CtapStatus.SUCCESS) {
                getInfoBytes.copyOfRange(1, getInfoBytes.size)
            } else {
                getInfoBytes
            }
            val infoMap = CtapCodec.SimpleCbor.read(cborSlice, strict = false) as? Map<*, *>
            val optionsMap = infoMap?.get(4L) as? Map<*, *>
            optionsMap?.get("uv") == true
        }.getOrDefault(false)
    }

    /**
     * Serialize a [Ctap2Request] into a wire command byte + canonical CBOR map.
     * Strip the "uv" option if the peer authenticator does not advertise built-in UV support
     * per CTAP 2.3 §6.1.1 / §6.2.2 to prevent protocol errors on restricted authenticators.
     */
    fun encodeRequest(
        request: Ctap2Request,
        authenticatorSupportsBuiltInUv: Boolean = true
    ): ByteArray {
        return when (request) {
            is Ctap2Request.GetInfo -> byteArrayOf(0x04)
            is Ctap2Request.Selection -> byteArrayOf(0x0B)
            is Ctap2Request.MakeCredential -> {
                val filteredOptions = request.options?.filterKeys { key ->
                    key != "uv" || authenticatorSupportsBuiltInUv
                }
                val map = buildMap<Long, Any> {
                    put(1L, request.clientDataHash)
                    put(2L, buildMap<String, Any> {
                        put("id", request.rpId)
                        if (request.rpName.isNotEmpty()) put("name", request.rpName)
                    })
                    put(3L, buildMap<String, Any> {
                        put("id", request.userId)
                        if (request.userName.isNotEmpty()) put("name", request.userName)
                        if (request.userDisplayName.isNotEmpty()) put("displayName", request.userDisplayName)
                    })
                    put(4L, request.pubKeyCredParams)
                    request.excludeList?.takeIf { it.isNotEmpty() }?.let { list ->
                        put(5L, list.map { it.toCborMap() })
                    }
                    // Preserve empty {"prf": {}} maps during MakeCredential so RPs that enable PRF at registration
                    // without immediate eval salts still trigger hmac-secret creation per WebAuthn Level 3 §10.1.4.
                    if (request.prf != null) {
                        put(6L, mapOf("prf" to request.prf.toCborMap()))
                    }
                    filteredOptions?.takeIf { it.isNotEmpty() }?.let { opts ->
                        put(7L, opts)
                    }
                }
                byteArrayOf(0x01) + CtapCodec.SimpleCbor.write(map)
            }
            is Ctap2Request.GetAssertion -> {
                val map = buildMap<Long, Any> {
                    put(1L, request.rpId)
                    put(2L, request.clientDataHash)
                    request.allowList?.takeIf { it.isNotEmpty() }?.let { list ->
                        put(3L, list.map { it.toCborMap() })
                    }
                    // Encode optional PRF extension dictionary in GetAssertion extensions (key 4) when non-empty
                    request.prf?.toCborMap()?.takeIf { it.isNotEmpty() }?.let { prfCbor ->
                        put(4L, mapOf("prf" to prfCbor))
                    }
                    val optionsMap = buildMap<String, Boolean> {
                        if (!request.userPresence) put("up", false)
                        val wantsUv = request.userVerification == "required" || request.userVerification == "preferred"
                        if (wantsUv && authenticatorSupportsBuiltInUv) {
                            put("uv", true)
                        }
                    }
                    if (optionsMap.isNotEmpty()) {
                        put(5L, optionsMap)
                    }
                }
                byteArrayOf(0x02) + CtapCodec.SimpleCbor.write(map)
            }
        }
    }

    private fun PrfExtensionInput.toCborMap(): Map<String, Any> = buildMap {
        eval?.let { put("eval", it.toCborMap()) }
        evalByCredential?.takeIf { it.isNotEmpty() }?.let { byCred ->
            put("evalByCredential", byCred.mapValues { (_, v) -> v.toCborMap() })
        }
    }

    private fun PrfValues.toCborMap(): Map<String, Any> = buildMap {
        put("first", first)
        second?.let { put("second", it) }
    }

    private fun CredentialDescriptor.toCborMap(): Map<String, Any> = buildMap {
        put("type", type)
        put("id", id)
        transports?.takeIf { it.isNotEmpty() }?.let { put("transports", it) }
    }

    /**
     * Decode a raw CTAP2 response payload (1-byte status code followed by optional CBOR map)
     * given the originating [commandByte] (0x01 MakeCredential, 0x02 GetAssertion, or 0x0B Selection).
     */
    fun decodeResponse(commandByte: Byte, rawResponse: ByteArray): Ctap2Response {
        if (rawResponse.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP response payload")
        }
        val status = rawResponse[0]
        if (status != CtapStatus.SUCCESS) {
            return Ctap2Response.ErrorResponse(status)
        }
        if (commandByte == 0x0B.toByte()) {
            if (rawResponse.size != 1) {
                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Selection response must not contain CBOR payload")
            }
            return Ctap2Response.SelectionResponse
        }

        val cborBytes = if (rawResponse.size > 1) rawResponse.copyOfRange(1, rawResponse.size) else ByteArray(0)
        // Use non-strict CBOR decoding for responses so authenticators with X.509 attestation certificates
        // or deeper extension structures do not fail the 4-level request depth check.
        val map = CtapCodec.SimpleCbor.read(cborBytes, strict = false) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CTAP response must be a CBOR map")

        return when (commandByte) {
            0x01.toByte() -> {
                val authData: ByteArray = map.requireField(2L, "MakeCredential.authData")
                // Enforce minimum 55-byte attested authData with AT flag (0x40) set per WebAuthn §6.1 & §6.5.1
                if (authData.size < 55 || (authData[32].toInt() and 0x40) == 0) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid MakeCredential authData")
                }
                Ctap2Response.MakeCredentialResponse(
                    fmt = map.requireField(1L, "MakeCredential.fmt"),
                    authData = authData,
                    attStmt = map.requireField(3L, "MakeCredential.attStmt"),
                    prf = CtapCodec.decodePrfExtensionOutput(map[6L])
                )
            }
            0x02.toByte() -> {
                val credMap = map[1L] as? Map<*, *>
                val credentialId = (credMap?.get("id") as? ByteArray) ?: ByteArray(0)
                val authData: ByteArray = map.requireField(2L, "GetAssertion.authData")
                val signature: ByteArray = map.requireField(3L, "GetAssertion.signature")
                // Enforce minimum 37-byte authData and non-empty signature per WebAuthn §6.1 & CTAP 2.3 §6.2
                if (authData.size < 37 || signature.isEmpty()) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid GetAssertion authData or signature")
                }
                val userMap = map[4L] as? Map<*, *>
                val userHandle = userMap?.get("id") as? ByteArray
                val userSelected = map[6L] == true
                // Extract unsignedExtensionOutputs from key 8 per CTAP 2.3 §6.2
                val prfOut = CtapCodec.decodePrfExtensionOutput(map[8L])
                Ctap2Response.GetAssertionResponse(
                    credentialId = credentialId,
                    authenticatorData = authData,
                    signature = signature,
                    userHandle = userHandle,
                    userSelected = userSelected,
                    prf = prfOut
                )
            }
            else -> throw CtapCodecException(CtapStatus.ERR_INVALID_COMMAND, "Unsupported response command context: $commandByte")
        }
    }
}