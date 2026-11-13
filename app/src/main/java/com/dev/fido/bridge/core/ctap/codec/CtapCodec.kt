package com.dev.fido.bridge.core.ctap.codec

import android.util.Half
import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.ctap.model.LargeBlobExtensionInput
import com.dev.fido.bridge.core.ctap.model.LargeBlobExtensionOutput
import com.dev.fido.bridge.core.ctap.model.PrfExtensionInput
import com.dev.fido.bridge.core.ctap.model.PrfExtensionOutput
import com.dev.fido.bridge.core.ctap.model.PrfValues
import java.io.ByteArrayOutputStream
import java.util.Arrays

/**
 * Custom exception representing CTAP codec errors with standard protocol status codes.
 */
class CtapCodecException(
    val statusCode: Byte,
    message: String,
    cause: Throwable? = null
) : IllegalArgumentException(message, cause)

/**
 * Map CTAP2 boolean "uv" option flag to WebAuthn userVerification requirement string.
 * Since AuthenticatorInfo advertises options["alwaysUv"] = true and options["uv"] = true,
 * CTAP 2.3 §6.1.2 Step 6.3 and §6.2.2 Step 5.4 mandate treating "uv" as true even when omitted or false.
 */
fun Boolean?.toWebAuthnUv(): String = "required"

object CtapCodec {

    // Include standard and post-quantum COSE algorithms across CTAP 2.0-2.3 so modern credential providers can negotiate newer key types while still rejecting bogus conformance probes pre-UI
    internal val SUPPORTED_COSE_ALGORITHMS = setOf(
        -7L, -8L, -9L, -35L, -36L, -37L, -38L, -39L, -47L,
        -48L, -49L, -50L, -257L, -258L, -259L, -65535L
    )

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP payload")
        }
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        // Centralize CBOR decoding error handling to avoid duplicating catch blocks across command parsers
        return try {
            when (commandByte) {
                0x04.toByte() -> {
                    if (cborBytes.isNotEmpty()) {
                        throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "GetInfo command must not contain parameters")
                    }
                    Ctap2Request.GetInfo
                }
                0x0B.toByte() -> {
                    if (cborBytes.isNotEmpty()) {
                        throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Selection command must not contain parameters")
                    }
                    Ctap2Request.Selection
                }
                0x01.toByte() -> decodeMakeCredential(cborBytes)
                0x02.toByte() -> decodeGetAssertion(cborBytes)
                else -> throw CtapCodecException(
                    CtapStatus.ERR_INVALID_COMMAND,
                    "Unsupported command byte: 0x${"%02X".format(commandByte)}"
                )
            }
        } catch (e: CtapCodecException) {
            throw e
        } catch (e: Exception) {
            Log.e("CtapCodec", "CTAP request decode error (command: 0x${"%02X".format(commandByte)})", e)
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid CTAP CBOR payload", e)
        }
    }

    /**
     * Extract and cast mandatory CBOR map fields while distinguishing missing keys (0x14) from type mismatches (0x11) per CTAP 2.3 §6.
     */
    internal inline fun <reified T> Map<*, *>.requireField(
        key: Any,
        name: String,
        missingStatus: Byte = CtapStatus.ERR_MISSING_PARAMETER
    ): T {
        val value = this[key]
            ?: throw CtapCodecException(missingStatus, "Missing required parameter: $name")
        return value as? T
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for parameter: $name")
    }

    private fun decodeMakeCredential(cborBytes: ByteArray): Ctap2Request.MakeCredential {
        val map = SimpleCbor.read(cborBytes) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "MakeCredential request must be a CBOR map")

        val clientDataHash = map.requireField<ByteArray>(1L, "clientDataHash")
        // Enforce 32-byte SHA-256 clientDataHash length before dispatching to Android CredentialManager
        if (clientDataHash.size != 32) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_LENGTH, "clientDataHash must be 32 bytes")
        }

        val rp = map.requireField<Map<*, *>>(2L, "rp")
        val rpId = rp.requireField<String>("id", "rp.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        val rpName = rp["name"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for rp.name")
        } ?: ""

        val user = map.requireField<Map<*, *>>(3L, "user")
        val userId = user.requireField<ByteArray>("id", "user.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        // Enforce WebAuthn §5.4.3 user handle length bounds (1..64 bytes)
        if (userId.isEmpty() || userId.size > 64) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_LENGTH, "user.id must be 1..64 bytes")
        }
        val userName = user["name"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for user.name")
        } ?: ""
        val userDisplayName = user["displayName"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for user.displayName")
        } ?: ""

        val pubKeyCredParamsRaw = map.requireField<List<*>>(4L, "pubKeyCredParams")

        // Validate every pubKeyCredParams element and ensure at least one supported public-key algorithm is present per CTAP 2.3 §6.1.2 Step 3
        val pubKeyCredParams = pubKeyCredParamsRaw.map { item ->
            val paramMap = item as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "pubKeyCredParams element must be a map")
            val type = paramMap.requireField<String>("type", "pubKeyCredParams.type", CtapStatus.ERR_INVALID_CBOR)
            // Enforce CBOR integer type for COSEAlgorithmIdentifier per CTAP 2.3 §6.1
            val alg = paramMap.requireField<Long>("alg", "pubKeyCredParams.alg", CtapStatus.ERR_INVALID_CBOR)

            mapOf(
                "type" to type,
                "alg" to alg
            )
        }
        if (pubKeyCredParams.none { it["type"] == "public-key" && it["alg"] in SUPPORTED_COSE_ALGORITHMS }) {
            throw CtapCodecException(CtapStatus.ERR_UNSUPPORTED_ALGORITHM, "No supported public-key algorithm in pubKeyCredParams")
        }

        // Extract excludeList (key 5) to prevent duplicate credential registration on the authenticator
        val excludeList = parseDescriptorList(map[5L], "excludeList")

        // Extract optional PRF and largeBlob extension inputs from extensions map (key 6) per WebAuthn Level 3 §10.1.4 & CTAP 2.3 §12.4
        val prf = parsePrfExtensionInput(map[6L], "MakeCredential.extensions")
        val largeBlob = parseLargeBlobMakeCredInput(map[6L])

        // Extract and strictly type-check options (key 7) such as resident key (rk) and user verification (uv) requirements per CTAP 2.3 §6.1.2
        val options = parseOptionsMap(map[7L], "MakeCredential.options")

        // Reject only "up"=false in MakeCredential to maintain forward compatibility with CTAP 2.1+ platforms that explicitly send "up"=true per CTAP 2.3 §6.1.2 Step 5
        if (options?.get("up") == false) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_OPTION, "Option 'up'=false is not valid in MakeCredential")
        }

        // Reject unsupported pinUvAuthParam (key 8) / pinUvAuthProtocol (key 9) per CTAP 2.3 §6.1.2 Step 4
        validatePinUvAuthFields(map, paramKey = 8L, protocolKey = 9L)

        // Reject enterpriseAttestation (key 10) since "ep" option is not advertised per CTAP 2.3 §6.1.2 Step 9.1
        map[10L]?.let { rawEp ->
            val ep = rawEp as? Long
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "enterpriseAttestation must be a CBOR unsigned integer")
            if (ep < 0L) {
                throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "enterpriseAttestation must be non-negative")
            }
            throw CtapCodecException(CtapStatus.ERR_INVALID_PARAMETER, "Enterprise attestation is not supported")
        }

        // Type-check optional attestationFormatsPreference (key 11) per CTAP 2.3 §6.1 & §8
        map[11L]?.let { rawFormats ->
            val formatList = rawFormats as? List<*>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "attestationFormatsPreference must be a CBOR array")
            if (formatList.any { it !is String }) {
                throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "attestationFormatsPreference elements must be text strings")
            }
        }

        return Ctap2Request.MakeCredential(
            clientDataHash = clientDataHash,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            pubKeyCredParams = pubKeyCredParams,
            excludeList = excludeList,
            options = options,
            prf = prf,
            largeBlob = largeBlob
        )
    }

    private fun decodeGetAssertion(cborBytes: ByteArray): Ctap2Request.GetAssertion {
        val map = SimpleCbor.read(cborBytes) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "GetAssertion request must be a CBOR map")

        val rpId = map.requireField<String>(1L, "rpId")
        val clientDataHash = map.requireField<ByteArray>(2L, "clientDataHash")
        // Enforce 32-byte SHA-256 clientDataHash length before dispatching to Android CredentialManager
        if (clientDataHash.size != 32) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_LENGTH, "clientDataHash must be 32 bytes")
        }

        val allowList = parseDescriptorList(map[3L], "allowList")

        // Extract optional PRF and largeBlob extension inputs from extensions map (key 4) per WebAuthn Level 3 §10.1.4 & CTAP 2.3 §12.4
        val prf = parsePrfExtensionInput(map[4L], "GetAssertion.extensions")
        val largeBlob = parseLargeBlobGetAssertInput(map[4L])

        // Validate CTAP2 options (key 5) per CTAP 2.3 §6.2.2 Step 4
        val options = parseOptionsMap(map[5L], "GetAssertion.options")
        if (options?.containsKey("rk") == true) {
            // Reject prohibited "rk" option in GetAssertion per CTAP 2.3 §6.2.2 Step 4.4
            throw CtapCodecException(CtapStatus.ERR_UNSUPPORTED_OPTION, "Option 'rk' is not supported in GetAssertion")
        }
        val uvFlag = options?.get("uv")
        // Default "up" to true when absent per CTAP 2.3 §6.2.2 Step 4.5
        val upFlag = options?.get("up") ?: true

        // Reject unsupported pinUvAuthParam (key 6) / pinUvAuthProtocol (key 7) per CTAP 2.3 §6.2.2 Step 2
        validatePinUvAuthFields(map, paramKey = 6L, protocolKey = 7L)

        return Ctap2Request.GetAssertion(
            rpId = rpId,
            clientDataHash = clientDataHash,
            allowList = allowList,
            userVerification = uvFlag.toWebAuthnUv(),
            userPresence = upFlag,
            prf = prf,
            largeBlob = largeBlob
        )
    }

    /**
     * Parse optional CTAP2 hybrid "prf" extension dictionary from extensions CBOR map.
     */
    private fun parsePrfExtensionInput(rawExtensions: Any?, fieldName: String): PrfExtensionInput? {
        if (rawExtensions == null) return null
        val extMap = rawExtensions as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName must be a CBOR map")
        val prfMap = extMap["prf"] as? Map<*, *> ?: return null

        val eval = (prfMap["eval"] as? Map<*, *>)?.let(::parsePrfValuesMap)
        // Require Base64URL-encoded credential ID text strings as evalByCredential keys per WebAuthn Level 3 §10.1.4
        val evalByCred = (prfMap["evalByCredential"] as? Map<*, *>)?.entries?.mapNotNull { (k, v) ->
            val credIdB64 = (k as? String)?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val vals = (v as? Map<*, *>)?.let(::parsePrfValuesMap) ?: return@mapNotNull null
            credIdB64 to vals
        }?.toMap()?.takeIf { it.isNotEmpty() }

        return PrfExtensionInput(eval = eval, evalByCredential = evalByCred)
    }

    private fun parsePrfValuesMap(map: Map<*, *>): PrfValues? {
        val first = (map["first"] as? ByteArray)?.takeIf { it.size == 32 } ?: return null
        val second = (map["second"] as? ByteArray)?.takeIf { it.size == 32 }
        return PrfValues(first = first, second = second)
    }

    /**
     * Decode PrfExtensionOutput from unsignedExtensionOutputs CBOR map (key 6 in MakeCredential, key 8 in GetAssertion).
     */
    internal fun decodePrfExtensionOutput(rawUnsignedExt: Any?): PrfExtensionOutput? {
        val prfMap = (rawUnsignedExt as? Map<*, *>)?.get("prf") as? Map<*, *> ?: return null
        val enabled = prfMap["enabled"] as? Boolean
        val results = (prfMap["results"] as? Map<*, *>)?.let(::parsePrfValuesMap)
        if (enabled == null && results == null) return null
        return PrfExtensionOutput(enabled = enabled, results = results)
    }

    /**
     * Serialize PrfExtensionOutput into a CBOR map for unsignedExtensionOutputs["prf"].
     */
    private fun encodePrfExtensionOutput(prf: PrfExtensionOutput): Map<String, Any> = buildMap {
        prf.enabled?.let { put("enabled", it) }
        prf.results?.let { res ->
            put("results", buildMap<String, Any> {
                put("first", res.first)
                res.second?.let { put("second", it) }
            })
        }
    }

    /**
     * Parse optional CTAP 2.3 §12.4 MakeCredential "largeBlob" extension input (`{support: "required" / "preferred"}`).
     */
    private fun parseLargeBlobMakeCredInput(rawExtensions: Any?): LargeBlobExtensionInput? {
        val extMap = rawExtensions as? Map<*, *> ?: return null
        val lbObj = extMap["largeBlob"] ?: return null
        val lbMap = lbObj as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob in MakeCredential must be a CBOR map")
        if (lbMap.keys != setOf<Any?>("support")) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid keys in MakeCredential largeBlob map")
        }
        val support = lbMap["support"] as? String
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob.support must be a text string")
        if (support != "required" && support != "preferred") {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid largeBlob.support value: $support")
        }
        return LargeBlobExtensionInput(support = support)
    }

    /**
     * Parse optional CTAP 2.3 §12.4 GetAssertion "largeBlob" extension input (`{read: true}` XOR `{write: bstr, originalSize: uint}`).
     */
    private fun parseLargeBlobGetAssertInput(rawExtensions: Any?): LargeBlobExtensionInput? {
        val extMap = rawExtensions as? Map<*, *> ?: return null
        val lbObj = extMap["largeBlob"] ?: return null
        val lbMap = lbObj as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob in GetAssertion must be a CBOR map")

        val hasRead = lbMap.containsKey("read")
        val hasWrite = lbMap.containsKey("write")
        val hasOrigSize = lbMap.containsKey("originalSize")

        // Enforce CTAP 2.3 §12.4 Step 2 mutual exclusion: (read only) XOR (write + originalSize)
        return when {
            hasRead && !hasWrite && !hasOrigSize && lbMap.size == 1 -> {
                if (lbMap["read"] != true) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob.read must be true")
                }
                LargeBlobExtensionInput(read = true)
            }
            !hasRead && hasWrite && hasOrigSize && lbMap.size == 2 -> {
                val writeBytes = lbMap["write"] as? ByteArray
                    ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob.write must be a byte string")
                val origSize = (lbMap["originalSize"] as? Long)?.takeIf { it >= 0L }
                    ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "largeBlob.originalSize must be an unsigned integer")
                LargeBlobExtensionInput(write = writeBytes, originalSize = origSize)
            }
            else -> throw CtapCodecException(
                CtapStatus.ERR_INVALID_CBOR,
                "largeBlob input must contain either 'read' or both 'write' and 'originalSize' per CTAP 2.3 §12.4"
            )
        }
    }

    /**
     * Decode LargeBlobExtensionOutput from unsignedExtensionOutputs CBOR map (key 6 in MakeCredential, key 8 in GetAssertion).
     */
    internal fun decodeLargeBlobExtensionOutput(rawUnsignedExt: Any?): LargeBlobExtensionOutput? {
        val lbMap = (rawUnsignedExt as? Map<*, *>)?.get("largeBlob") as? Map<*, *> ?: return null
        val supported = lbMap["supported"] as? Boolean
        val blob = lbMap["blob"] as? ByteArray
        val originalSize = (lbMap["originalSize"] as? Number)?.toLong()?.takeIf { it >= 0L }
        val written = lbMap["written"] as? Boolean
        if (supported == null && (blob == null || originalSize == null) && written == null) return null
        return LargeBlobExtensionOutput(
            supported = supported,
            blob = blob,
            originalSize = originalSize,
            written = written
        )
    }

    /**
     * Serialize LargeBlobExtensionOutput into a CBOR map for unsignedExtensionOutputs["largeBlob"] per CTAP 2.3 §12.4.
     */
    private fun encodeLargeBlobExtensionOutput(lb: LargeBlobExtensionOutput): Map<String, Any> = buildMap {
        lb.supported?.let { put("supported", it) }
        if (lb.blob != null && lb.originalSize != null) {
            put("blob", lb.blob)
            put("originalSize", lb.originalSize)
        }
        lb.written?.let { put("written", it) }
    }

    /**
     * Validate and extract the CTAP2 options map (Map<String, Boolean>), throwing ERR_CBOR_UNEXPECTED_TYPE on non-map or non-boolean values per CTAP 2.3 §6 & §8.
     */
    private fun parseOptionsMap(rawOptions: Any?, fieldName: String): Map<String, Boolean>? {
        if (rawOptions == null) return null
        val optionsMap = rawOptions as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName must be a CBOR map")
        return optionsMap.entries.associate { (k, v) ->
            val keyStr = k as? String
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName key must be a text string")
            val valBool = v as? Boolean
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName['$keyStr'] value must be a boolean")
            keyStr to valBool
        }
    }

    /**
     * Type-check and reject pinUvAuthParam / pinUvAuthProtocol fields when pinUvAuthProtocols is not supported
     * per CTAP 2.3 §6.1.2 Step 4 and §6.2.2 Step 2.
     */
    private fun validatePinUvAuthFields(map: Map<*, *>, paramKey: Long, protocolKey: Long) {
        val rawParam = map[paramKey]
        val rawProtocol = map[protocolKey]
        if (rawParam != null && rawParam !is ByteArray) {
            throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "pinUvAuthParam must be a CBOR byte string")
        }
        if (rawProtocol != null && (rawProtocol !is Long || rawProtocol < 0L)) {
            throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "pinUvAuthProtocol must be a CBOR unsigned integer")
        }
        if (rawParam != null) {
            if (rawProtocol == null) {
                throw CtapCodecException(CtapStatus.ERR_MISSING_PARAMETER, "Missing pinUvAuthProtocol for pinUvAuthParam")
            }
            throw CtapCodecException(CtapStatus.ERR_INVALID_PARAMETER, "Unsupported pinUvAuthProtocol: $rawProtocol")
        }
    }

    /**
     * Parse CBOR array of PublicKeyCredentialDescriptor maps shared by MakeCredential and GetAssertion.
     */
    private fun parseDescriptorList(rawList: Any?, fieldName: String): List<CredentialDescriptor>? {
        if (rawList == null) return null
        val list = rawList as? List<*>
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName must be a CBOR array")
        return list.map { item ->
            val descMap = item as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName element must be a map")
            val type = descMap.requireField<String>("type", "$fieldName.type", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            val id = descMap.requireField<ByteArray>("id", "$fieldName.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            // Validate optional transports array per CTAP 2.3 §8 external structure typing rules
            val transports = descMap["transports"]?.let { rawTransports ->
                val transportList = rawTransports as? List<*>
                    ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName.transports must be a CBOR array")
                transportList.map { t ->
                    t as? String
                        ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName.transports element must be a text string")
                }
            }
            CredentialDescriptor(type = type, id = id, transports = transports)
        }
    }

    fun encodeResponse(response: Ctap2Response): ByteArray {
        return when (response) {
            is Ctap2Response.ErrorResponse -> byteArrayOf(response.errorCode)
            is Ctap2Response.SelectionResponse -> byteArrayOf(CtapStatus.SUCCESS)
            is Ctap2Response.GetInfoResponse -> {
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(AuthenticatorInfo.toCborMap(response))
            }
            is Ctap2Response.MakeCredentialResponse -> {
                val map = mutableMapOf<Long, Any>(
                    1L to response.fmt,
                    2L to response.authData,
                    3L to response.attStmt
                )
                // Aggregate unsignedExtensionOutputs (key 6) across prf and largeBlob per CTAP 2.3 §6.1 & §12.4
                val unsignedExt = buildMap<String, Any> {
                    response.prf?.let { put("prf", encodePrfExtensionOutput(it)) }
                    response.largeBlob?.let {
                        val encoded = encodeLargeBlobExtensionOutput(it)
                        if (encoded.isNotEmpty()) put("largeBlob", encoded)
                    }
                }
                if (unsignedExt.isNotEmpty()) {
                    map[6L] = unsignedExt
                }
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(map)
            }
            is Ctap2Response.GetAssertionResponse -> {
                val map = mutableMapOf<Long, Any>(
                    2L to response.authenticatorData,
                    3L to response.signature
                )
                if (response.credentialId.isNotEmpty()) {
                    map[1L] = mapOf("id" to response.credentialId, "type" to "public-key")
                }
                response.userHandle?.let { map[4L] = mapOf("id" to it) }
                if (response.userSelected) {
                    map[6L] = true
                }
                // Aggregate unsignedExtensionOutputs (key 8) across prf and largeBlob per CTAP 2.3 §6.2 & §12.4
                // (key 7 is reserved for largeBlobKey byte string)
                val unsignedExt = buildMap<String, Any> {
                    response.prf?.let { put("prf", encodePrfExtensionOutput(it)) }
                    response.largeBlob?.let {
                        val encoded = encodeLargeBlobExtensionOutput(it)
                        if (encoded.isNotEmpty()) put("largeBlob", encoded)
                    }
                }
                if (unsignedExt.isNotEmpty()) {
                    map[8L] = unsignedExt
                }
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(map)
            }
        }
    }

    // A lightweight, dependency-free CBOR encoder/decoder optimized for FIDO structures
    object SimpleCbor {
        /**
         * Decode CBOR byte stream into Kotlin primitives and collections.
         * Enforce strict CTAP 2.3 §8 canonical constraints by default, while allowing relaxed RFC 8949
         * decoding when parsing internal WebAuthn attestationObjects returned by Android credential providers.
         */
        fun read(
            bytes: ByteArray,
            strict: Boolean = true,
            allowTrailingBytes: Boolean = false
        ): Any? {
            if (bytes.isEmpty()) {
                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CBOR byte stream")
            }
            // Allow up to 5 container nesting levels in strict mode to accommodate extensions.prf.evalByCredential.<credId> maps
            val maxDepth = if (strict) 5 else 8
            var pos = 0
            fun readByte(): Int {
                if (pos >= bytes.size) throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unexpected end of CBOR stream")
                return bytes[pos++].toInt() and 0xFF
            }
            // Bound declared CBOR item length against remaining unconsumed stream bytes to prevent 32-bit addition overflow and oversized loops
            fun requireIntLength(v: Long): Int {
                val remaining = bytes.size - pos
                if (v < 0L || v > remaining.toLong()) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR item length overflow: $v")
                }
                return v.toInt()
            }
            fun readBytes(len: Int): ByteArray {
                val res = bytes.copyOfRange(pos, pos + len)
                pos += len
                return res
            }
            fun readItem(depth: Int): Any? {
                val b = readByte()
                val majorType = b shr 5
                val info = b and 0x1F

                // Decode unsigned argument and enforce CTAP 2.3 §8 canonical minimal-length integer encoding when strict
                val value: Long = when {
                    info < 24 -> info.toLong()
                    info == 24 -> {
                        val v = readByte().toLong()
                        if (strict && majorType != 7 && v < 24L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 1-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 25 -> {
                        val v = ((readByte() shl 8) or readByte()).toLong()
                        if (strict && majorType != 7 && v < 0x100L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 2-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 26 -> {
                        val i = (readByte() shl 24) or (readByte() shl 16) or (readByte() shl 8) or readByte()
                        val v = i.toLong() and 0xFFFFFFFFL
                        if (strict && majorType != 7 && v < 0x10000L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 4-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 27 -> {
                        val v = (readByte().toLong() shl 56) or
                            (readByte().toLong() shl 48) or
                            (readByte().toLong() shl 40) or
                            (readByte().toLong() shl 32) or
                            (readByte().toLong() shl 24) or
                            (readByte().toLong() shl 16) or
                            (readByte().toLong() shl 8) or
                            readByte().toLong()
                        // Reject MSB-overflowing (< 0L) 8-byte integers, and reject non-canonical (< 2^32) encodings when strict per CTAP 2.3 §8
                        if (majorType != 7 && (v < 0L || (strict && v < 0x100000000L))) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 8-byte CBOR integer encoding")
                        }
                        v
                    }
                    // Reject indefinite-length items (info == 31) and reserved additional info (28..30) per CTAP 2.3 §8
                    else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported or indefinite-length CBOR info: $info")
                }

                return when (majorType) {
                    0 -> value
                    1 -> -1L - value
                    2 -> readBytes(requireIntLength(value))
                    3 -> String(readBytes(requireIntLength(value)), Charsets.UTF_8)
                    4 -> {
                        // Enforce CTAP 2.3 §8 maximum CBOR container nesting depth (4 levels for wire commands)
                        if (depth >= maxDepth) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR nesting depth exceeds limit of $maxDepth")
                        }
                        val len = requireIntLength(value)
                        val list = mutableListOf<Any?>()
                        for (i in 0 until len) list.add(readItem(depth + 1))
                        list
                    }
                    5 -> {
                        if (depth >= maxDepth) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR nesting depth exceeds limit of $maxDepth")
                        }
                        val len = requireIntLength(value)
                        val map = linkedMapOf<Any?, Any?>()
                        for (i in 0 until len) {
                            val k = readItem(depth + 1)
                            // Reject duplicate map keys per CTAP 2.3 §8 canonical CBOR decoding rules
                            if (map.containsKey(k)) {
                                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Duplicate CBOR map key: $k")
                            }
                            map[k] = readItem(depth + 1)
                        }
                        map
                    }
                    7 -> {
                        when (info) {
                            20 -> false
                            21 -> true
                            22 -> null
                            // Preserve exact 16-, 32-, and 64-bit IEEE 754 float widths per CTAP 2.3 §8
                            25 -> Half.valueOf(value.toShort())
                            26 -> Float.fromBits(value.toInt())
                            27 -> Double.fromBits(value)
                            else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported CBOR simple value or float: $info")
                        }
                    }
                    else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported CBOR major type: $majorType")
                }
            }
            val root = readItem(0)
            // Reject trailing unconsumed bytes unless parsing an embedded prefix structure (e.g., COSE_Key in authData)
            if (!allowTrailingBytes && pos != bytes.size) {
                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Trailing bytes after root CBOR item: ${bytes.size - pos}")
            }
            return root
        }

        fun write(value: Any?): ByteArray {
            // Use ByteArrayOutputStream to avoid O(N^2) array allocations during serialization
            val out = ByteArrayOutputStream()
            fun writeMajor(major: Int, v: Long) {
                val type = major shl 5
                when {
                    v < 24 -> out.write(type or v.toInt())
                    v < 0x100 -> {
                        out.write(type or 24)
                        out.write(v.toInt())
                    }
                    v < 0x10000 -> {
                        out.write(type or 25)
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                    v < 0x100000000L -> {
                        out.write(type or 26)
                        out.write((v shr 24).toInt())
                        out.write((v shr 16).toInt())
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                    else -> {
                        out.write(type or 27)
                        out.write((v shr 56).toInt())
                        out.write((v shr 48).toInt())
                        out.write((v shr 40).toInt())
                        out.write((v shr 32).toInt())
                        out.write((v shr 24).toInt())
                        out.write((v shr 16).toInt())
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                }
            }
            fun writeItem(v: Any?) {
                when (v) {
                    null -> out.write(0xF6)
                    is Byte, is Short, is Int, is Long -> {
                        val l = (v as Number).toLong()
                        if (l >= 0L) writeMajor(0, l) else writeMajor(1, -1L - l)
                    }
                    // Preserve exact 16-, 32-, and 64-bit IEEE 754 float widths per CTAP 2.3 §8
                    is Half -> {
                        val bits = v.halfValue().toInt() and 0xFFFF
                        out.write(0xF9)
                        out.write(bits ushr 8)
                        out.write(bits)
                    }
                    is Float -> {
                        val bits = v.toRawBits()
                        out.write(0xFA)
                        out.write(bits ushr 24)
                        out.write(bits ushr 16)
                        out.write(bits ushr 8)
                        out.write(bits)
                    }
                    is Double -> {
                        val bits = v.toRawBits()
                        out.write(0xFB)
                        out.write((bits ushr 56).toInt())
                        out.write((bits ushr 48).toInt())
                        out.write((bits ushr 40).toInt())
                        out.write((bits ushr 32).toInt())
                        out.write((bits ushr 24).toInt())
                        out.write((bits ushr 16).toInt())
                        out.write((bits ushr 8).toInt())
                        out.write(bits.toInt())
                    }
                    is Boolean -> out.write(if (v) 0xF5 else 0xF4)
                    is ByteArray -> { writeMajor(2, v.size.toLong()); out.write(v) }
                    is String -> { val b = v.toByteArray(Charsets.UTF_8); writeMajor(3, b.size.toLong()); out.write(b) }
                    is List<*> -> { writeMajor(4, v.size.toLong()); v.forEach { writeItem(it) } }
                    is Map<*, *> -> {
                        writeMajor(5, v.size.toLong())
                        // Sort encoded map keys in bytewise lexicographic order per CTAP 2.3 §8 (major type, then length, then value)
                        val sortedEntries = v.entries.map { (k, vl) ->
                            write(k) to vl
                        }.sortedWith { a, b ->
                            Arrays.compareUnsigned(a.first, b.first)
                        }
                        sortedEntries.forEach { (kBytes, vl) ->
                            out.write(kBytes)
                            writeItem(vl)
                        }
                    }
                    else -> throw CtapCodecException(
                        CtapStatus.ERR_INVALID_CBOR,
                        "Unsupported CBOR value type: ${v.javaClass.simpleName}"
                    )
                }
            }
            writeItem(value)
            return out.toByteArray()
        }
    }
}