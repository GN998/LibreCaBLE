package com.dev.fido.bridge.authenticator.proxy

import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.codec.CtapCodec.requireField
import com.dev.fido.bridge.core.ctap.codec.CtapCodecException
import com.dev.fido.bridge.core.ctap.codec.toWebAuthnUv
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.ctap.model.PrfExtensionInput
import com.dev.fido.bridge.core.ctap.model.PrfExtensionOutput
import com.dev.fido.bridge.core.ctap.model.PrfValues
import com.dev.fido.bridge.core.security.CryptoUtils
import org.json.JSONArray
import org.json.JSONObject

object CtapMapper {

    fun toWebAuthnGetCredentialJson(req: Ctap2Request.GetAssertion): String {
        return JSONObject().apply {
            // Set challenge to Base64URL-encoded clientDataHash required by Android CredentialManager WebAuthn API
            put("challenge", CryptoUtils.encodeBase64UrlNoPadding(req.clientDataHash))
            put("rpId", req.rpId)
            put("userVerification", req.userVerification)

            // Omit empty allowCredentials so Android CredentialManager providers do not reject discoverable credential lookups
            req.allowList?.takeIf { it.isNotEmpty() }?.let { list ->
                put("allowCredentials", list.toJsonArray())
            }
            req.prf?.takeIf { it.hasEvaluationInputs() }?.let { prf ->
                put("extensions", JSONObject().put("prf", prf.toJsonObject()))
            }
        }.toString()
    }

    fun toWebAuthnCreateCredentialJson(req: Ctap2Request.MakeCredential): String {
        return JSONObject().apply {
            // Set challenge to Base64URL-encoded clientDataHash required by Android CredentialManager WebAuthn API
            put("challenge", CryptoUtils.encodeBase64UrlNoPadding(req.clientDataHash))
            put("rp", JSONObject().apply {
                put("id", req.rpId)
                put("name", req.rpName)
            })
            put("user", JSONObject().apply {
                put("id", CryptoUtils.encodeBase64UrlNoPadding(req.userId))
                put("name", req.userName)
                put("displayName", req.userDisplayName)
            })
            put("pubKeyCredParams", JSONArray(req.pubKeyCredParams.map(::JSONObject)))

            // Forward excludeList to prevent re-registration of existing credentials
            req.excludeList?.takeIf { it.isNotEmpty() }?.let { list ->
                put("excludeCredentials", list.toJsonArray())
            }

            // Enforce non-discoverable credential creation when "rk" is false or absent per CTAP 2.3 §6.1.2 Step 14 to avoid exhausting hardware security key storage slots
            val rkRequired = req.options?.get("rk") ?: false
            val uvRequired = req.options?.get("uv")
            put("authenticatorSelection", JSONObject().apply {
                put("residentKey", if (rkRequired) "required" else "discouraged")
                put("requireResidentKey", rkRequired)
                put("userVerification", uvRequired.toWebAuthnUv())
            })
            // Request direct attestation from the underlying credential provider so hardware or vendor
            // attestation statements (fmt, attStmt) and AAGUID are preserved over CTAP2; the client
            // platform remains responsible for applying the RP's attestation conveyance preference.
            put("attestation", "direct")
            // Forward "prf" during MakeCredential only when immediate evaluation salts are present;
            // Windows 11 unconditionally sends an empty {"prf": {}} whenever GetInfo advertises "prf",
            // which otherwise causes hardware-key providers to emit a signed {"hmac-secret": true}
            // extension in authData that Chromium rejects when the RP did not request PRF.
            req.prf?.takeIf { it.hasEvaluationInputs() }?.let { prf ->
                put("extensions", JSONObject().put("prf", prf.toJsonObject()))
            }
        }.toString()
    }

    private fun PrfExtensionInput.hasEvaluationInputs(): Boolean =
        eval != null || !evalByCredential.isNullOrEmpty()

    /**
     * Serialize pre-hashed CTAP2 PRF inputs into WebAuthn JSON with "prfAlreadyHashed": true
     * so downstream Android credential providers do not double-hash the 32-byte salts.
     */
    private fun PrfExtensionInput.toJsonObject(): JSONObject = JSONObject().apply {
        eval?.let { put("eval", it.toJsonObject()) }
        evalByCredential?.takeIf { it.isNotEmpty() }?.let { map ->
            put("evalByCredential", JSONObject().apply {
                map.forEach { (credIdB64, vals) -> put(credIdB64, vals.toJsonObject()) }
            })
        }
        put("prfAlreadyHashed", true)
    }

    private fun PrfValues.toJsonObject(): JSONObject = JSONObject().apply {
        put("first", CryptoUtils.encodeBase64UrlNoPadding(first))
        second?.let { put("second", CryptoUtils.encodeBase64UrlNoPadding(it)) }
    }

    private fun parsePrfOutputFromClientExtensionResults(
        rootObj: JSONObject,
        isRegistration: Boolean = false
    ): PrfExtensionOutput? {
        val prfObj = rootObj.optJSONObject("clientExtensionResults")?.optJSONObject("prf") ?: return null
        val results = prfObj.optJSONObject("results")?.let { resObj ->
            val firstStr = resObj.optString("first", "")
            if (firstStr.isEmpty()) return@let null
            val firstBytes = CryptoUtils.decodeBase64Url(firstStr).takeIf { it.size == 32 } ?: return@let null
            val secondBytes = resObj.optString("second", "").takeIf { it.isNotEmpty() }
                ?.let { CryptoUtils.decodeBase64Url(it) }
                ?.takeIf { it.size == 32 }
            PrfValues(first = firstBytes, second = secondBytes)
        }
        // Default enabled to true during registration if the provider returned PRF results without an explicit enabled boolean
        val enabled = when {
            prfObj.has("enabled") -> prfObj.optBoolean("enabled")
            isRegistration && results != null -> true
            else -> null
        }
        if (enabled == null && results == null) return null
        return PrfExtensionOutput(enabled = enabled, results = results)
    }

    /**
     * Convert list of CTAP CredentialDescriptors into WebAuthn allowCredentials/excludeCredentials JSONArray.
     */
    private fun List<CredentialDescriptor>.toJsonArray(): JSONArray = JSONArray().apply {
        forEach { item ->
            put(JSONObject().apply {
                put("type", item.type)
                put("id", CryptoUtils.encodeBase64UrlNoPadding(item.id))
                // Forward optional transports array when provided by the client platform
                item.transports?.takeIf { it.isNotEmpty() }?.let { transports ->
                    put("transports", JSONArray(transports))
                }
            })
        }
    }

    fun parseAssertionResponseJson(
        jsonResponseStr: String,
        allowList: List<CredentialDescriptor>? = null
    ): Ctap2Response.GetAssertionResponse {
        val rootObj = JSONObject(jsonResponseStr)
        // Extract selected credential ID from authenticationResponseJson first so multi-credential allowLists return the exact match
        val idStr = rootObj.optString("rawId", "").ifEmpty { rootObj.optString("id", "") }
        val credentialId = if (idStr.isNotEmpty()) {
            CryptoUtils.decodeBase64Url(idStr)
        } else {
            allowList?.firstOrNull()?.id ?: ByteArray(0)
        }

        val responseObj = rootObj.getJSONObject("response")
        // Guard against JSONObject.NULL before calling optString so Android's org.json does not coerce null userHandles from non-discoverable hardware keys into literal "null" strings
        val userHandle = if (!responseObj.isNull("userHandle")) {
            responseObj.optString("userHandle", "").takeIf { it.isNotEmpty() }?.let { CryptoUtils.decodeBase64Url(it) }
        } else {
            null
        }

        return Ctap2Response.GetAssertionResponse(
            credentialId = credentialId,
            authenticatorData = CryptoUtils.decodeBase64Url(responseObj.getString("authenticatorData")),
            signature = CryptoUtils.decodeBase64Url(responseObj.getString("signature")),
            userHandle = userHandle,
            // Set userSelected to true when the user selected a discoverable credential on the authenticator UI per CTAP 2.3 §6.2.2
            userSelected = allowList.isNullOrEmpty(),
            prf = parsePrfOutputFromClientExtensionResults(rootObj)
        )
    }

    fun parseMakeCredentialResponseJson(
        jsonResponseStr: String,
        prfRequested: Boolean = false
    ): Ctap2Response.MakeCredentialResponse {
        val rootObj = JSONObject(jsonResponseStr)
        val responseObj = rootObj.getJSONObject("response")
        val attestationObjectBytes = CryptoUtils.decodeBase64Url(responseObj.getString("attestationObject"))

        // Decode provider-generated WebAuthn attestationObject using non-strict RFC 8949 rules before canonical CTAP2 re-encoding
        val map = CtapCodec.SimpleCbor.read(attestationObjectBytes, strict = false) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "attestationObject must be a CBOR map")

        // Report enabled=true in unsignedExtensionOutputs when the client sent an empty MakeCredential
        // "prf" dictionary that was omitted from the provider request to keep hardware authData clean.
        val prfOutput = parsePrfOutputFromClientExtensionResults(rootObj, isRegistration = true)
            ?: if (prfRequested) PrfExtensionOutput(enabled = true) else null

        return Ctap2Response.MakeCredentialResponse(
            fmt = map.requireField("fmt", "attestationObject.fmt"),
            authData = map.requireField("authData", "attestationObject.authData"),
            attStmt = map.requireField("attStmt", "attestationObject.attStmt"),
            prf = prfOutput
        )
    }
}