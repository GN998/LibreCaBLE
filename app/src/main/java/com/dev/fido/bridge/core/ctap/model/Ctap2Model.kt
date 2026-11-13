package com.dev.fido.bridge.core.ctap.model

/**
 * Represent a pair of 32-byte pre-hashed PRF evaluation salts or outputs per WebAuthn Level 3 §10.1.4.
 */
data class PrfValues(
    val first: ByteArray,
    val second: ByteArray? = null
)

/**
 * Represent CTAP2/WebAuthn PRF extension request inputs (eval and optional evalByCredential map keyed by Base64URL credential ID).
 */
data class PrfExtensionInput(
    val eval: PrfValues? = null,
    val evalByCredential: Map<String, PrfValues>? = null
)

/**
 * Represent CTAP2/WebAuthn PRF extension response outputs carried in unsignedExtensionOutputs["prf"].
 */
data class PrfExtensionOutput(
    val enabled: Boolean? = null,
    val results: PrfValues? = null
)

/**
 * Represent CTAP 2.3 §12.4 largeBlob extension request inputs.
 * On the CTAP wire, [write] carries RFC 1951 DEFLATE-compressed bytes alongside [originalSize].
 */
data class LargeBlobExtensionInput(
    val support: String? = null,
    val read: Boolean? = null,
    val write: ByteArray? = null,
    val originalSize: Long? = null
)

/**
 * Represent CTAP 2.3 §12.4 largeBlob extension response outputs carried in unsignedExtensionOutputs["largeBlob"].
 * On the CTAP wire, [blob] carries RFC 1951 DEFLATE-compressed bytes alongside [originalSize].
 */
data class LargeBlobExtensionOutput(
    val supported: Boolean? = null,
    val blob: ByteArray? = null,
    val originalSize: Long? = null,
    val written: Boolean? = null
)

sealed class Ctap2Request {
    // Use singleton data objects to avoid allocating dummy fields for stateless GetInfo and Selection requests
    data object GetInfo : Ctap2Request()
    data object Selection : Ctap2Request()

    data class GetAssertion(
        val rpId: String,
        val clientDataHash: ByteArray,
        val allowList: List<CredentialDescriptor>? = null,
        val userVerification: String,
        // Default "up" to true per CTAP 2.3 §6.2.2 Step 4.5; false indicates a silent pre-flight probe
        val userPresence: Boolean = true,
        val prf: PrfExtensionInput? = null,
        val largeBlob: LargeBlobExtensionInput? = null
    ) : Ctap2Request()

    data class MakeCredential(
        val clientDataHash: ByteArray,
        val rpId: String,
        val rpName: String,
        val userId: ByteArray,
        val userName: String,
        val userDisplayName: String,
        val pubKeyCredParams: List<Map<String, Any>>,
        val excludeList: List<CredentialDescriptor>? = null,
        val options: Map<String, Boolean>? = null,
        val prf: PrfExtensionInput? = null,
        val largeBlob: LargeBlobExtensionInput? = null
    ) : Ctap2Request()
}

data class CredentialDescriptor(
    val type: String,
    val id: ByteArray,
    // Preserve optional transport hints so CredentialManager providers can route credential lookups accurately
    val transports: List<String>? = null
)

sealed class Ctap2Response {
    data class GetInfoResponse(
        val versions: List<String>,
        val extensions: List<String>,
        val aaguid: ByteArray,
        val options: Map<String, Boolean>,
        val maxMsgSize: Int,
        val pinUvAuthProtocols: List<Int>,
        val algorithms: List<Map<String, Any>> = emptyList()
    ) : Ctap2Response()

    data object SelectionResponse : Ctap2Response()

    data class GetAssertionResponse(
        val credentialId: ByteArray,
        val authenticatorData: ByteArray,
        val signature: ByteArray,
        val userHandle: ByteArray? = null,
        // Indicate whether a credential was explicitly selected via the authenticator UI per CTAP 2.3 §6.2.2
        val userSelected: Boolean = false,
        val prf: PrfExtensionOutput? = null,
        val largeBlob: LargeBlobExtensionOutput? = null
    ) : Ctap2Response()

    data class MakeCredentialResponse(
        val fmt: String,
        val authData: ByteArray,
        val attStmt: Map<*, *>,
        val prf: PrfExtensionOutput? = null,
        val largeBlob: LargeBlobExtensionOutput? = null
    ) : Ctap2Response()

    data class ErrorResponse(val errorCode: Byte) : Ctap2Response()
}