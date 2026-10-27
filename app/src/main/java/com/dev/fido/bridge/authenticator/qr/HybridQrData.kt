package com.dev.fido.bridge.core.hybrid

// Data class representing extracted FIDO URI parameters
data class HybridQrData(
    val publicKey: ByteArray,
    val secret: ByteArray,
    val tunnelServerId: Int,
    // Preserve optional creation timestamp (Key 3) to detect stale QR codes pre-handshake
    val timestampSeconds: Long? = null,
    // Default unknown or absent operation hints (Key 5) to "ga" per CTAP 2.3 §11.5.1.1
    val operationHint: String = "ga"
)