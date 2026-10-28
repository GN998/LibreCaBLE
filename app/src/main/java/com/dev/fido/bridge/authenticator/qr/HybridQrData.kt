package com.dev.fido.bridge.authenticator.qr

// Data class representing extracted FIDO URI parameters
data class HybridQrData(
    val publicKey: ByteArray,
    val secret: ByteArray,
    val tunnelServerId: Int,
    // Preserve optional creation timestamp (Key 3) to detect stale QR codes pre-handshake
    val timestampSeconds: Long? = null,
    // Default unknown or absent operation hints (Key 5) to "ga" per CTAP 2.3 §11.5.1.1
    val operationHint: String = "ga",
    // Default absent transport channel list (Key 6) to WebSockets (0) per PXP §5.3.1
    val supportedTransports: Set<Int> = setOf(0)
)