package com.dev.fido.bridge.core.transport

/**
 * Unified physical transport frame channel abstraction per PXP §6.1.
 * Decouples upper-layer Noise handshakes and CTAP2 state machines from underlying WebSocket or BLE L2CAP sockets.
 */
interface PxpDataChannel {
    fun sendFrame(data: ByteArray)
    fun close()
    fun cancel()
}