package com.dev.fido.bridge.authenticator.transport

import android.bluetooth.BluetoothAdapter
import android.util.Log
import com.dev.fido.bridge.authenticator.transport.ble.AuthenticatorL2capChannel
import com.dev.fido.bridge.authenticator.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.authenticator.transport.noise.NoiseSession
import com.dev.fido.bridge.authenticator.transport.websocket.TunnelWebsocket
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.transport.PxpDataChannel
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser,
    private val adapterProvider: () -> BluetoothAdapter? = { null }
) {
    companion object {
        // Pre-serialize immutable post-handshake CBOR payload once to eliminate encoding overhead during handshake
        private val CACHED_POST_HANDSHAKE_MSG: ByteArray by lazy {
            // Share canonical AuthenticatorInfo CBOR map to prevent capability drift between pre-flight and 0x04 GetInfo
            val getInfoBytes = CtapCodec.SimpleCbor.write(AuthenticatorInfo.toCborMap())
            // Advertise only "ctap" support in Key 3 so clients do not send unimplemented typeJSON (0x03) Digital Credentials frames per CTAP 2.3 §11.5
            val postHandshakeMap = mapOf(
                1L to getInfoBytes,
                3L to listOf("ctap")
            )
            CtapCodec.SimpleCbor.write(postHandshakeMap)
        }
    }

    @Volatile
    private var activeChannel: PxpDataChannel? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile
    private var handshakeTimeoutJob: Job? = null

    @Volatile
    var onStatusUpdate: ((String) -> Unit)? = null
    // Notify controller when a transaction finishes or the tunnel closes to decouple control flow from log strings
    @Volatile
    var onSessionTerminated: (() -> Unit)? = null

    /**
     * Atomically clear active session references if owned by [channel] so concurrent
     * callbacks and stopSession() never double-close or leak watchdog jobs.
     */
    private fun clearActiveSession(channel: PxpDataChannel): Boolean = synchronized(this) {
        if (activeChannel === channel) {
            handshakeTimeoutJob?.cancel()
            handshakeTimeoutJob = null
            activeChannel = null
            true
        } else {
            false
        }
    }

    // Synchronize session startup with stopSession() so rapid consecutive scans cancel prior setup coroutines before launching new ones
    @Synchronized
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int,
        supportedTransports: Set<Int> = setOf(0),
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        // Terminate any lingering transport channel, BLE advertisement, or coroutine job
        // from a prior scan before starting a new hybrid transport session.
        stopSession()

        // Offload session setup from the UI thread while validating and setting the peer public key
        // prior to opening the channel to prevent race conditions with onConnected and avoid socket leaks.
        transportScope.launch {
            // Instantiate a dedicated NoiseSession and busy guard per transport session to prevent cross-session state races
            val sessionNoise = NoiseSession()
            val isProcessingCtap = AtomicBoolean(false)
            try {
                val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
                sessionNoise.prepareSession(uncompressedPeerKey)
            } catch (e: Exception) {
                Log.e("TransportManager", "Invalid peer public key", e)
                onStatusUpdate?.invoke("Error: ${e.message}")
                onSessionTerminated?.invoke()
                return@launch
            }

            // Pre-derive the 64-byte EID key before connecting so BLE advertising can start immediately
            val eidKey = CryptoHelper.endif(
                ikm = psk,
                salt = ByteArray(0),
                info = byteArrayOf(1, 0, 0, 0),
                length = 64
            )

            // Synchronize frame encryption and channel enqueueing under sessionNoise monitor to prevent
            // out-of-order AES-GCM write nonces when reader-thread 0x06 busy replies race with IO-thread CTAP responses.
            fun sendEncryptedFrame(channel: PxpDataChannel, plaintext: ByteArray) {
                synchronized(sessionNoise) {
                    channel.sendFrame(sessionNoise.encrypt(plaintext))
                }
            }

            fun startAdvertisingForChannel(
                channel: PxpDataChannel,
                routingId: ByteArray,
                effectiveDomainId: Int,
                serverPsm: Int?,
                onAdvertFailed: (Int) -> Unit
            ): Boolean {
                if (activeChannel !== channel) return false

                // 1. Generate the single 16-byte advertPlaintext seed (containing nonce, routingId, domainId)
                val advertPlaintext = CryptoHelper.generateSeed(routingId, effectiveDomainId)

                // 2. Encrypt the EXACT advertPlaintext seed to 20-byte BLE EID using pre-derived eidKey
                val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                // 3. Derive 32-byte Noise PSK and initialize KNpsk0 state machine before starting radio advertising
                val noisePsk = CryptoHelper.endif(
                    ikm = psk,
                    salt = advertPlaintext,
                    info = byteArrayOf(3, 0, 0, 0),
                    length = 32
                )
                sessionNoise.initializeHandshake(noisePsk)

                // 4. Dispatch BLE advertising (with optional L2CAP PSM suffix)
                val bleDispatched = bleAdvertiser.startAdvertising(finalEid, serverPsm) { errorCode ->
                    onAdvertFailed(errorCode)
                }
                if (!bleDispatched) {
                    return false
                }
                onStatusUpdate?.invoke("Connecting...")

                // Enforce a 60-second handshake deadline under monitor lock so stopSession() cannot race with watchdog creation
                synchronized(this@TransportManager) {
                    if (activeChannel === channel) {
                        handshakeTimeoutJob?.cancel()
                        handshakeTimeoutJob = transportScope.launch {
                            delay(60_000)
                            if (!sessionNoise.isHandshakeComplete && clearActiveSession(channel)) {
                                Log.w("TransportManager", "Handshake timed out waiting for ClientHello; closing session.")
                                onStatusUpdate?.invoke("Connection timed out")
                                bleAdvertiser.stopAdvertising()
                                channel.cancel()
                                onSessionTerminated?.invoke()
                            }
                        }
                    }
                }
                return true
            }

            fun handleInboundFrame(sourceChannel: PxpDataChannel, encryptedFrame: ByteArray) {
                if (activeChannel !== sourceChannel) return
                try {
                    if (!sessionNoise.isHandshakeComplete) {
                        Log.d("TransportManager", "Received ClientHello, processing Noise KNpsk0 handshake...")
                        val serverHello = sessionNoise.processClientHelloAndGenerateServerHello(encryptedFrame)

                        // Cancel the handshake watchdog and stop BLE proximity advertising after ClientHello is authenticated
                        synchronized(this@TransportManager) {
                            handshakeTimeoutJob?.cancel()
                            handshakeTimeoutJob = null
                        }
                        bleAdvertiser.stopAdvertising()

                        // Enqueue ServerHello and Post-Handshake frames back-to-back before UI dispatch to minimize round-trip latency
                        sourceChannel.sendFrame(serverHello)
                        sendEncryptedFrame(sourceChannel, CACHED_POST_HANDSHAKE_MSG)

                        Log.d("TransportManager", "Noise KNpsk0 Handshake Success! Sent Post-Handshake Message.")
                        onStatusUpdate?.invoke("Connected")
                    } else {
                        val decrypted = sessionNoise.decrypt(encryptedFrame)
                        // Treat empty post-handshake frames as a protocol error per CTAP 2.3 §11.5.1.2
                        require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                        val frameType = decrypted[0].toInt() and 0xFF
                        when (frameType) {
                            0x01 -> {
                                // Reject overlapping CTAP commands with ERR_CHANNEL_BUSY (0x06) per CTAP 2.3 §6 to prevent concurrent UI prompts
                                if (!isProcessingCtap.compareAndSet(false, true)) {
                                    Log.w("TransportManager", "Channel busy; rejecting concurrent CTAP request with 0x06")
                                    sendEncryptedFrame(sourceChannel, byteArrayOf(0x01, CtapStatus.ERR_CHANNEL_BUSY))
                                    return
                                }

                                val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                                // Avoid coercing empty CTAP payloads into a fake 0x00 command byte so logs reflect actual wire data
                                val commandByte = ctapReq.firstOrNull()
                                val cmdLabel = commandByte?.let { "0x%02X".format(it) } ?: "EMPTY"
                                Log.d("TransportManager", "Received CTAP Request ($cmdLabel)!")
                                onStatusUpdate?.invoke("Verifying...")

                                // Dispatch CTAP request asynchronously so transport reader thread remains responsive
                                transportScope.launch {
                                    try {
                                        val response = onRequestReceived(ctapReq)
                                        // Ensure coroutine was not cancelled and session was not replaced while awaiting UI prompt
                                        ensureActive()
                                        if (activeChannel !== sourceChannel) return@launch

                                        val framedResponse = byteArrayOf(0x01) + response
                                        sendEncryptedFrame(sourceChannel, framedResponse)

                                        // Close the channel cleanly after a MakeCredential (0x01) or GetAssertion (0x02) ceremony
                                        // unless it was a silent pre-flight probe (up=false), where the client expects the channel
                                        // to remain open for a subsequent interactive request per CTAP 2.3 §6.2.2.
                                        if (commandByte == 0x01.toByte() || commandByte == 0x02.toByte()) {
                                            val statusByte = response[0]
                                            val isSilentPreFlight = commandByte == 0x02.toByte() &&
                                                statusByte == CtapStatus.ERR_NO_CREDENTIALS &&
                                                runCatching {
                                                    val req = CtapCodec.decodeRequest(ctapReq)
                                                    req is com.dev.fido.bridge.core.ctap.model.Ctap2Request.GetAssertion && !req.userPresence
                                                }.getOrDefault(false)

                                            if (!isSilentPreFlight && clearActiveSession(sourceChannel)) {
                                                val msg = if (statusByte == CtapStatus.SUCCESS) {
                                                    "Completed"
                                                } else {
                                                    "Cancelled (0x${"%02X".format(statusByte)})"
                                                }
                                                onStatusUpdate?.invoke(msg)
                                                sourceChannel.close()
                                                onSessionTerminated?.invoke()
                                            } else if (statusByte != CtapStatus.SUCCESS) {
                                                onStatusUpdate?.invoke("Cancelled (0x${"%02X".format(statusByte)})")
                                            }
                                        }
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Log.e("TransportManager", "Error processing CTAP request", e)
                                        onStatusUpdate?.invoke("Error: ${e.message}")
                                        // Cancel the underlying channel on fatal CTAP dispatch errors to prevent orphaned keep-alive pings
                                        if (clearActiveSession(sourceChannel)) {
                                            sourceChannel.cancel()
                                            onSessionTerminated?.invoke()
                                        }
                                    } finally {
                                        isProcessingCtap.set(false)
                                    }
                                }
                            }
                            0x00 -> {
                                // Close session cleanly upon receiving client shutdown message (typeShutdown = 0) per CTAP 2.3 §11.5 / PXP §6.2
                                Log.d("TransportManager", "Received Shutdown message (0x00), closing channel.")
                                bleAdvertiser.stopAdvertising()
                                if (clearActiveSession(sourceChannel)) {
                                    onStatusUpdate?.invoke("Completed")
                                    sourceChannel.close()
                                    onSessionTerminated?.invoke()
                                }
                            }
                            else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                        }
                    }
                } catch (e: Exception) {
                    val msg = "Error: ${e.message}"
                    Log.e("TransportManager", msg, e)
                    bleAdvertiser.stopAdvertising()
                    // Cancel the channel when handshake or frame decryption fails so the session does not remain open indefinitely
                    if (clearActiveSession(sourceChannel)) {
                        sourceChannel.cancel()
                        onStatusUpdate?.invoke(msg)
                        onSessionTerminated?.invoke()
                    }
                }
            }

            fun startWebsocketFallback(priorChannel: PxpDataChannel?) {
                if (0 !in supportedTransports) {
                    if (priorChannel == null || clearActiveSession(priorChannel)) {
                        priorChannel?.cancel()
                        onStatusUpdate?.invoke("BLE L2CAP unavailable and WebSocket not supported by QR")
                        onSessionTerminated?.invoke()
                    }
                    return
                }

                val ephemeralTunnelId = CryptoHelper.endif(
                    ikm = psk,
                    salt = ByteArray(0),
                    info = byteArrayOf(2, 0, 0, 0),
                    length = 16
                )

                lateinit var sessionWs: TunnelWebsocket
                sessionWs = TunnelWebsocket(
                    domainId = domainId,
                    ephemeralTunnelId = ephemeralTunnelId,
                    onConnected = { routingId ->
                        val ok = startAdvertisingForChannel(
                            channel = sessionWs,
                            routingId = routingId,
                            effectiveDomainId = domainId,
                            serverPsm = null,
                            onAdvertFailed = { errorCode ->
                                if (clearActiveSession(sessionWs)) {
                                    sessionWs.cancel()
                                    onStatusUpdate?.invoke("BLE advertising failed ($errorCode)")
                                    onSessionTerminated?.invoke()
                                }
                            }
                        )
                        if (!ok && clearActiveSession(sessionWs)) {
                            onStatusUpdate?.invoke("Failed to start BLE advertising")
                            sessionWs.cancel()
                            onSessionTerminated?.invoke()
                        }
                    },
                    onMessageReceived = { frame -> handleInboundFrame(sessionWs, frame) },
                    onStatusUpdate = null,
                    onDisconnected = {
                        if (clearActiveSession(sessionWs)) {
                            bleAdvertiser.stopAdvertising()
                            onSessionTerminated?.invoke()
                        }
                    }
                )

                val shouldConnect = synchronized(this@TransportManager) {
                    ensureActive()
                    if (priorChannel == null || activeChannel === priorChannel) {
                        handshakeTimeoutJob?.cancel()
                        handshakeTimeoutJob = null
                        priorChannel?.cancel()
                        activeChannel = sessionWs
                        true
                    } else {
                        false
                    }
                }
                if (shouldConnect) {
                    bleAdvertiser.stopAdvertising()
                    sessionWs.connect()
                }
            }

            // Priority 1: Direct BLE L2CAP CoC when supported by both QR (Key 6 contains 1) and local controller per PXP §6.1.2
            if (1 in supportedTransports && bleAdvertiser.isExtendedAdvertisingSupported()) {
                lateinit var sessionL2cap: AuthenticatorL2capChannel
                sessionL2cap = AuthenticatorL2capChannel(
                    adapterProvider = adapterProvider,
                    onMessageReceived = { frame -> handleInboundFrame(sessionL2cap, frame) },
                    onDisconnected = {
                        // Fall back to WebSocket if L2CAP drops before completing the Noise handshake
                        if (!sessionNoise.isHandshakeComplete && 0 in supportedTransports) {
                            Log.w("TransportManager", "L2CAP disconnected pre-handshake; falling back to WebSocket")
                            startWebsocketFallback(priorChannel = sessionL2cap)
                        } else if (clearActiveSession(sessionL2cap)) {
                            bleAdvertiser.stopAdvertising()
                            onSessionTerminated?.invoke()
                        }
                    }
                )

                val psm = sessionL2cap.startServer()
                if (psm != null) {
                    synchronized(this@TransportManager) {
                        ensureActive()
                        activeChannel = sessionL2cap
                    }
                    val dispatched = startAdvertisingForChannel(
                        channel = sessionL2cap,
                        routingId = ByteArray(3),
                        effectiveDomainId = 0,
                        serverPsm = psm,
                        onAdvertFailed = { errorCode ->
                            Log.w("TransportManager", "Extended BLE advert failed ($errorCode); falling back to WebSocket")
                            startWebsocketFallback(priorChannel = sessionL2cap)
                        }
                    )
                    if (!dispatched) {
                        Log.w("TransportManager", "Extended BLE advert dispatch failed; falling back to WebSocket")
                        startWebsocketFallback(priorChannel = sessionL2cap)
                    }
                    return@launch
                }
            }

            // Priority 2 (Fallback): Standard WebSocket tunnel + Legacy 20-byte BLE advertisement
            startWebsocketFallback(priorChannel = null)
        }
    }

    @Synchronized
    fun stopSession() {
        handshakeTimeoutJob?.cancel()
        handshakeTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleAdvertiser.stopAdvertising()
        activeChannel?.cancel()
        activeChannel = null
    }
}