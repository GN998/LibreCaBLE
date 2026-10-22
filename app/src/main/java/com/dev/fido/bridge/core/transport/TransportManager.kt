package com.dev.fido.bridge.core.transport

import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.transport.ble.HybridBleAdvertiser
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseSession
import com.dev.fido.bridge.core.transport.websocket.TunnelWebsocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch

class TransportManager(
    private val bleAdvertiser: HybridBleAdvertiser
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
    private var tunnelWebsocket: TunnelWebsocket? = null
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile
    private var handshakeTimeoutJob: Job? = null

    var onStatusUpdate: ((String) -> Unit)? = null
    // Notify controller when a transaction finishes or the tunnel closes to decouple control flow from log strings
    var onSessionTerminated: (() -> Unit)? = null

    // Support suspending callback to prevent blocking OkHttp reader thread during UI credential prompts
    fun startSession(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int,
        onRequestReceived: suspend (ByteArray) -> ByteArray
    ) {
        // Terminate any lingering WebSocket connection, BLE advertisement, or coroutine job
        // from a prior scan before starting a new hybrid transport session.
        stopSession()

        // Offload session setup from the UI thread while validating and setting the peer public key
        // prior to opening the WebSocket to prevent race conditions with onConnected and avoid socket leaks.
        transportScope.launch {
            // Instantiate a dedicated NoiseSession per transport session to prevent cross-session state races on rapid re-scans
            val sessionNoise = NoiseSession()
            try {
                val uncompressedPeerKey = CryptoHelper.decompressECKey(peerPublicKey)
                sessionNoise.prepareSession(uncompressedPeerKey)
            } catch (e: Exception) {
                Log.e("TransportManager", "Invalid peer public key", e)
                onStatusUpdate?.invoke("Error: ${e.message}")
                onSessionTerminated?.invoke()
                return@launch
            }

            val ephemeralTunnelId = CryptoHelper.endif(
                ikm = psk,
                salt = ByteArray(0),
                info = byteArrayOf(2, 0, 0, 0),
                length = 16
            )

            // Pre-derive the 64-byte EID key before connecting so BLE advertising can start immediately upon receiving the routing ID
            val eidKey = CryptoHelper.endif(
                ikm = psk,
                salt = ByteArray(0),
                info = byteArrayOf(1, 0, 0, 0),
                length = 64
            )

            lateinit var sessionWs: TunnelWebsocket
            sessionWs = TunnelWebsocket(
                domainId = domainId,
                ephemeralTunnelId = ephemeralTunnelId,
                onConnected = { routingId ->
                    if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket

                    // 1. Generate the single 16-byte advertPlaintext seed (containing nonce, routingId, domainId)
                    val advertPlaintext = CryptoHelper.generateSeed(routingId, domainId)

                    // 2. Encrypt the EXACT advertPlaintext seed to 20-byte BLE EID using pre-derived eidKey
                    val finalEid = CryptoHelper.generateEid(eidKey, advertPlaintext)

                    // 3. Start BLE advertising immediately before deriving Noise keys or generating P-256 keypairs, and abort the tunnel if the radio is unavailable
                    val bleDispatched = bleAdvertiser.startAdvertising(finalEid) { errorCode ->
                        // Handle asynchronous BLE start failures (e.g., ADVERTISE_FAILED_TOO_MANY_ADVERTISERS)
                        // delivered on the main looper so the tunnel does not hang until the 60s watchdog expires.
                        if (tunnelWebsocket === sessionWs) {
                            handshakeTimeoutJob?.cancel()
                            tunnelWebsocket = null
                            sessionWs.close()
                            onStatusUpdate?.invoke("Error: BLE advertising failed (code $errorCode).")
                            onSessionTerminated?.invoke()
                        }
                    }
                    if (!bleDispatched) {
                        onStatusUpdate?.invoke("Error: Failed to start BLE advertising.")
                        sessionWs.close()
                        tunnelWebsocket = null
                        onSessionTerminated?.invoke()
                        return@TunnelWebsocket
                    }
                    onStatusUpdate?.invoke("BLE Advertising Started with 20-byte EID...")

                    // 4. Derive 32-byte Noise PSK using the EXACT same advertPlaintext while BLE radio is already broadcasting
                    val noisePsk = CryptoHelper.endif(
                        ikm = psk,
                        salt = advertPlaintext,
                        info = byteArrayOf(3, 0, 0, 0),
                        length = 32
                    )

                    // 5. Initialize Noise KNpsk0 state machine with derived noisePsk
                    sessionNoise.initializeHandshake(noisePsk)

                    // Enforce a 60-second handshake deadline to reclaim the WebSocket and URI guard if a scanned QR code is stale
                    handshakeTimeoutJob?.cancel()
                    handshakeTimeoutJob = transportScope.launch {
                        delay(60_000)
                        if (tunnelWebsocket === sessionWs && !sessionNoise.isHandshakeComplete) {
                            Log.w("TransportManager", "Handshake timed out waiting for ClientHello; closing session.")
                            onStatusUpdate?.invoke("Handshake timed out. Please scan the QR code again.")
                            bleAdvertiser.stopAdvertising()
                            sessionWs.close()
                            tunnelWebsocket = null
                            onSessionTerminated?.invoke()
                        }
                    }
                },
                onMessageReceived = { encryptedFrame ->
                    if (tunnelWebsocket !== sessionWs) return@TunnelWebsocket
                    try {
                        if (!sessionNoise.isHandshakeComplete) {
                            Log.d("TransportManager", "Received ClientHello, processing Noise KNpsk0 handshake...")
                            // Cancel the handshake watchdog and stop BLE proximity advertising once the peer responds
                            handshakeTimeoutJob?.cancel()
                            bleAdvertiser.stopAdvertising()

                            val serverHello = sessionNoise.processClientHelloAndGenerateServerHello(encryptedFrame)
                            val encryptedPostHandshake = sessionNoise.encrypt(CACHED_POST_HANDSHAKE_MSG)

                            // Enqueue ServerHello and Post-Handshake frames back-to-back before UI dispatch to minimize round-trip latency
                            sessionWs.sendFrame(serverHello)
                            sessionWs.sendFrame(encryptedPostHandshake)

                            val msg = "Noise KNpsk0 Handshake Success!\nSent Post-Handshake Message."
                            Log.d("TransportManager", msg)
                            onStatusUpdate?.invoke(msg)
                        } else {
                            val decrypted = sessionNoise.decrypt(encryptedFrame)
                            // Treat empty post-handshake frames as a protocol error per CTAP 2.3 §11.5.1.2
                            require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                            val frameType = decrypted[0].toInt() and 0xFF
                            when (frameType) {
                                0x01 -> {
                                    val ctapReq = decrypted.copyOfRange(1, decrypted.size)
                                    // Avoid coercing empty CTAP payloads into a fake 0x00 command byte so logs reflect actual wire data
                                    val commandByte = ctapReq.firstOrNull()
                                    val cmdLabel = commandByte?.let { "0x%02X".format(it) } ?: "EMPTY"
                                    val logMsg = "Received CTAP Request ($cmdLabel)!"
                                    Log.d("TransportManager", logMsg)
                                    onStatusUpdate?.invoke(logMsg)

                                    // Dispatch CTAP request asynchronously so WebSocket reader thread remains responsive
                                    transportScope.launch {
                                        try {
                                            val response = onRequestReceived(ctapReq)
                                            // Ensure coroutine was not cancelled and session was not replaced while awaiting UI prompt
                                            ensureActive()
                                            if (tunnelWebsocket !== sessionWs) return@launch

                                            val framedResponse = byteArrayOf(0x01) + response
                                            sessionWs.sendFrame(sessionNoise.encrypt(framedResponse))

                                            // Close the tunnel cleanly after a successful MakeCredential (0x01) or GetAssertion (0x02)
                                            // ceremony. OkHttp's RealWebSocket flushes all prior sendFrame messages before transmitting
                                            // the 1000 Close frame, preventing trailing 0x00 client probes and background keep-alive leaks.
                                            if (commandByte == 0x01.toByte() || commandByte == 0x02.toByte()) {
                                                val statusByte = response[0]
                                                if (statusByte == CtapStatus.SUCCESS) {
                                                    onStatusUpdate?.invoke("CTAP Transaction Complete.")
                                                    tunnelWebsocket = null
                                                    sessionWs.close()
                                                    onSessionTerminated?.invoke()
                                                } else {
                                                    onStatusUpdate?.invoke("CTAP Rejected (Status: 0x${"%02X".format(statusByte)}).")
                                                }
                                            }
                                        } catch (e: CancellationException) {
                                            throw e
                                        } catch (e: Exception) {
                                            Log.e("TransportManager", "Error processing CTAP request", e)
                                            onStatusUpdate?.invoke("CTAP Error: ${e.message}")
                                            // Close the underlying WebSocket on fatal CTAP dispatch errors to prevent orphaned keep-alive pings
                                            sessionWs.close()
                                            if (tunnelWebsocket === sessionWs) {
                                                tunnelWebsocket = null
                                            }
                                            onSessionTerminated?.invoke()
                                        }
                                    }
                                }
                                0x00 -> {
                                    // Close session cleanly upon receiving client shutdown message (typeShutdown = 0) per CTAP 2.3 §11.5
                                    Log.d("TransportManager", "Received Shutdown message (0x00), closing tunnel.")
                                    onStatusUpdate?.invoke("Peer closed connection. Session complete.")
                                    bleAdvertiser.stopAdvertising()
                                    sessionWs.close()
                                    if (tunnelWebsocket === sessionWs) {
                                        tunnelWebsocket = null
                                    }
                                    onSessionTerminated?.invoke()
                                }
                                else -> Log.d("TransportManager", "Received Unknown Frame Type: 0x${frameType.toString(16)}")
                            }
                        }
                    } catch (e: Exception) {
                        val msg = "Frame Error: ${e.message}"
                        Log.e("TransportManager", msg, e)
                        handshakeTimeoutJob?.cancel()
                        bleAdvertiser.stopAdvertising()
                        // Close the WebSocket when handshake or frame decryption fails so the tunnel does not remain open indefinitely
                        sessionWs.close()
                        if (tunnelWebsocket === sessionWs) {
                            tunnelWebsocket = null
                        }
                        onStatusUpdate?.invoke(msg)
                        onSessionTerminated?.invoke()
                    }
                },
                onStatusUpdate = { status ->
                    if (tunnelWebsocket === sessionWs) {
                        onStatusUpdate?.invoke(status)
                    }
                },
                onDisconnected = {
                    // Stop BLE advertising and reset session guard via explicit disconnect callback instead of log string matching
                    if (tunnelWebsocket === sessionWs) {
                        handshakeTimeoutJob?.cancel()
                        bleAdvertiser.stopAdvertising()
                        tunnelWebsocket = null
                        onSessionTerminated?.invoke()
                    }
                }
            )
            // Guard WebSocket assignment and connection against concurrent stopSession() calls on the main thread
            // so a cancelled setup coroutine cannot escape teardown and leak a background socket.
            synchronized(this@TransportManager) {
                ensureActive()
                tunnelWebsocket = sessionWs
                sessionWs.connect()
            }
        }
    }

    @Synchronized
    fun stopSession() {
        handshakeTimeoutJob?.cancel()
        handshakeTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleAdvertiser.stopAdvertising()
        tunnelWebsocket?.close()
        tunnelWebsocket = null
    }
}