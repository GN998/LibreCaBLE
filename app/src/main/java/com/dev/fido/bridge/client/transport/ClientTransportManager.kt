package com.dev.fido.bridge.client.transport

import android.util.Log
import com.dev.fido.bridge.client.ctap.ClientCtapCodec
import com.dev.fido.bridge.client.qr.ClientQrSessionData
import com.dev.fido.bridge.client.transport.ble.ClientL2capChannel
import com.dev.fido.bridge.client.transport.ble.HybridBleScanner
import com.dev.fido.bridge.client.transport.noise.ClientNoiseSession
import com.dev.fido.bridge.client.transport.websocket.ClientTunnelWebsocket
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.security.DomainDerivation
import com.dev.fido.bridge.core.transport.PxpDataChannel
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class ClientTransportManager(
    private val bleScanner: HybridBleScanner
) {
    private val transportScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    private var activeChannel: PxpDataChannel? = null

    @Volatile
    private var sessionTimeoutJob: Job? = null

    @Volatile
    var onStatusUpdate: ((String) -> Unit)? = null

    @Volatile
    var onPeerConnected: (() -> Unit)? = null

    private fun clearActiveSession(channel: PxpDataChannel?): Boolean = synchronized(this) {
        if (channel == null || activeChannel === channel) {
            sessionTimeoutJob?.cancel()
            sessionTimeoutJob = null
            activeChannel = null
            true
        } else {
            false
        }
    }

    /**
     * Start a QR-initiated client transaction: scan for the authenticator's BLE EID advertisement,
     * connect over BLE L2CAP CoC (or fallback to the authenticator-selected WebSocket tunnel domain),
     * complete the Noise KNpsk0 initiator handshake, negotiate UV capability from Post-Handshake GetInfo,
     * and exchange the CTAP2 command/response per PXP §6.1-6.2.
     */
    @Synchronized
    fun startClientSession(
        qrSession: ClientQrSessionData,
        ctapRequest: Ctap2Request,
        onSuccess: (Ctap2Response) -> Unit,
        onError: (String) -> Unit
    ) {
        stopSession()

        // Offload HKDF key derivation and BLE binder registration from the UI thread
        transportScope.launch {
            val eidKey = CryptoHelper.endif(
                ikm = qrSession.qrSecret,
                salt = ByteArray(0),
                info = byteArrayOf(1, 0, 0, 0),
                length = 64
            )
            val tunnelId = CryptoHelper.endif(
                ikm = qrSession.qrSecret,
                salt = ByteArray(0),
                info = byteArrayOf(2, 0, 0, 0),
                length = 16
            )

            ensureActive()

            val scanStarted = bleScanner.startScanning(
                eidKey = eidKey,
                onAdvertMatched = { advert ->
                    transportScope.launch {
                        connectTunnelAndExecuteCeremony(
                            qrSession = qrSession,
                            tunnelId = tunnelId,
                            advert = advert,
                            ctapRequest = ctapRequest,
                            onSuccess = onSuccess,
                            onError = onError
                        )
                    }
                },
                onFailure = { errorCode ->
                    stopSession()
                    onError("BLE scan failed (code $errorCode).")
                }
            )

            if (!scanStarted) {
                onError("Failed to start BLE scanner. Check Bluetooth state and permissions.")
                return@launch
            }

            onStatusUpdate?.invoke("Scan with other device")

            // Enforce a 90-second overall ceremony timeout while waiting for QR scan and user verification
            synchronized(this@ClientTransportManager) {
                sessionTimeoutJob?.cancel()
                sessionTimeoutJob = transportScope.launch {
                    delay(90_000)
                    stopSession()
                    onError("Transaction timed out.")
                }
            }
        }
    }

    private fun connectTunnelAndExecuteCeremony(
        qrSession: ClientQrSessionData,
        tunnelId: ByteArray,
        advert: com.dev.fido.bridge.core.transport.noise.DecryptedBleAdvert,
        ctapRequest: Ctap2Request,
        onSuccess: (Ctap2Response) -> Unit,
        onError: (String) -> Unit
    ) {
        onStatusUpdate?.invoke("Connecting...")

        // Derive 32-byte Noise PSK (purpose = 3) using the decrypted 16-byte BLE advert plaintext as salt
        val psk = CryptoHelper.endif(
            ikm = qrSession.qrSecret,
            salt = advert.plaintext,
            info = byteArrayOf(3, 0, 0, 0),
            length = 32
        )

        val noiseSession = ClientNoiseSession(
            identityPrivateKey = qrSession.identityPrivateKey,
            uncompressedIdentityPubKey = qrSession.uncompressedIdentityPublicKey
        )
        // Pre-compute the 81-byte ClientHello before the transport channel finishes setup
        val clientHello = noiseSession.startHandshakeAndBuildClientHello(psk)
        val awaitingPostHandshake = AtomicBoolean(true)
        val completed = AtomicBoolean(false)
        val commandByte: Byte = when (ctapRequest) {
            is Ctap2Request.MakeCredential -> 0x01
            is Ctap2Request.GetAssertion -> 0x02
            is Ctap2Request.GetInfo -> 0x04
            is Ctap2Request.Selection -> 0x0B
        }

        fun sendEncryptedFrame(targetChannel: PxpDataChannel, plaintext: ByteArray) {
            synchronized(noiseSession) {
                targetChannel.sendFrame(noiseSession.encrypt(plaintext))
            }
        }

        fun onChannelConnected(sourceChannel: PxpDataChannel) {
            if (activeChannel === sourceChannel) {
                // Initiator speaks first in KNpsk0 to prove possession of the decrypted BLE advert
                sourceChannel.sendFrame(clientHello)
            }
        }

        fun onChannelMessage(sourceChannel: PxpDataChannel, frame: ByteArray) {
            if (activeChannel !== sourceChannel) return
            try {
                if (!noiseSession.isHandshakeComplete) {
                    noiseSession.processServerHello(frame)
                    onPeerConnected?.invoke()
                    onStatusUpdate?.invoke("Connected")
                } else if (awaitingPostHandshake.compareAndSet(true, false)) {
                    val postHandshakeBytes = noiseSession.decrypt(frame)
                    val postMap = CtapCodec.SimpleCbor.read(postHandshakeBytes, strict = false) as? Map<*, *>
                        ?: throw IllegalArgumentException("Invalid post-handshake CBOR map")
                    val getInfoBytes = postMap[1L] as? ByteArray
                        ?: throw IllegalArgumentException("Post-handshake message missing getInfo (key 1)")

                    // Negotiate built-in UV per CTAP 2.3 §6.1.1 / §6.2.2 based on peer GetInfo capabilities
                    val supportsBuiltInUv = ClientCtapCodec.extractBuiltInUvSupport(getInfoBytes)
                    val encodedCtapPayload = ClientCtapCodec.encodeRequest(ctapRequest, supportsBuiltInUv)

                    // Send framed CTAP command (0x01 = typeCTAP || commandByte || CBOR) before dispatching UI status update
                    sendEncryptedFrame(sourceChannel, byteArrayOf(0x01) + encodedCtapPayload)
                    onStatusUpdate?.invoke("Verify on other device...")
                } else {
                    val decrypted = noiseSession.decrypt(frame)
                    require(decrypted.isNotEmpty()) { "Empty transport frame is a protocol error" }

                    when (val msgType = decrypted[0].toInt() and 0xFF) {
                        0x01 -> {
                            // typeCTAP response from authenticator
                            val rawCtapResp = decrypted.copyOfRange(1, decrypted.size)
                            val parsedResp = ClientCtapCodec.decodeResponse(commandByte, rawCtapResp)

                            // Send typeShutdown (0x00) to close the hybrid transaction cleanly per PXP §6.2
                            runCatching { sendEncryptedFrame(sourceChannel, byteArrayOf(0x00)) }

                            if (completed.compareAndSet(false, true) && clearActiveSession(sourceChannel)) {
                                sourceChannel.close()
                                onSuccess(parsedResp)
                            }
                        }
                        0x02 -> {
                            // typeUpdate (linking metadata from authenticator); ignore in stateless QR mode per PXP §6.2
                            Log.d("ClientTransport", "Ignored optional typeUpdate (0x02) frame")
                        }
                        else -> {
                            throw IllegalArgumentException("Unexpected hybrid frame type: 0x${"%02X".format(msgType)}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("ClientTransport", "Client transport error", e)
                if (completed.compareAndSet(false, true) && clearActiveSession(sourceChannel)) {
                    sourceChannel.cancel()
                    onError("Protocol error: ${e.message}")
                }
            }
        }

        fun onChannelDisconnected(sourceChannel: PxpDataChannel) {
            if (!completed.get() && clearActiveSession(sourceChannel)) {
                onError("Connection closed before authentication completed.")
            }
        }

        fun startWebsocketTransport(expectedPriorChannel: PxpDataChannel?) {
            val domain = DomainDerivation.resolveDomainOrNull(advert.encodedTunnelServerDomain)
            if (domain == null) {
                if (clearActiveSession(expectedPriorChannel)) {
                    onError("Authenticator requested unsupported tunnel domain ID: ${advert.encodedTunnelServerDomain}")
                }
                return
            }
            lateinit var ws: ClientTunnelWebsocket
            ws = ClientTunnelWebsocket(
                domain = domain,
                routingId = advert.routingId,
                tunnelId = tunnelId,
                onConnected = { onChannelConnected(ws) },
                onMessageReceived = { frame -> onChannelMessage(ws, frame) },
                onStatusUpdate = null,
                onDisconnected = { onChannelDisconnected(ws) }
            )
            // Bind the WebSocket channel only if the session was not cancelled while L2CAP was attempting to connect
            val shouldConnect = synchronized(this@ClientTransportManager) {
                if (expectedPriorChannel == null || activeChannel === expectedPriorChannel) {
                    activeChannel = ws
                    true
                } else {
                    false
                }
            }
            if (shouldConnect) {
                ws.connect()
            }
        }

        // Prefer direct BLE L2CAP CoC when the authenticator advertises a server PSM in the suffix per PXP §6.1.2,
        // falling back to WebSockets if the L2CAP socket fails to connect.
        val psm = advert.serverPsm
        val device = advert.bluetoothDevice
        if (psm != null && device != null) {
            Log.d("ClientTransport", "Authenticator advertised L2CAP PSM $psm; connecting over BLE CoC")
            lateinit var l2cap: ClientL2capChannel
            l2cap = ClientL2capChannel(
                device = device,
                psm = psm,
                onConnected = { onChannelConnected(l2cap) },
                onMessageReceived = { frame -> onChannelMessage(l2cap, frame) },
                onConnectFailed = {
                    Log.w("ClientTransport", "L2CAP connection failed; falling back to WebSocket tunnel")
                    startWebsocketTransport(expectedPriorChannel = l2cap)
                },
                onDisconnected = { onChannelDisconnected(l2cap) }
            )
            synchronized(this) {
                activeChannel = l2cap
            }
            l2cap.connect()
        } else {
            startWebsocketTransport(expectedPriorChannel = null)
        }
    }

    @Synchronized
    fun stopSession() {
        sessionTimeoutJob?.cancel()
        sessionTimeoutJob = null
        transportScope.coroutineContext.cancelChildren()
        bleScanner.stopScanning()
        activeChannel?.cancel()
        activeChannel = null
    }
}