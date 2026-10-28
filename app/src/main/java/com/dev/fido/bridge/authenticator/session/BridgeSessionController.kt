package com.dev.fido.bridge.authenticator.session

import android.content.Context
import android.content.Intent
import android.util.Log
import com.dev.fido.bridge.authenticator.proxy.CredentialManagerProxy
import com.dev.fido.bridge.authenticator.transport.TransportManager
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import com.dev.fido.bridge.core.ctap.codec.CtapCodecException
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import com.dev.fido.bridge.core.session.BridgeForegroundService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class BridgeSessionController(
    private val context: Context,
    // Require non-null TransportManager to eliminate redundant safe-call operators
    private val transportManager: TransportManager
) {
    private val proxy = CredentialManagerProxy(context)
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val serviceIntent = Intent(context, BridgeForegroundService::class.java)

    var onStatusUpdate: ((String) -> Unit)? = null
    var onSessionTerminated: (() -> Unit)? = null

    fun onQrCodeScanned(
        peerPublicKey: ByteArray,
        psk: ByteArray,
        domainId: Int,
        supportedTransports: Set<Int> = setOf(0)
    ) {
        // Terminate any prior transport session first, then cancel pending Main-thread dispatches
        // so no background callback from a previous scan can enqueue after cancelChildren().
        stopSession()

        transportManager.onStatusUpdate = { status ->
            scope.launch { onStatusUpdate?.invoke(status) }
        }
        transportManager.onSessionTerminated = {
            context.stopService(serviceIntent)
            scope.launch { onSessionTerminated?.invoke() }
        }

        transportManager.startSession(peerPublicKey, psk, domainId, supportedTransports) { rawCtapRequest ->
            try {
                val parsedRequest = CtapCodec.decodeRequest(rawCtapRequest)

                // Switch to Main dispatcher non-blockingly for Android CredentialManager UI interaction
                val response = withContext(Dispatchers.Main) {
                    proxy.handleCtapRequest(parsedRequest)
                }

                CtapCodec.encodeResponse(response)
            } catch (e: CancellationException) {
                // Rethrow cancellation exceptions to respect structured concurrency lifecycles
                throw e
            } catch (e: CtapCodecException) {
                // Log protocol-level command or CBOR rejections as warnings without stack traces since client probes are expected
                Log.w("SessionController", "Rejected CTAP request with status 0x${"%02X".format(e.statusCode)}: ${e.message}")
                byteArrayOf(e.statusCode)
            } catch (e: Exception) {
                Log.e("SessionController", "Unhandled exception during CTAP processing", e)
                byteArrayOf(CtapStatus.ERR_OPERATION_DENIED)
            }
        }

        // Elevate process priority after dispatching I/O setup so opaque credential provider or lock pattern UIs do not freeze the WebSocket
        context.startForegroundService(serviceIntent)
    }

    // Detach transport callbacks before tearing down the session so closing sockets cannot enqueue stale termination events
    fun stopSession() {
        transportManager.onStatusUpdate = null
        transportManager.onSessionTerminated = null
        transportManager.stopSession()
        context.stopService(serviceIntent)
        scope.coroutineContext.cancelChildren()
    }
}