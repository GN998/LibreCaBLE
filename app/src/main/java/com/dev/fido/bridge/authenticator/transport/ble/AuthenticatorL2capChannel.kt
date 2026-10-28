package com.dev.fido.bridge.authenticator.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.util.Log
import com.dev.fido.bridge.core.transport.PxpDataChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/**
 * BLE L2CAP Connection-oriented Channel (CoC) server implementation per PXP §6.1.2 / CTAP 2.3 §11.5.1.1.2.
 * Listens on an auto-generated insecure L2CAP server PSM and frames messages with a 4-byte big-endian length prefix.
 */
class AuthenticatorL2capChannel(
    private val adapterProvider: () -> BluetoothAdapter?,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onDisconnected: () -> Unit
) : PxpDataChannel {

    companion object {
        // Cap inbound frame size to 1 MiB to match PXP §6.2 plaintext limits and prevent OOM on corrupted length headers
        private const val MAX_FRAME_BYTES = 1 shl 20
    }

    private val channelScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val outboundQueue = Channel<ByteArray>(Channel.UNLIMITED)

    @Volatile
    private var serverSocket: BluetoothServerSocket? = null

    @Volatile
    private var activeSocket: BluetoothSocket? = null

    @Volatile
    private var isClosed = false

    /**
     * Allocate an insecure L2CAP server socket and return its dynamic PSM immediately
     * so BLE extended advertising can start without waiting for network I/O.
     */
    @SuppressLint("MissingPermission")
    fun startServer(): Int? {
        val adapter = adapterProvider() ?: return null
        val server = try {
            adapter.listenUsingInsecureL2capChannel()
        } catch (t: Throwable) {
            Log.w("AuthL2capChannel", "Failed to allocate insecure L2CAP server socket", t)
            return null
        }

        serverSocket = server
        val assignedPsm = server.psm
        Log.d("AuthL2capChannel", "Allocated BLE L2CAP server PSM $assignedPsm")

        channelScope.launch {
            val clientSocket = try {
                server.accept().also { activeSocket = it }
            } catch (t: Throwable) {
                runCatching { server.close() }
                if (!isClosed) {
                    Log.w("AuthL2capChannel", "L2CAP accept failed on PSM $assignedPsm", t)
                    onDisconnected()
                }
                return@launch
            } finally {
                // Close listening server socket immediately after accepting the peer connection
                runCatching { server.close() }
            }

            val input = DataInputStream(clientSocket.inputStream)
            val output = DataOutputStream(clientSocket.outputStream)

            launch {
                try {
                    for (payload in outboundQueue) {
                        output.writeInt(payload.size)
                        output.write(payload)
                        output.flush()
                    }
                    // Allow the BLE controller to finish transmitting queued L2CAP CoC credits in the background
                    // after close() is called so closing the socket does not abort the final CTAP response frame.
                    if (isClosed) {
                        delay(500)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: IOException) {
                    if (!isClosed) {
                        Log.w("AuthL2capChannel", "L2CAP write stream closed", e)
                    }
                } finally {
                    if (isClosed) {
                        runCatching { clientSocket.close() }
                    }
                }
            }

            try {
                while (isActive && !isClosed) {
                    val length = input.readInt()
                    if (length <= 0 || length > MAX_FRAME_BYTES) {
                        throw IOException("Invalid L2CAP frame length: $length")
                    }
                    val buffer = ByteArray(length)
                    input.readFully(buffer)
                    onMessageReceived(buffer)
                }
            } catch (e: EOFException) {
                Log.d("AuthL2capChannel", "L2CAP peer closed stream cleanly (EOF)")
            } catch (e: IOException) {
                if (!isClosed) {
                    Log.w("AuthL2capChannel", "L2CAP read error", e)
                }
            } finally {
                runCatching { clientSocket.close() }
                onDisconnected()
            }
        }

        return assignedPsm
    }

    override fun sendFrame(data: ByteArray) {
        outboundQueue.trySend(data)
    }

    override fun close() {
        isClosed = true
        runCatching { serverSocket?.close() }
        outboundQueue.close()
    }

    override fun cancel() {
        isClosed = true
        outboundQueue.close()
        runCatching { serverSocket?.close() }
        runCatching { activeSocket?.close() }
        channelScope.cancel()
    }
}