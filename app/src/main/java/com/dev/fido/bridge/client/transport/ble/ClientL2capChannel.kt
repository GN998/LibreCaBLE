package com.dev.fido.bridge.client.transport.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.util.Log
import com.dev.fido.bridge.core.transport.PxpDataChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

/**
 * BLE L2CAP Connection-oriented Channel (CoC) client implementation per PXP §6.1.2 / CTAP 2.3 §11.5.1.1.2.
 * Frames every message with a 4-byte big-endian unsigned length prefix over an insecure L2CAP socket.
 */
class ClientL2capChannel(
    private val device: BluetoothDevice,
    private val psm: Int,
    private val onConnected: () -> Unit,
    private val onMessageReceived: (ByteArray) -> Unit,
    private val onConnectFailed: (Throwable) -> Unit,
    private val onDisconnected: () -> Unit
) : PxpDataChannel {

    companion object {
        // Cap inbound frame size to 1 MiB to match PXP §6.2 plaintext limits and prevent OOM on corrupted length headers
        private const val MAX_FRAME_BYTES = 1 shl 20
    }

    private val channelScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val outboundQueue = Channel<ByteArray>(Channel.UNLIMITED)

    @Volatile
    private var socket: BluetoothSocket? = null

    @Volatile
    private var isClientClosed = false

    @SuppressLint("MissingPermission")
    fun connect() {
        channelScope.launch {
            val l2capSocket = try {
                device.createInsecureL2capChannel(psm).also { socket = it }
            } catch (t: Throwable) {
                if (!isClientClosed) {
                    Log.e("ClientL2capChannel", "Failed to create L2CAP socket on PSM $psm", t)
                    onConnectFailed(t)
                }
                return@launch
            }

            try {
                l2capSocket.connect()
                Log.d("ClientL2capChannel", "L2CAP CoC connected on PSM $psm")
            } catch (t: Throwable) {
                runCatching { l2capSocket.close() }
                if (!isClientClosed) {
                    Log.w("ClientL2capChannel", "L2CAP connect failed on PSM $psm", t)
                    onConnectFailed(t)
                }
                return@launch
            }

            val input = DataInputStream(l2capSocket.inputStream)
            val output = DataOutputStream(l2capSocket.outputStream)

            // Serialize 4-byte big-endian length-prefixed frames sequentially; closing outboundQueue
            // flushes any remaining frames (e.g., 0x00 typeShutdown) before closing the socket in finally.
            launch {
                try {
                    for (payload in outboundQueue) {
                        output.writeInt(payload.size)
                        output.write(payload)
                        output.flush()
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: IOException) {
                    if (!isClientClosed) {
                        Log.w("ClientL2capChannel", "L2CAP write stream closed", e)
                    }
                } finally {
                    if (isClientClosed) {
                        runCatching { l2capSocket.close() }
                    }
                }
            }

            // Trigger ClientHello transmission immediately after writer loop is active
            onConnected()

            // Read 4-byte big-endian length prefix followed by exact payload bytes per PXP §6.1.2
            try {
                while (isActive && !isClientClosed) {
                    val length = input.readInt()
                    if (length <= 0 || length > MAX_FRAME_BYTES) {
                        throw IOException("Invalid L2CAP frame length: $length")
                    }
                    val buffer = ByteArray(length)
                    input.readFully(buffer)
                    onMessageReceived(buffer)
                }
            } catch (e: EOFException) {
                Log.d("ClientL2capChannel", "L2CAP peer closed stream cleanly (EOF)")
            } catch (e: IOException) {
                if (!isClientClosed) {
                    Log.w("ClientL2capChannel", "L2CAP read error", e)
                }
            } finally {
                runCatching { l2capSocket.close() }
                onDisconnected()
            }
        }
    }

    override fun sendFrame(data: ByteArray) {
        outboundQueue.trySend(data)
    }

    override fun close() {
        isClientClosed = true
        // Closing the channel signals the writer loop to flush pending frames and close the socket
        outboundQueue.close()
    }

    override fun cancel() {
        isClientClosed = true
        outboundQueue.close()
        runCatching { socket?.close() }
        channelScope.cancel()
    }
}