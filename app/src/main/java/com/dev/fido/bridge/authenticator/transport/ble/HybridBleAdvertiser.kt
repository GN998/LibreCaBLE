package com.dev.fido.bridge.authenticator.transport.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import com.dev.fido.bridge.core.ctap.codec.CtapCodec
import java.util.UUID

// Resolve BluetoothLeAdvertiser and BluetoothAdapter dynamically per session so toggling system Bluetooth does not leave stale references
class HybridBleAdvertiser(
    private val advertiserProvider: () -> BluetoothLeAdvertiser?,
    private val adapterProvider: () -> BluetoothAdapter? = { null }
) {

    private val FIDO_SERVICE_UUID = UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb")
    private var activeCallback: AdvertiseCallback? = null
    private var activeSetCallback: AdvertisingSetCallback? = null

    /**
     * Check whether the local controller supports BLE Extended Advertising required
     * to broadcast the advertisement suffix per PXP §5.4.1.
     */
    fun isExtendedAdvertisingSupported(): Boolean =
        adapterProvider()?.isLeExtendedAdvertisingSupported == true

    /**
     * Start broadcasting the 20-byte caBLE EID (plus optional CBOR advertisement suffix {1: serverPsm})
     * over BLE and return whether the request was dispatched.
     * Synchronize access across OkHttp reader, coroutine timeout, and Android main threads to prevent leaked advertising state.
     */
    @Synchronized
    fun startAdvertising(
        eid: ByteArray,
        serverPsm: Int? = null,
        onFailure: ((Int) -> Unit)? = null
    ): Boolean {
        // Stop any active advertising before starting a new session
        stopAdvertising()

        val advertiser = advertiserProvider()
        if (advertiser == null) {
            Log.e("HybridBleAdvertiser", "BLE Advertiser not available")
            return false
        }

        val serviceUuid = ParcelUuid(FIDO_SERVICE_UUID)

        // Append canonical CBOR advertisement suffix {1: server_psm} and broadcast via connectable
        // BLE Extended Advertising when an L2CAP channel is offered per PXP §5.4.1 & §6.1.2.
        if (serverPsm != null && isExtendedAdvertisingSupported()) {
            val suffixBytes = CtapCodec.SimpleCbor.write(mapOf(1L to serverPsm.toLong()))
            val extendedServiceData = eid + suffixBytes

            val parameters = AdvertisingSetParameters.Builder()
                .setLegacyMode(false)
                .setConnectable(true)
                .setScannable(false)
                .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
                .build()

            val data = AdvertiseData.Builder()
                .addServiceUuid(serviceUuid)
                .addServiceData(serviceUuid, extendedServiceData)
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .build()

            val setCallback = object : AdvertisingSetCallback() {
                override fun onAdvertisingSetStarted(
                    advertisingSet: AdvertisingSet?,
                    txPower: Int,
                    status: Int
                ) {
                    if (status == ADVERTISE_SUCCESS) {
                        Log.d("HybridBleAdvertiser", "Extended EID+L2CAP BLE Advertising started (PSM=$serverPsm)")
                    } else {
                        Log.e("HybridBleAdvertiser", "Extended BLE Advertising failed with status: $status")
                        val shouldNotify = synchronized(this@HybridBleAdvertiser) {
                            if (activeSetCallback === this) {
                                activeSetCallback = null
                                true
                            } else {
                                false
                            }
                        }
                        if (shouldNotify) {
                            onFailure?.invoke(status)
                        }
                    }
                }
            }

            return try {
                // Limit extended advertising duration to 6000 * 10ms = 60s to match the handshake watchdog
                advertiser.startAdvertisingSet(parameters, data, null, null, null, 6000, 0, setCallback)
                activeSetCallback = setCallback
                true
            } catch (e: SecurityException) {
                Log.e("HybridBleAdvertiser", "SecurityException starting extended BLE advertising", e)
                false
            } catch (e: Exception) {
                Log.e("HybridBleAdvertiser", "Unexpected error starting extended BLE advertising", e)
                false
            }
        }

        // Use AdvertiseSettings with ADVERTISE_MODE_LOW_LATENCY instead of AdvertisingSetParameters.INTERVAL_MIN (100ms)
        // so the Android BLE stack schedules high-frequency proximity bursts without OEM coexistence throttling.
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(false)
            .setTimeout(60_000)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(serviceUuid)
            .addServiceData(serviceUuid, eid)
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.d("HybridBleAdvertiser", "EID BLE Advertising started successfully: $settingsInEffect")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e("HybridBleAdvertiser", "EID BLE Advertising failed with errorCode: $errorCode")
                // Clear activeCallback under monitor lock only if this callback is still current,
                // then notify caller outside the lock to abort the awaiting tunnel session.
                val shouldNotify = synchronized(this@HybridBleAdvertiser) {
                    if (activeCallback === this) {
                        activeCallback = null
                        true
                    } else {
                        false
                    }
                }
                if (shouldNotify) {
                    onFailure?.invoke(errorCode)
                }
            }
        }

        return try {
            advertiser.startAdvertising(settings, data, callback)
            activeCallback = callback
            true
        } catch (e: SecurityException) {
            Log.e("HybridBleAdvertiser", "SecurityException: Missing required BLE/Location permissions", e)
            false
        } catch (e: Exception) {
            Log.e("HybridBleAdvertiser", "Unexpected error starting BLE advertising", e)
            false
        }
    }

    @Synchronized
    fun stopAdvertising() {
        activeSetCallback?.let { cb ->
            try {
                advertiserProvider()?.stopAdvertisingSet(cb)
                Log.d("HybridBleAdvertiser", "Extended BLE Advertising stopped")
            } catch (e: Exception) {
                Log.w("HybridBleAdvertiser", "Failed to stop extended BLE advertising", e)
            } finally {
                activeSetCallback = null
            }
        }

        val callback = activeCallback ?: return
        try {
            advertiserProvider()?.stopAdvertising(callback)
            Log.d("HybridBleAdvertiser", "BLE Advertising stopped")
        } catch (e: Exception) {
            Log.w("HybridBleAdvertiser", "Failed to stop BLE advertising", e)
        } finally {
            activeCallback = null
        }
    }
}