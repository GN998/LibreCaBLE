package com.dev.fido.bridge.core.transport.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

// Resolve BluetoothLeAdvertiser dynamically per session so toggling system Bluetooth does not leave a stale or null instance
class HybridBleAdvertiser(private val advertiserProvider: () -> BluetoothLeAdvertiser?) {

    private val FIDO_SERVICE_UUID = UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb")
    private var activeCallback: AdvertiseCallback? = null

    /**
     * Start broadcasting the 20-byte caBLE EID over BLE and return whether the request was dispatched.
     * Synchronize access across OkHttp reader, coroutine timeout, and Android main threads to prevent leaked advertising state.
     */
    @Synchronized
    fun startAdvertising(eid: ByteArray, onFailure: ((Int) -> Unit)? = null): Boolean {
        // Stop any active advertising before starting a new session
        stopAdvertising()

        val advertiser = advertiserProvider()
        if (advertiser == null) {
            Log.e("HybridBleAdvertiser", "BLE Advertiser not available")
            return false
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
            .addServiceUuid(ParcelUuid(FIDO_SERVICE_UUID))
            .addServiceData(ParcelUuid(FIDO_SERVICE_UUID), eid)
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