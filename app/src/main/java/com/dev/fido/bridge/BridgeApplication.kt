package com.dev.fido.bridge

import android.app.Application
import android.util.Log
import com.dev.fido.bridge.core.security.TunnelConfigManager
import com.dev.fido.bridge.core.transport.SharedHttpClient

class BridgeApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize persistent tunnel configuration store before any FIDO intent is processed
        TunnelConfigManager.init(this)
        // Pre-warm OkHttp TLS provider and P-256 curve parameters in the background without emitting network traffic
        SharedHttpClient.warmupLocalCryptoAndTls()
        Log.d("BridgeApplication", "LibreCaBLE Application initialized.")
    }
}