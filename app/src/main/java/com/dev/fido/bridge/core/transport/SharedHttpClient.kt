package com.dev.fido.bridge.core.transport

import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/**
 * Shared OkHttpClient singleton and cold-start crypto/TLS warmer used by both authenticator and client WebSocket tunnels.
 */
object SharedHttpClient {
    // Initialize OkHttpClient lazily so referencing this object in Application.onCreate()
    // does not synchronously load the system X509TrustManager and SSLContext on the main thread.
    // OkHttp 5.x enables RFC 8305 Happy Eyeballs (fastFallback) by default so unreachable IPv6
    // routes fall back to IPv4 within 250ms instead of blocking for the full 10s connectTimeout.
    val sharedClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .pingInterval(5, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Pre-initialize the OkHttp TLS engine and JCA P-256 curve parameters on a background IO thread
     * during cold start to eliminate classloading and trust-store overhead without blocking the main thread.
     */
    fun warmupLocalCryptoAndTls() {
        CoroutineScope(Dispatchers.IO).launch {
            sharedClient
            CryptoHelper.warmup()
        }
    }
}