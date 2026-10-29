package com.dev.fido.bridge.core.session

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder

/**
 * Maintain foreground process priority (oom_adj <= 200) during active caBLE sessions so full-screen
 * opaque credential provider or device lock pattern activities do not push the host process into
 * cached background state and trigger kernel TCP socket resets (ECONNABORTED).
 */
class BridgeForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "passkey_bridge_session"
        private const val NOTIFICATION_ID = 1001
    }

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Passkey Hybrid Session",
            NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("LibreCaBLE")
            .setContentText("Authenticating with nearby device...")
            .setSmallIcon(applicationInfo.icon)
            .setOngoing(true)
            .build()

        startForeground(
            NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
        )
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}