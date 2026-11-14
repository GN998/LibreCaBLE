// File: app/src/main/java/com/dev/fido/bridge/core/ui/BridgeUiTheme.kt
package com.dev.fido.bridge.core.ui

import android.content.Context
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.widget.TextView

/**
 * Shared programmatic UI styling constants and view factories for authenticator and client bottom sheets.
 */
object BridgeUiTheme {
    // Use compile-time ARGB integer constants to avoid runtime Color.parseColor string parsing overhead
    const val COLOR_TERMINAL_BG = 0xFF020617.toInt()
    const val COLOR_CARD_BG = 0xFF0F172A.toInt()
    const val COLOR_SCRIM = 0x88000000.toInt()
    const val COLOR_TEXT_TITLE = 0xFFF8FAFC.toInt()
    const val COLOR_TEXT_TERMINAL = 0xFFE2E8F0.toInt()
    const val COLOR_TEXT_STATUS = 0xFF94A3B8.toInt()
    const val COLOR_BADGE_SUCCESS = 0xFF10B981.toInt()

    // Round to nearest pixel to match Android TypedValue.complexToDimensionPixelSize on fractional DPIs
    fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density + 0.5f).toInt()

    /**
     * Create a dark slate card background with a translucent Material You system accent border.
     */
    fun Context.createCardBackground(radii: FloatArray): GradientDrawable = GradientDrawable().apply {
        setColor(COLOR_CARD_BG)
        cornerRadii = radii
        setStroke(dp(1).coerceAtLeast(1), getColor(android.R.color.system_accent1_400) and 0x55FFFFFF)
    }

    /**
     * Create a 24dp rounded top-corners background for modal bottom sheet cards.
     */
    fun Context.createBottomSheetBackground(): GradientDrawable {
        val r = dp(24).toFloat()
        return createCardBackground(floatArrayOf(r, r, r, r, 0f, 0f, 0f, 0f))
    }

    fun Context.createSheetTitleTextView(): TextView = TextView(this).apply {
        text = "Passkey"
        textSize = 16f
        typeface = Typeface.DEFAULT_BOLD
        setTextColor(COLOR_TEXT_TITLE)
        gravity = Gravity.CENTER
    }

    fun Context.createSheetStatusTextView(initialText: String): TextView = TextView(this).apply {
        text = initialText
        textSize = 13f
        typeface = Typeface.MONOSPACE
        setTextColor(COLOR_TEXT_STATUS)
        gravity = Gravity.CENTER
    }
}