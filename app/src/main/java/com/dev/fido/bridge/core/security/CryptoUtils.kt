package com.dev.fido.bridge.core.security

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.util.zip.Deflater
import java.util.zip.Inflater

object CryptoUtils {
    // Cap decompressed largeBlob size to 1 MiB per CTAP 2.3 §6.10.4 to prevent DEFLATE zip-bomb OOM
    private const val MAX_LARGE_BLOB_UNCOMPRESSED_BYTES = 1 shl 20

    fun encodeBase64UrlNoPadding(data: ByteArray): String {
        return Base64.encodeToString(data, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)
    }

    fun decodeBase64Url(base64Str: String): ByteArray {
        // Delegate URL-safe alphabet and missing padding handling directly to Android's native Base64 decoder
        return Base64.decode(base64Str.trim(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * Compress raw largeBlob bytes using RFC 1951 raw DEFLATE (nowrap = true) per CTAP 2.3 §12.4.
     */
    fun deflateRaw(uncompressed: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, /* nowrap = */ true)
        return try {
            deflater.setInput(uncompressed)
            deflater.finish()
            val out = ByteArrayOutputStream(uncompressed.size.coerceAtLeast(64))
            val buf = ByteArray(1024)
            while (!deflater.finished()) {
                val count = deflater.deflate(buf)
                if (count > 0) out.write(buf, 0, count)
            }
            out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    /**
     * Decompress RFC 1951 raw DEFLATE (nowrap = true) bytes and verify exact [expectedOriginalSize] per CTAP 2.3 §12.4.
     */
    fun inflateRaw(compressed: ByteArray, expectedOriginalSize: Long): ByteArray? {
        if (expectedOriginalSize < 0L || expectedOriginalSize > MAX_LARGE_BLOB_UNCOMPRESSED_BYTES) {
            return null
        }
        val expectedLen = expectedOriginalSize.toInt()
        val inflater = Inflater(/* nowrap = */ true)
        return try {
            inflater.setInput(compressed)
            val out = ByteArrayOutputStream(expectedLen.coerceAtLeast(32))
            val buf = ByteArray(1024)
            while (!inflater.finished()) {
                val count = inflater.inflate(buf)
                if (count > 0) {
                    if (out.size() + count > expectedLen) return null
                    out.write(buf, 0, count)
                } else if (inflater.needsInput() || inflater.needsDictionary()) {
                    break
                }
            }
            if (!inflater.finished() || out.size() != expectedLen) null else out.toByteArray()
        } catch (_: Exception) {
            null
        } finally {
            inflater.end()
        }
    }
}

/**
 * Format byte array into hexadecimal string for logging and tunnel URL construction.
 */
fun ByteArray.toHex(uppercase: Boolean = false): String {
    val format = if (uppercase) "%02X" else "%02x"
    return joinToString("") { format.format(it) }
}

/**
 * Decode hexadecimal string into raw bytes for routing ID and protocol parameter extraction.
 */
fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have an even length" }
    return ByteArray(length / 2) { i ->
        substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

/**
 * Convert BigInteger to fixed-width unsigned big-endian byte array.
 * Strip leading sign byte or pad with leading zeros to satisfy P-256 32-byte coordinate encoding.
 */
fun BigInteger.toFixedLengthBytes(length: Int = 32): ByteArray {
    val bytes = toByteArray()
    return when {
        bytes.size == length -> bytes
        bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
        else -> ByteArray(length).also {
            System.arraycopy(bytes, 0, it, length - bytes.size, bytes.size)
        }
    }
}