package com.dev.fido.bridge.authenticator.transport.noise

import android.util.Log
import com.dev.fido.bridge.core.transport.noise.CryptoHelper
import com.dev.fido.bridge.core.transport.noise.NoiseCrypter
import com.dev.fido.bridge.core.transport.noise.NoiseHandshakeState
import java.security.interfaces.ECPrivateKey

/**
 * Noise KNpsk0 responder state machine for QR-initiated authenticator transactions per CTAP 2.3 §11.5.1.2 / PXP §6.2.
 * Pre-generates the local ephemeral P-256 keypair upon instantiation so transport callbacks remain free of key-generation latency.
 */
class NoiseSession(
    private val peerPublicKeyBytes: ByteArray
) {
    @Volatile
    var isHandshakeComplete = false
        private set

    private var noiseState: NoiseHandshakeState? = null
    private var crypter: NoiseCrypter? = null
    private val ephPriv: ECPrivateKey
    private val phoneEphemeralPubKey: ByteArray

    init {
        val (pub, priv) = CryptoHelper.generateEcKeyPair()
        ephPriv = priv
        phoneEphemeralPubKey = CryptoHelper.uncompressECKey(pub)
    }

    // Step 1: Initialize the noise state machine with derived PSK
    @Synchronized
    fun initializeHandshake(psk: ByteArray) {
        // Reset handshake flag and session crypter so fallback channels never reuse stale transport state
        isHandshakeComplete = false
        crypter = null

        val nh = NoiseHandshakeState()
        noiseState = nh

        nh.mixHash(byteArrayOf(1))
        nh.mixHash(peerPublicKeyBytes)
        nh.mixKeyAndHash(psk)

        Log.d("NoiseSession", "Noise KNpsk0 initialized with derived PSK, waiting for ClientHello")
    }

    // Step 2: Process the incoming ClientHello and generate ServerHello
    @Synchronized
    fun processClientHelloAndGenerateServerHello(clientHello: ByteArray): ByteArray {
        val nh = checkNotNull(noiseState) { "Handshake not initialized" }

        if (clientHello.size < 81) {
            throw IllegalArgumentException("ClientHello message too short: ${clientHello.size} bytes")
        }

        val pcEphemeralPubKey = clientHello.copyOfRange(0, 65)
        val clientHelloPayload = clientHello.copyOfRange(65, clientHello.size)

        nh.mixHash(pcEphemeralPubKey)
        nh.mixKey(pcEphemeralPubKey)
        val plaintext = nh.decryptAndHash(clientHelloPayload)
        // Reject non-empty ClientHello plaintext per CTAP 2.3 §11.5.1.2 handshake verification rules
        if (plaintext.isNotEmpty()) {
            throw IllegalArgumentException("ClientHello decrypted payload must be empty per CTAP 2.3 §11.5.1.2, got ${plaintext.size} bytes")
        }

        nh.mixHash(phoneEphemeralPubKey)
        nh.mixKey(phoneEphemeralPubKey)

        val peDh = CryptoHelper.ecdh(ephPriv, pcEphemeralPubKey)
        nh.mixKey(peDh)

        val psDh = CryptoHelper.ecdh(ephPriv, peerPublicKeyBytes)
        nh.mixKey(psDh)

        val serverHelloPayload = nh.encryptAndHash(ByteArray(0))
        val serverHello = phoneEphemeralPubKey + serverHelloPayload

        val (rx, tx) = nh.splitSessionKeys()
        crypter = NoiseCrypter(rx, tx)
        // Release ephemeral handshake state and intermediate chaining keys once transport keys are split
        noiseState = null
        isHandshakeComplete = true

        Log.d("NoiseSession", "Processed ClientHello, generated ServerHello. Handshake complete.")
        return serverHello
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        // Require initialized session crypter instead of falling back to unencrypted plaintext
        return checkNotNull(crypter) { "Handshake not complete" }.encrypt(plaintext)
    }

    @Synchronized
    fun decrypt(ciphertext: ByteArray): ByteArray {
        return checkNotNull(crypter) { "Handshake not complete" }.decrypt(ciphertext)
    }
}