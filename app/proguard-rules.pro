# Strip verbose and debug log calls in release builds to prevent leaking WebAuthn PII
# (rpId, credentialId, userHandle, and raw JSON payloads) to system logcat per WebAuthn §14.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}