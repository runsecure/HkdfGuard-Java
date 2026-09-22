package com.runsecure.hkdfguard.diagnostics;

/**
 * One ComponentTelemetry instance per component in the library - the single place every module's
 * Tracer/Meter/enableSensitiveLogging telemetry lives. Preserves the flag-sharing split from the
 * C# original: ROOT, CACHE, DATA_PROTECTION, and ENCRYPTED_CONFIGURATION all share one
 * enableSensitiveLogging flag (set any of them, all four read the new value);
 * CRYPTO_SESSION_AES_GCM256 and KEY_WRAPPING each keep their own, independent flag.
 */
public final class HkdfGuardTelemetry {

    private HkdfGuardTelemetry() {
    }

    public static final ComponentTelemetry ROOT = new ComponentTelemetry("HkdfGuard");

    public static final ComponentTelemetry CACHE = new ComponentTelemetry("HkdfGuard.Cache", ROOT);

    public static final ComponentTelemetry DATA_PROTECTION =
            new ComponentTelemetry("HkdfGuard.DataEncryptionKey", ROOT);

    public static final ComponentTelemetry ENCRYPTED_CONFIGURATION =
            new ComponentTelemetry("HkdfGuard.EncryptedConfiguration", ROOT);

    public static final ComponentTelemetry CRYPTO_SESSION_AES_GCM256 =
            new ComponentTelemetry("HkdfGuard.CryptoSession.AesGcm256");

    public static final ComponentTelemetry KEY_WRAPPING = new ComponentTelemetry("HkdfGuard.KeyWrapping.V1");
}
