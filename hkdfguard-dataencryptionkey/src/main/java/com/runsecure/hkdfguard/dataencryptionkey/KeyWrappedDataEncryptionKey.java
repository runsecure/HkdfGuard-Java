package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ICryptoSession;
import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.Arrays;

/**
 * An IDataProtectionKey backed by one wrapped DEK payload. sessionProvider owns revealing that
 * payload's key (from a fresh unwrap, once its cached ICryptoSession expires) and performing the
 * actual data encrypt/decrypt with it - see ICryptoSessionProvider. Every operation resolves
 * getSession fresh rather than caching the session itself, so it always uses a non-expired one.
 */
public class KeyWrappedDataEncryptionKey implements IDataProtectionKey {

    // ICryptoSession is cipher-agnostic, so its exact ciphertext overhead (nonce/tag for
    // AES-GCM, potentially something else for a swapped-in cipher) isn't known here - over-
    // allocate generously and trim to what it actually wrote.
    private static final int MAX_CIPHER_OVERHEAD = 64;
    private static final byte[] EMPTY_AAD = new byte[0];

    private final ICryptoSessionProvider sessionProvider;

    public KeyWrappedDataEncryptionKey(ICryptoSessionProvider sessionProvider) {
        this.sessionProvider = sessionProvider;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, EMPTY_AAD);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.KEY_WRAPPED_KEY_ENCRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length),
                        ComponentTelemetry.Detail.of(AttributeNames.AAD_LENGTH, aad.length));
            }

            ICryptoSession session = sessionProvider.getSession();
            byte[] buffer = new byte[plaintext.length + MAX_CIPHER_OVERHEAD];
            int written = session.encrypt(plaintext, aad, buffer);
            return Arrays.copyOf(buffer, written);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] result) {
        return decrypt(ciphertext, EMPTY_AAD, result);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.KEY_WRAPPED_KEY_DECRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.CIPHERTEXT_LENGTH, ciphertext.length),
                        ComponentTelemetry.Detail.of(AttributeNames.AAD_LENGTH, aad.length));
            }

            ICryptoSession session = sessionProvider.getSession();
            return session.decrypt(ciphertext, aad, result);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }
}
