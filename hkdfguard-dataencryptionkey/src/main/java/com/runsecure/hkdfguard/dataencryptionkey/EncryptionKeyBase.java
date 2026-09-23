package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.Arrays;

/**
 * A DataEncryptionKey backed by one CryptoProvider. Every operation calls straight through to
 * provider, which owns revealing/refreshing its own key material - EncryptionKeyBase adds only
 * the allocation sizing (via provider.getEncryptedAllocationLength) and telemetry every concrete
 * key in this package needs.
 */
public abstract class EncryptionKeyBase implements DataEncryptionKey {

    private static final byte[] EMPTY_AAD = new byte[0];

    private final CryptoProvider provider;

    protected EncryptionKeyBase(CryptoProvider provider) {
        this.provider = provider;
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

            byte[] buffer = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int written = provider.encrypt(plaintext, aad, buffer);
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

            return provider.decrypt(ciphertext, aad, result);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }
}
