package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.DataProtectionKey;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.security.SecureRandom;
import java.util.function.BiFunction;

/**
 * An DataProtectionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
 * unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
 * exists yet: construct one (generating a fresh random DEK, or supplying an existing one),
 * encrypt whatever needs protecting during the pipeline, then read the same plaintext DEK back
 * via asBytes at the end of the chain to hand off to the platform's native "initialize" CLI
 * utility, which independently wraps/registers it against a real KEK. close zeroes the DEK.
 */
public final class PipelineDataEncryptionKeyImpl implements DataProtectionKey, AutoCloseable {

    private static final int DEK_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] dek;
    private final CryptoProvider provider;
    private final KeyWrappedDataEncryptionKeyImpl inner;

    /**
     * Generates a fresh, cryptographically random 32-byte DEK.
     *
     * @param sessionProviderFactory See the other constructor overload.
     */
    public PipelineDataEncryptionKeyImpl(BiFunction<KeyWrapper, byte[], CryptoProvider> sessionProviderFactory) {
        this(randomDek(), sessionProviderFactory);
    }

    /**
     * @param dek The plain 32-byte DEK to use as-is - ownership transfers to this instance, which
     *     zeroes it on close.
     * @param sessionProviderFactory Builds the CryptoProvider this instance
     *     encrypts/decrypts through (this class can't construct one directly - a concrete
     *     provider lives in whichever cipher module the caller chose, not here) - e.g.
     *     {@code (kw, wrapped) -> new AesGcmCryptoProviderImpl(kw, wrapped, 60)}. Since dek
     *     needs no unwrapping, it's handed to that factory as both the key wrapper (an identity
     *     wrapper that reveals whatever "wrapped" bytes it's given, unchanged) and the wrapped
     *     payload itself.
     * @throws IllegalArgumentException dek is empty/all-zero, or not exactly 32 bytes
     */
    public PipelineDataEncryptionKeyImpl(byte[] dek, BiFunction<KeyWrapper, byte[], CryptoProvider> sessionProviderFactory) {
        if (ArrayUtility.isNullOrEmpty(dek)) {
            throw new IllegalArgumentException("DEK must not be empty or all zero.");
        }
        if (dek.length != DEK_LENGTH) {
            throw new IllegalArgumentException("DEK must be exactly " + DEK_LENGTH + " bytes.");
        }

        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.PIPELINE_KEY_INITIALIZE).startSpan();
        try {
            this.dek = dek;
            this.provider = sessionProviderFactory.apply(new IdentityKeyWrapperImpl(), dek);
            this.inner = new KeyWrappedDataEncryptionKeyImpl(provider);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    private static byte[] randomDek() {
        byte[] dek = new byte[DEK_LENGTH];
        RANDOM.nextBytes(dek);
        return dek;
    }

    /**
     * The plain, plaintext DEK this instance protects with - e.g. to hand off to the platform's
     * native "initialize" CLI utility once the pipeline finishes.
     */
    public byte[] asBytes() {
        return dek;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return inner.encrypt(plaintext);
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        return inner.encrypt(plaintext, aad);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] result) {
        return inner.decrypt(ciphertext, result);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        return inner.decrypt(ciphertext, aad, result);
    }

    /**
     * Closes the underlying session provider/session, and zeroes the plaintext DEK.
     */
    @Override
    public void close() {
        provider.close();
        ArrayUtility.zeroMemory(dek);
    }

    // Treats the "wrapped" payload it's handed as already being the plaintext key - there is
    // nothing to unwrap, since this whole class's point is using a plain key as-is.
    private static final class IdentityKeyWrapperImpl implements KeyWrapper {

        @Override
        public int encrypt(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException("IdentityKeyWrapperImpl only supports decrypt.");
        }

        @Override
        public int encrypt(byte[] plaintext, byte[] result, byte[] aad) {
            throw new UnsupportedOperationException("IdentityKeyWrapperImpl only supports decrypt.");
        }

        @Override
        public int decrypt(byte[] wrapped, byte[] result) {
            System.arraycopy(wrapped, 0, result, 0, wrapped.length);
            return wrapped.length;
        }

        @Override
        public int decrypt(byte[] wrapped, byte[] result, byte[] aad) {
            return decrypt(wrapped, result);
        }

        @Override
        public int generateAndWrap(byte[] result) {
            throw new UnsupportedOperationException("IdentityKeyWrapperImpl only supports decrypt.");
        }
    }
}
