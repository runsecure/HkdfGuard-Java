package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.abstractions.IKeyWrapper;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.Arrays;
import java.util.function.BiFunction;

/**
 * An IDataProtectionKey whose own DEK is never read from a file on disk - keyWrapper generates
 * and immediately wraps a fresh one in the constructor (see IKeyWrapper.generateAndWrap); the
 * plaintext DEK itself never crosses that call's return value. sessionProviderFactory then binds
 * an ICryptoSessionProvider to that wrapped payload (this class can't construct one directly - a
 * concrete provider lives in whichever cipher module the caller chose, not here). Every
 * encrypt/decrypt delegates to an inner KeyWrappedDataEncryptionKey built from that provider, the
 * same as a durable, file-backed key would use.
 */
public final class EphemeralDataEncryptionKey implements IDataProtectionKey {

    // IKeyWrapper.generateAndWrap is implementation-agnostic about its own wrapped-payload
    // format/size (a native KMS library's is a small fixed size, at most a few hundred bytes) -
    // over-allocate generously and trim to what it actually wrote, the same as
    // KeyWrappedDataEncryptionKey's MAX_CIPHER_OVERHEAD does for cipher output.
    private static final int MAX_WRAPPED_LENGTH = 512;

    private final KeyWrappedDataEncryptionKey inner;

    /**
     * @param keyWrapper Generates and wraps this instance's own fresh DEK.
     * @param sessionProviderFactory Builds the ICryptoSessionProvider bound to keyWrapper and its
     *     freshly-generated wrapped payload - e.g.
     *     {@code (kw, wrapped) -> new AesGcmCryptoSessionProvider(kw, wrapped, 60)}.
     */
    public EphemeralDataEncryptionKey(IKeyWrapper keyWrapper,
                                       BiFunction<IKeyWrapper, byte[], ICryptoSessionProvider> sessionProviderFactory) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.EPHEMERAL_KEY_INITIALIZE).startSpan();
        try {
            byte[] buffer = new byte[MAX_WRAPPED_LENGTH];
            int written = keyWrapper.generateAndWrap(buffer);
            byte[] wrapped = Arrays.copyOf(buffer, written);

            ICryptoSessionProvider sessionProvider = sessionProviderFactory.apply(keyWrapper, wrapped);
            this.inner = new KeyWrappedDataEncryptionKey(sessionProvider);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
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
}
