package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.abstractions.CryptoProvider;

/**
 * A DataEncryptionKey backed by a plain 32-byte DEK, used directly - never wrapped, never
 * unwrapped. Meant for a pipeline that needs to encrypt secrets in-flight before a durable KEK
 * exists yet: build one via PipelineKeyFactory, encrypt whatever needs protecting during the
 * pipeline, then read the same plaintext DEK back via asBytes at the end of the chain to hand
 * off to the platform's native "initialize" CLI utility, which independently wraps/registers it
 * against a real KEK. close zeroes the DEK.
 */
public final class PipelineDataEncryptionKeyImpl extends EncryptionKeyBase implements AutoCloseable {

    private final CryptoProvider provider;
    private final byte[] dek;

    public PipelineDataEncryptionKeyImpl(CryptoProvider provider, byte[] dek) {
        super(provider);
        this.provider = provider;
        this.dek = dek;
    }

    /**
     * The plain, plaintext DEK this instance protects with - e.g. to hand off to the platform's
     * native "initialize" CLI utility once the pipeline finishes.
     */
    public byte[] asBytes() {
        return dek;
    }

    /**
     * Closes the underlying provider, and zeroes the plaintext DEK.
     */
    @Override
    public void close() {
        provider.close();
        ArrayUtility.zeroMemory(dek);
    }
}
