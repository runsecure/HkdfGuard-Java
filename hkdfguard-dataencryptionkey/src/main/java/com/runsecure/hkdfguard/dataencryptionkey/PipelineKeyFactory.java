package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.CryptoProviderFactory;

import java.security.SecureRandom;

/**
 * Builds fresh PipelineDataEncryptionKeyImpl instances, each around a newly generated random
 * 32-byte DEK.
 *
 * <p>The C# original's create also accepts a format-provider argument and an optional key
 * version, neither of which its own implementation ever reads (a pipeline key isn't registered
 * in a KeyRing, so it has no format or version to speak of) - this port drops both rather than
 * carrying two parameters that do nothing.
 */
public final class PipelineKeyFactory {

    private static final int DEK_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Generates a fresh, cryptographically random 32-byte DEK and builds a
     * PipelineDataEncryptionKeyImpl around it via factory.createForPipeline.
     */
    public PipelineDataEncryptionKeyImpl create(CryptoProviderFactory factory) {
        byte[] dek = new byte[DEK_LENGTH];
        RANDOM.nextBytes(dek);

        CryptoProvider provider = factory.createForPipeline(new DummyKeyWrapperImpl(), dek);
        return new PipelineDataEncryptionKeyImpl(provider, dek);
    }
}
