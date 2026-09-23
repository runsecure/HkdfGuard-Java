package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;

import java.util.Arrays;

/**
 * Builds AesGcmCryptoProviderImpl instances, implementing CryptoProviderFactory.
 */
public final class AesGcmCryptoProviderFactoryImpl implements CryptoProviderFactory {

    private static final int GENERATE_AND_WRAP_BUFFER_LENGTH = 512;

    @Override
    public CryptoProvider create(KeyWrapper wrapper, byte[] wrapped, int expirySeconds) {
        return new AesGcmCryptoProviderImpl(wrapper, wrapped, expirySeconds);
    }

    @Override
    public CryptoProvider createEphemeral(KeyWrapper wrapper, int expirySeconds) {
        byte[] wrapped = new byte[GENERATE_AND_WRAP_BUFFER_LENGTH];
        int written = wrapper.generateAndWrap(wrapped);
        byte[] wrappedBytes = Arrays.copyOf(wrapped, written);
        return new AesGcmCryptoProviderImpl(wrapper, wrappedBytes, expirySeconds);
    }

    @Override
    public CryptoProvider createForPipeline(KeyWrapper wrapper, byte[] notWrapped) {
        return new AesGcmCryptoProviderImpl(wrapper, notWrapped);
    }
}
