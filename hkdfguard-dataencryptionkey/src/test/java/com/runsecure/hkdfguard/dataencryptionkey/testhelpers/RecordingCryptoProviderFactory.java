package com.runsecure.hkdfguard.dataencryptionkey.testhelpers;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderFactoryImpl;

import java.util.ArrayList;
import java.util.List;

/**
 * A CryptoProviderFactory that delegates to a real AesGcmCryptoProviderFactoryImpl (so callers
 * get a genuinely working CryptoProvider back) while recording the arguments each method was
 * called with - lets KeyRingBuilder tests assert exactly what it passes through without
 * depending on AesGcmCryptoProviderImpl exposing its own configuration for inspection.
 */
public final class RecordingCryptoProviderFactory implements CryptoProviderFactory {

    private final AesGcmCryptoProviderFactoryImpl inner = new AesGcmCryptoProviderFactoryImpl();

    private final List<Integer> createExpirySecondsCalls = new ArrayList<>();
    private final List<Integer> createEphemeralExpirySecondsCalls = new ArrayList<>();

    public List<Integer> getCreateExpirySecondsCalls() {
        return createExpirySecondsCalls;
    }

    public List<Integer> getCreateEphemeralExpirySecondsCalls() {
        return createEphemeralExpirySecondsCalls;
    }

    @Override
    public CryptoProvider create(KeyWrapper wrapper, byte[] wrapped, int expirySeconds) {
        createExpirySecondsCalls.add(expirySeconds);
        return inner.create(wrapper, wrapped, expirySeconds);
    }

    @Override
    public CryptoProvider createEphemeral(KeyWrapper wrapper, int expirySeconds) {
        createEphemeralExpirySecondsCalls.add(expirySeconds);
        return inner.createEphemeral(wrapper, expirySeconds);
    }

    @Override
    public CryptoProvider createForPipeline(KeyWrapper wrapper, byte[] notWrapped) {
        return inner.createForPipeline(wrapper, notWrapped);
    }
}
