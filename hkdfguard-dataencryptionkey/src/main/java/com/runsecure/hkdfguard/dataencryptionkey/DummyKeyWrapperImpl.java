package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.KeyWrapper;

/**
 * Stands in for the KeyWrapper the pipeline flow's CryptoProviderFactory.createForPipeline
 * requires but never actually calls (the DEK is used as-is, never wrapped) - every member is an
 * inert no-op.
 */
final class DummyKeyWrapperImpl implements KeyWrapper {

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        return 0;
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result) {
        return 0;
    }

    @Override
    public int generateAndWrap(byte[] result) {
        return 0;
    }
}
