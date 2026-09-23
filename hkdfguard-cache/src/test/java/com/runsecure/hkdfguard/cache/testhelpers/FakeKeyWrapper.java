package com.runsecure.hkdfguard.cache.testhelpers;

import com.runsecure.hkdfguard.abstractions.KeyWrapper;

/**
 * An KeyWrapper that always reveals the same fixed key - isolates ProtectedCacheImpl tests from the
 * real blob/file/OS-storage machinery (already covered elsewhere) while still exercising real
 * AES-GCM via a real CryptoProvider.
 */
public final class FakeKeyWrapper implements KeyWrapper {

    private final byte[] key;

    public FakeKeyWrapper(byte[] key) {
        this.key = key;
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        throw new UnsupportedOperationException("FakeKeyWrapper only supports decrypt.");
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result, byte[] aad) {
        throw new UnsupportedOperationException("FakeKeyWrapper only supports decrypt.");
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result) {
        System.arraycopy(key, 0, result, 0, key.length);
        return key.length;
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result, byte[] aad) {
        return decrypt(wrapped, result);
    }

    @Override
    public int generateAndWrap(byte[] result) {
        throw new UnsupportedOperationException("FakeKeyWrapper only supports decrypt.");
    }
}
