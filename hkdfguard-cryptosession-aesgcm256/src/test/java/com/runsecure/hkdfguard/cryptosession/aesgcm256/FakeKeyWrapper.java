package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.KeyWrapper;

import java.security.SecureRandom;

/**
 * A KeyWrapper that always reveals a fresh random key, tracking how many times decrypt was
 * called - isolates AesGcmCryptoProviderImpl tests from any real native KMS machinery.
 */
final class FakeKeyWrapper implements KeyWrapper {

    private static final SecureRandom RANDOM = new SecureRandom();

    private int decryptCallCount;
    private int generateAndWrapCallCount;

    /** When set, decrypt throws this instead of revealing a key. */
    private RuntimeException throwOnDecrypt;

    int getDecryptCallCount() {
        return decryptCallCount;
    }

    int getGenerateAndWrapCallCount() {
        return generateAndWrapCallCount;
    }

    void setThrowOnDecrypt(RuntimeException exception) {
        this.throwOnDecrypt = exception;
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result) {
        decryptCallCount++;
        if (throwOnDecrypt != null) {
            throw throwOnDecrypt;
        }

        RANDOM.nextBytes(result);
        return result.length;
    }

    @Override
    public int generateAndWrap(byte[] result) {
        generateAndWrapCallCount++;
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        System.arraycopy(key, 0, result, 0, key.length);
        return key.length;
    }
}
