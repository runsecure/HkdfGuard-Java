package com.runsecure.hkdfguard.dataencryptionkey.testhelpers;

import com.runsecure.hkdfguard.abstractions.KeyWrapper;

/**
 * An KeyWrapper that always reveals/generates the same fixed key, tracking how many times
 * decrypt/generateAndWrap were called - isolates
 * KeyWrappedDataEncryptionKeyImpl/EphemeralDataEncryptionKeyImpl/KeyRing tests from the real native KMS
 * machinery while still exercising real AES-GCM via a real CryptoProvider.
 */
public final class FakeKeyWrapper implements KeyWrapper {

    private final byte[] key;
    private int decryptCallCount;
    private int generateAndWrapCallCount;

    /**
     * When set, decrypt throws this instead of revealing the key - lets tests exercise a
     * KeyWrappedDataEncryptionKeyImpl encrypt/decrypt catch block without depending on the real
     * cipher failing.
     */
    private RuntimeException throwOnDecrypt;

    public FakeKeyWrapper(byte[] key) {
        this.key = key;
    }

    public int getDecryptCallCount() {
        return decryptCallCount;
    }

    public int getGenerateAndWrapCallCount() {
        return generateAndWrapCallCount;
    }

    public void setThrowOnDecrypt(RuntimeException exception) {
        this.throwOnDecrypt = exception;
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
        decryptCallCount++;
        if (throwOnDecrypt != null) {
            throw throwOnDecrypt;
        }

        System.arraycopy(key, 0, result, 0, key.length);
        return key.length;
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result, byte[] aad) {
        return decrypt(wrapped, result);
    }

    @Override
    public int generateAndWrap(byte[] result) {
        generateAndWrapCallCount++;
        System.arraycopy(key, 0, result, 0, key.length);
        return key.length;
    }
}
