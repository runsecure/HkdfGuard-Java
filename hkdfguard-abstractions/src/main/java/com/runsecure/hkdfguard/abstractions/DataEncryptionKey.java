package com.runsecure.hkdfguard.abstractions;

public interface DataEncryptionKey {

    /**
     * Key Wrapper for protecting an encryption key
     *
     * @param plaintext The plain bytes to encrypt
     * @return The encrypted key, ready to be stored
     */
    byte[] encrypt(byte[] plaintext);

    /**
     * Key Wrapper for protecting an encryption key
     *
     * @param plaintext The plain bytes to encrypt
     * @param aad Additional Auth Data for the encrypt operation
     * @return The encrypted key, ready to be stored
     */
    byte[] encrypt(byte[] plaintext, byte[] aad);

    /**
     * Key Wrapper for revealing an encryption key
     *
     * @param ciphertext The encrypted key
     * @param result The decrypted key array
     * @return Number of bytes written to the result
     */
    int decrypt(byte[] ciphertext, byte[] result);

    /**
     * Key Wrapper for revealing an encryption key
     *
     * @param ciphertext The encrypted key
     * @param aad Additional Auth Data for decrypting the key
     * @param result The decrypted key array
     * @return Number of bytes written to the result
     */
    int decrypt(byte[] ciphertext, byte[] aad, byte[] result);
}
