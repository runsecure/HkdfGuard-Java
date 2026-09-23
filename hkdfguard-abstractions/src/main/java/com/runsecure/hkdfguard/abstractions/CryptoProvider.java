package com.runsecure.hkdfguard.abstractions;

/**
 * A cached, key-bound AEAD encrypt/decrypt surface. Implementations own revealing and refreshing
 * their own underlying key material internally - callers just call encrypt/decrypt on every
 * operation and always get a currently-valid key, without ever seeing (or needing to manage) the
 * session/expiry machinery behind it.
 */
public interface CryptoProvider extends AutoCloseable {

    /**
     * Encrypt the data
     *
     * @param plaintext Plain data to encrypt
     * @param result The array to hold the encrypted data
     * @return Number of bytes written to the encrypted array
     */
    int encrypt(byte[] plaintext, byte[] result);

    /**
     * Encrypt the data
     *
     * @param plaintext Plain data to encrypt
     * @param aad The Additional Auth Data for the encrypt operation
     * @param result The array to hold the encrypted data
     * @return Number of bytes written to the encrypted array
     */
    int encrypt(byte[] plaintext, byte[] aad, byte[] result);

    /**
     * Decrypt the data
     *
     * @param ciphertext The encrypted data to decrypt
     * @param result The array to receive the decrypted data
     * @return The number of bytes written to the decrypted array
     */
    int decrypt(byte[] ciphertext, byte[] result);

    /**
     * Decrypt the data
     *
     * @param ciphertext The encrypted data to decrypt
     * @param aad Additional Auth Data for the decrypt operation
     * @param result The array to receive the decrypted data
     * @return The number of bytes written to the decrypted array
     */
    int decrypt(byte[] ciphertext, byte[] aad, byte[] result);

    @Override
    void close();
}
