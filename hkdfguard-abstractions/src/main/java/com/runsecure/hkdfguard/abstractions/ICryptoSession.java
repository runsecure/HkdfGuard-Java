package com.runsecure.hkdfguard.abstractions;

import java.time.Instant;

/**
 * A live, key-bound symmetric-cipher session: the key is supplied once, at construction (not
 * per-call), and this instance holds it - and whatever native resources the cipher needs - until
 * closed. getExpiresAt marks when a caller (see ICryptoSessionProvider) should treat this session
 * as stale and refresh it, rather than reuse it indefinitely.
 */
public interface ICryptoSession extends AutoCloseable {

    /**
     * The instant after which this session should no longer be reused.
     */
    Instant getExpiresAt();

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
