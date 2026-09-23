package com.runsecure.hkdfguard.abstractions;

/**
 * Protects (encrypt) and reveals (decrypt) an encryption key against a single, implicitly
 * identified KEK (e.g. a native KMS-backed key, identified by service name at construction).
 * decrypt takes the wrapped payload as an explicit argument on every call, so one instance can
 * reveal any number of different wrapped keys sharing the same KEK - it holds no wrapped payload
 * of its own.
 */
public interface KeyWrapper {

    /**
     * Protects an encryption key
     *
     * @param plaintext The plain bytes to encrypt
     * @param result The encrypted key
     * @return Number of bytes written to the result
     */
    int encrypt(byte[] plaintext, byte[] result);

    /**
     * Protects an encryption key
     *
     * @param plaintext The plain bytes to encrypt
     * @param result The encrypted key
     * @param aad Additional Auth Data for the encrypt operation
     * @return Number of bytes written to the result
     */
    int encrypt(byte[] plaintext, byte[] result, byte[] aad);

    /**
     * Reveals a previously-wrapped key
     *
     * @param wrapped The wrapped key to reveal
     * @param result The decrypted key array
     * @return Number of bytes written to the result
     */
    int decrypt(byte[] wrapped, byte[] result);

    /**
     * Reveals a previously-wrapped key
     *
     * @param wrapped The wrapped key to reveal
     * @param result The decrypted key array
     * @param aad Additional Auth Data for decrypting the key
     * @return Number of bytes written to the result
     */
    int decrypt(byte[] wrapped, byte[] result, byte[] aad);

    /**
     * Generates a fresh key and immediately protects it against the same KEK this instance
     * wraps/reveals against - the plaintext key never crosses this call's return value.
     *
     * @param result The wrapped key
     * @return Number of bytes written to the result
     */
    int generateAndWrap(byte[] result);
}
