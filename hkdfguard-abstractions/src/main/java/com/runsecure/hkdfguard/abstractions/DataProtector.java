package com.runsecure.hkdfguard.abstractions;

/**
 * A named, string-level data protector: the name given at construction is used as the Additional
 * Auth Data for every encrypt/decrypt, binding a protected value to the purpose it was protected
 * for so it can't be reused under a different one. encrypt/decrypt resolve the actual
 * IDataProtectionKey to use from a KeyRing, rather than holding one key permanently.
 */
public interface IDataProtector {

    /**
     * Encrypts a plaintext char array and formats the result via the configured
     * IEncryptedFormatProvider
     *
     * @param plaintext The plaintext to encrypt
     * @return The formatted, encrypted string
     */
    String encrypt(char[] plaintext);

    /**
     * Parses a formatted encrypted string via the configured IEncryptedFormatProvider and
     * decrypts it directly into result - this never materializes the plaintext as a String.
     *
     * @param encrypted The formatted, encrypted string, as chars
     * @param result The array to receive the decrypted plaintext characters
     * @return Number of chars written to result
     */
    int decrypt(char[] encrypted, char[] result);

    /**
     * Computes an upper bound on how many chars decrypt will write for the given formatted
     * string, so a result buffer can be sized without decrypting first.
     *
     * @param encrypted The formatted, encrypted string, as chars
     * @return An upper bound on the decrypted length
     */
    int getMaxDecryptedLength(char[] encrypted);
}
