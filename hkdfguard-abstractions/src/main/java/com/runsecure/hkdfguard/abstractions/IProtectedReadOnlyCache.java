package com.runsecure.hkdfguard.abstractions;

import java.util.OptionalInt;

/**
 * Read surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
 * IDataProtectionKey. Names are compared case-insensitively, matching ConcurrentHashMap /
 * ConcurrentSkipListMap conventions used by implementations. decrypt reveals a stored value back
 * into a caller-owned array, returning 0 for a missing name rather than throwing. Nothing here
 * ever holds plaintext beyond the duration of a single decrypt call - only the encrypted bytes
 * are retained internally.
 */
public interface IProtectedReadOnlyCache {

    /**
     * Decrypts the value stored under name into result.
     *
     * @param name The name the value was stored under
     * @param result The array to receive the decrypted plaintext bytes
     * @return Number of bytes written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, byte[] result);

    /**
     * Decrypts the value stored under name into result as UTF-8-decoded characters.
     *
     * @param name The name the value was stored under
     * @param result The array to receive the decrypted plaintext characters
     * @return Number of chars written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, char[] result);

    /**
     * Computes an upper bound on how many bytes or chars decrypt will write for the value stored
     * under name, so a result buffer can be sized without decrypting first.
     *
     * @param name The name the value was stored under
     * @return An upper bound on the decrypted length, or empty if no value is stored under name
     */
    OptionalInt tryGetMaxDecryptedLength(String name);
}
