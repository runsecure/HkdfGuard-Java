package com.runsecure.hkdfguard.abstractions;

/**
 * Read/write surface of a highly concurrent name -&gt; encrypted-value cache backed by a single
 * DataEncryptionKey. add/addOrUpdate protect and store plaintext under a name; the read surface
 * (decrypt/tryGetMaxDecryptedLength) is inherited from ProtectedReadOnlyCache. Nothing here ever
 * holds plaintext beyond the duration of a single add/addOrUpdate call - only the encrypted bytes
 * are retained internally.
 */
public interface ProtectedCache extends ProtectedReadOnlyCache {

    /**
     * Encrypts plaintext and stores it under name.
     *
     * @param name The name to store the encrypted value under
     * @param plaintext The plaintext to protect - zeroed as a side effect of encrypting it
     * @throws IllegalArgumentException A value is already stored under this name
     */
    void add(String name, byte[] plaintext);

    /**
     * Encrypts plaintext (as UTF-8 bytes) and stores it under name.
     *
     * @param name The name to store the encrypted value under
     * @param plaintext The plaintext to protect - zeroed as a side effect of encrypting it
     * @throws IllegalArgumentException A value is already stored under this name
     */
    void add(String name, char[] plaintext);

    /**
     * Encrypts plaintext and stores it under name, replacing any value already stored under that
     * name.
     *
     * @param name The name to store the encrypted value under
     * @param plaintext The plaintext to protect - zeroed as a side effect of encrypting it
     */
    void addOrUpdate(String name, byte[] plaintext);

    /**
     * Encrypts plaintext (as UTF-8 bytes) and stores it under name, replacing any value already
     * stored under that name.
     *
     * @param name The name to store the encrypted value under
     * @param plaintext The plaintext to protect - zeroed as a side effect of encrypting it
     */
    void addOrUpdate(String name, char[] plaintext);
}
