package com.runsecure.hkdfguard.abstractions;

/**
 * Builds CryptoProvider instances bound to a KeyWrapper, for each of the three ways this library
 * reveals a DEK.
 */
public interface CryptoProviderFactory {

    /**
     * Builds a CryptoProvider that reveals wrapped through wrapper, refreshing every
     * expirySeconds.
     */
    CryptoProvider create(KeyWrapper wrapper, byte[] wrapped, int expirySeconds);

    /**
     * Generates a fresh DEK via wrapper.generateAndWrap and builds a CryptoProvider around it,
     * refreshing every expirySeconds.
     */
    CryptoProvider createEphemeral(KeyWrapper wrapper, int expirySeconds);

    /**
     * Builds a CryptoProvider around notWrapped directly - notWrapped is already a plaintext
     * DEK, never wrapped or unwrapped through wrapper.
     */
    CryptoProvider createForPipeline(KeyWrapper wrapper, byte[] notWrapped);
}
