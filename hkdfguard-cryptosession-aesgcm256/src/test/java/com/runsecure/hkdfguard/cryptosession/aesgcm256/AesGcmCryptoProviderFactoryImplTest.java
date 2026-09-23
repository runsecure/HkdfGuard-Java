package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AesGcmCryptoProviderFactoryImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AesGcmCryptoProviderFactoryImpl FACTORY = new AesGcmCryptoProviderFactoryImpl();

    @Test
    void create_producesAWorkingProvider() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (CryptoProvider provider = FACTORY.create(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int written = provider.encrypt(plaintext, encrypted);

            byte[] decrypted = new byte[plaintext.length];
            assertEquals(plaintext.length, provider.decrypt(Arrays.copyOf(encrypted, written), decrypted));
        }
    }

    @Test
    void createEphemeral_callsGenerateAndWrapExactlyOnce() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (CryptoProvider ignored = FACTORY.createEphemeral(wrapper, 60)) {
            assertEquals(1, wrapper.getGenerateAndWrapCallCount());
        }
    }

    @Test
    void createEphemeral_producesAWorkingProvider() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (CryptoProvider provider = FACTORY.createEphemeral(wrapper, 60)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();
            byte[] encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int written = provider.encrypt(plaintext, encrypted);

            byte[] decrypted = new byte[expected.length];
            int decryptedLength = provider.decrypt(Arrays.copyOf(encrypted, written), decrypted);

            assertEquals(expected.length, decryptedLength);
            assertArrayEquals(expected, decrypted);
        }
    }

    @Test
    void createForPipeline_neverCallsTheKeyWrapper() {
        // createForPipeline uses the supplied bytes directly as the AES key - there is nothing to
        // wrap/unwrap, so the wrapper it's handed should never be invoked.
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        wrapper.setThrowOnDecrypt(new IllegalStateException("should not be called"));
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);

        try (CryptoProvider ignored = FACTORY.createForPipeline(wrapper, dek)) {
            assertEquals(0, wrapper.getDecryptCallCount());
            assertEquals(0, wrapper.getGenerateAndWrapCallCount());
        }
    }

    @Test
    void createForPipeline_producesAWorkingProvider() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);

        try (CryptoProvider provider = FACTORY.createForPipeline(wrapper, dek)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();
            byte[] encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int written = provider.encrypt(plaintext, encrypted);

            byte[] decrypted = new byte[expected.length];
            int decryptedLength = provider.decrypt(Arrays.copyOf(encrypted, written), decrypted);

            assertEquals(expected.length, decryptedLength);
            assertArrayEquals(expected, decrypted);
        }
    }

    @Test
    void createForPipeline_providerCloseDoesNotThrow() {
        // Regression test: the pipeline-only AesGcmCryptoProviderImpl constructor used to leave
        // its background-refresh executor field null, and close unconditionally called
        // refreshExecutor.shutdownNow(), throwing a NullPointerException.
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);
        CryptoProvider provider = FACTORY.createForPipeline(wrapper, dek);

        assertDoesNotThrow(provider::close);
    }
}
