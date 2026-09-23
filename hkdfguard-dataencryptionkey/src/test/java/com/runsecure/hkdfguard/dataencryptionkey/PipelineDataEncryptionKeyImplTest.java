package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AuthenticationTagMismatchException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PipelineDataEncryptionKeyImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AesGcmCryptoProviderFactoryImpl CRYPTO_PROVIDER_FACTORY = new AesGcmCryptoProviderFactoryImpl();

    private static PipelineDataEncryptionKeyImpl createKey(byte[] dek) {
        if (dek == null) {
            dek = new byte[32];
            RANDOM.nextBytes(dek);
        }
        CryptoProvider provider = CRYPTO_PROVIDER_FACTORY.createForPipeline(new DummyKeyWrapperImpl(), dek);
        return new PipelineDataEncryptionKeyImpl(provider, dek);
    }

    @Test
    void asBytes_returnsTheSuppliedDek() {
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);
        byte[] expected = dek.clone();

        try (PipelineDataEncryptionKeyImpl key = createKey(dek)) {
            assertArrayEquals(expected, key.asBytes());
        }
    }

    @Test
    void encryptDecrypt_roundTrips() {
        try (PipelineDataEncryptionKeyImpl key = createKey(null)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();

            byte[] encrypted = key.encrypt(plaintext);
            byte[] decrypted = new byte[expected.length];
            int written = key.decrypt(encrypted, decrypted);

            assertEquals(expected.length, written);
            assertArrayEquals(expected, decrypted);
        }
    }

    @Test
    void encryptDecrypt_withAad_roundTrips() {
        try (PipelineDataEncryptionKeyImpl key = createKey(null)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();
            byte[] aad = "context".getBytes(StandardCharsets.UTF_8);

            byte[] encrypted = key.encrypt(plaintext, aad);
            byte[] decrypted = new byte[expected.length];
            int written = key.decrypt(encrypted, aad, decrypted);

            assertArrayEquals(expected, Arrays.copyOf(decrypted, written));
        }
    }

    @Test
    void decrypt_withMismatchedAad_throws() {
        try (PipelineDataEncryptionKeyImpl key = createKey(null)) {
            byte[] encrypted = key.encrypt("top secret".getBytes(StandardCharsets.UTF_8), "context-a".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class,
                    () -> key.decrypt(encrypted, "context-b".getBytes(StandardCharsets.UTF_8), new byte[16]));
        }
    }

    @Test
    void twoInstances_withDifferentDeks_cannotDecryptEachOthersCiphertext() {
        try (PipelineDataEncryptionKeyImpl key1 = createKey(null);
             PipelineDataEncryptionKeyImpl key2 = createKey(null)) {
            byte[] encrypted = key1.encrypt("top secret".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class, () -> key2.decrypt(encrypted, new byte[16]));
        }
    }

    @Test
    void close_zeroesTheDek() {
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);

        PipelineDataEncryptionKeyImpl key = createKey(dek);
        key.close();

        assertArrayEquals(new byte[32], dek);
    }

    @Test
    void close_doesNotThrow() {
        // Regression test: AesGcmCryptoProviderImpl's pipeline-only constructor used to leave its
        // background-refresh executor field null, which crashed close with a
        // NullPointerException once PipelineDataEncryptionKeyImpl started closing its provider.
        PipelineDataEncryptionKeyImpl key = createKey(null);

        assertDoesNotThrow(key::close);
    }
}
