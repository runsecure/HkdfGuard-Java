package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AuthenticationTagMismatchException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PipelineDataEncryptionKeyImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BiFunction<KeyWrapper, byte[], CryptoProvider> SESSION_PROVIDER_FACTORY =
            (keyWrapper, wrapped) -> new AesGcmCryptoProviderImpl(keyWrapper, wrapped, 60);

    @Test
    void constructor_withNoDekSupplied_generatesARandom32ByteDek() {
        try (PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
            assertEquals(32, key.asBytes().length);

            boolean allZero = true;
            for (byte b : key.asBytes()) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            assertFalse(allZero);
        }
    }

    @Test
    void constructor_withNoDekSupplied_generatesADifferentDekEachTime() {
        try (PipelineDataEncryptionKeyImpl key1 = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY);
             PipelineDataEncryptionKeyImpl key2 = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
            assertNotEquals(Arrays.toString(key1.asBytes()), Arrays.toString(key2.asBytes()));
        }
    }

    @Test
    void constructor_withSuppliedDek_usesItAsIs() {
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);
        byte[] expected = dek.clone();

        try (PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(dek, SESSION_PROVIDER_FACTORY)) {
            assertArrayEquals(expected, key.asBytes());
        }
    }

    @Test
    void constructor_withEmptyDek_throws() {
        assertThrows(IllegalArgumentException.class, () -> new PipelineDataEncryptionKeyImpl(new byte[32], SESSION_PROVIDER_FACTORY));
    }

    @Test
    void constructor_withWrongSizeDek_throws() {
        byte[] wrongSize = new byte[16];
        RANDOM.nextBytes(wrongSize);
        assertThrows(IllegalArgumentException.class, () -> new PipelineDataEncryptionKeyImpl(wrongSize, SESSION_PROVIDER_FACTORY));
    }

    @Test
    void encryptDecrypt_roundTrips() {
        try (PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
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
        try (PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
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
        try (PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
            byte[] encrypted = key.encrypt("top secret".getBytes(StandardCharsets.UTF_8), "context-a".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class,
                    () -> key.decrypt(encrypted, "context-b".getBytes(StandardCharsets.UTF_8), new byte[16]));
        }
    }

    @Test
    void twoInstances_withDifferentGeneratedDeks_cannotDecryptEachOthersCiphertext() {
        try (PipelineDataEncryptionKeyImpl key1 = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY);
             PipelineDataEncryptionKeyImpl key2 = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY)) {
            byte[] encrypted = key1.encrypt("top secret".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class, () -> key2.decrypt(encrypted, new byte[16]));
        }
    }

    @Test
    void close_zeroesTheDek() {
        PipelineDataEncryptionKeyImpl key = new PipelineDataEncryptionKeyImpl(SESSION_PROVIDER_FACTORY);

        key.close();

        assertArrayEquals(new byte[32], key.asBytes());
    }
}
