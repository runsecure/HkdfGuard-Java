package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IKeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoSessionProvider;
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

class PipelineDataEncryptionKeyTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BiFunction<IKeyWrapper, byte[], ICryptoSessionProvider> SESSION_PROVIDER_FACTORY =
            (keyWrapper, wrapped) -> new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60);

    @Test
    void constructor_withNoDekSupplied_generatesARandom32ByteDek() {
        try (PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
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
        try (PipelineDataEncryptionKey key1 = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY);
             PipelineDataEncryptionKey key2 = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
            assertNotEquals(Arrays.toString(key1.asBytes()), Arrays.toString(key2.asBytes()));
        }
    }

    @Test
    void constructor_withSuppliedDek_usesItAsIs() {
        byte[] dek = new byte[32];
        RANDOM.nextBytes(dek);
        byte[] expected = dek.clone();

        try (PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(dek, SESSION_PROVIDER_FACTORY)) {
            assertArrayEquals(expected, key.asBytes());
        }
    }

    @Test
    void constructor_withEmptyDek_throws() {
        assertThrows(IllegalArgumentException.class, () -> new PipelineDataEncryptionKey(new byte[32], SESSION_PROVIDER_FACTORY));
    }

    @Test
    void constructor_withWrongSizeDek_throws() {
        byte[] wrongSize = new byte[16];
        RANDOM.nextBytes(wrongSize);
        assertThrows(IllegalArgumentException.class, () -> new PipelineDataEncryptionKey(wrongSize, SESSION_PROVIDER_FACTORY));
    }

    @Test
    void encryptDecrypt_roundTrips() {
        try (PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
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
        try (PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
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
        try (PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
            byte[] encrypted = key.encrypt("top secret".getBytes(StandardCharsets.UTF_8), "context-a".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class,
                    () -> key.decrypt(encrypted, "context-b".getBytes(StandardCharsets.UTF_8), new byte[16]));
        }
    }

    @Test
    void twoInstances_withDifferentGeneratedDeks_cannotDecryptEachOthersCiphertext() {
        try (PipelineDataEncryptionKey key1 = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY);
             PipelineDataEncryptionKey key2 = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY)) {
            byte[] encrypted = key1.encrypt("top secret".getBytes(StandardCharsets.UTF_8));

            assertThrows(AuthenticationTagMismatchException.class, () -> key2.decrypt(encrypted, new byte[16]));
        }
    }

    @Test
    void close_zeroesTheDek() {
        PipelineDataEncryptionKey key = new PipelineDataEncryptionKey(SESSION_PROVIDER_FACTORY);

        key.close();

        assertArrayEquals(new byte[32], key.asBytes());
    }
}
