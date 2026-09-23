package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCryptoSessionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    @Test
    void encryptDecrypt_roundTrips() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] expectedPlaintext = plaintext.clone();
            byte[] encrypted = new byte[plaintext.length + 28];

            int written = cipher.encrypt(plaintext, encrypted);
            assertEquals(encrypted.length, written);

            byte[] decrypted = new byte[expectedPlaintext.length];
            int decryptedLength = cipher.decrypt(encrypted, decrypted);

            assertEquals(expectedPlaintext.length, decryptedLength);
            assertArrayEquals(expectedPlaintext, decrypted);
        }
    }

    @Test
    void encryptDecrypt_roundTrips_withAad() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] expectedPlaintext = plaintext.clone();
            byte[] aad = "context".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = new byte[plaintext.length + 28];

            cipher.encrypt(plaintext, aad, encrypted);

            byte[] decrypted = new byte[expectedPlaintext.length];
            cipher.decrypt(encrypted, aad, decrypted);

            assertArrayEquals(expectedPlaintext, decrypted);
        }
    }

    @Test
    void decrypt_withWrongAad_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = new byte[plaintext.length + 28];
            cipher.encrypt(plaintext, "correct-aad".getBytes(StandardCharsets.UTF_8), encrypted);

            byte[] decrypted = new byte[11];
            assertThrows(AuthenticationTagMismatchException.class,
                    () -> cipher.decrypt(encrypted, "wrong-aad".getBytes(StandardCharsets.UTF_8), decrypted));
        }
    }

    @Test
    void decrypt_withTamperedCiphertext_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = new byte[plaintext.length + 28];
            cipher.encrypt(plaintext, encrypted);
            encrypted[15] ^= (byte) 0xFF;

            byte[] decrypted = new byte[11];
            assertThrows(AuthenticationTagMismatchException.class, () -> cipher.decrypt(encrypted, decrypted));
        }
    }

    @Test
    void encrypt_withTooSmallResultBuffer_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] tooSmall = new byte[plaintext.length];

            assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(plaintext, tooSmall));
        }
    }

    @Test
    void decrypt_withTooShortCiphertext_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] tooShort = new byte[10];
            byte[] result = new byte[4];

            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(tooShort, result));
        }
    }

    @Test
    @SuppressWarnings("resource")
    void constructor_withInvalidKeySize_throws() {
        byte[] invalidKey = new byte[10];
        RANDOM.nextBytes(invalidKey);

        assertThrows(IllegalArgumentException.class, () -> new AesGcmCryptoSession(invalidKey));
    }

    @Test
    @SuppressWarnings("resource")
    void constructor_withAllZeroKey_throws() {
        byte[] zeroKey = new byte[32];

        assertThrows(IllegalArgumentException.class, () -> new AesGcmCryptoSession(zeroKey));
    }

    @Test
    void encrypt_withAllZeroPlaintext_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] zeroPlaintext = new byte[11];
            byte[] encrypted = new byte[zeroPlaintext.length + 28];

            assertThrows(IllegalArgumentException.class, () -> cipher.encrypt(zeroPlaintext, encrypted));
        }
    }

    @Test
    void decrypt_withNonZeroButTooShortCiphertext_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] tooShort = new byte[10];
            RANDOM.nextBytes(tooShort); // non-zero, but shorter than nonce + tag
            byte[] result = new byte[4];

            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(tooShort, result));
        }
    }

    @Test
    void decrypt_withTooSmallResultBuffer_throws() {
        try (AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey())) {
            byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = new byte[plaintext.length + 28];
            cipher.encrypt(plaintext, encrypted);

            byte[] tooSmall = new byte[plaintext.length - 1];
            assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(encrypted, tooSmall));
        }
    }

    @Test
    void close_zeroesTheKey() {
        byte[] key = randomKey();
        byte[] keyClone = key.clone();
        AesGcmCryptoSession cipher = new AesGcmCryptoSession(key);

        cipher.close();

        assertArrayEquals(new byte[32], key);
        assertNotEquals(Arrays.toString(keyClone), Arrays.toString(key));
    }

    @Test
    void close_thenEncrypt_throws() {
        AesGcmCryptoSession cipher = new AesGcmCryptoSession(randomKey());
        cipher.close();

        assertThrows(ObjectDisposedException.class,
                () -> cipher.encrypt("hello".getBytes(StandardCharsets.UTF_8), new byte[33]));
    }
}
