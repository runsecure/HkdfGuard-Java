package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AuthenticationTagMismatchException;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.SensitiveLoggingScope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyWrappedDataEncryptionKeyImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyWrappedDataEncryptionKeyImpl createKey(FakeKeyWrapper[] wrapperOut) {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        if (wrapperOut != null) {
            wrapperOut[0] = wrapper;
        }
        return new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
    }

    @Test
    void encryptDecrypt_roundTrips() {
        KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(null);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        // AesGcmCryptoSession.encrypt zeroes the plaintext array it's given as a side effect.
        byte[] expected = plaintext.clone();

        byte[] encrypted = dataProtectionKey.encrypt(plaintext);
        assertEquals(expected.length + 12 + 16, encrypted.length);

        byte[] decrypted = new byte[expected.length];
        int decryptedLength = dataProtectionKey.decrypt(encrypted, decrypted);

        assertEquals(expected.length, decryptedLength);
        assertArrayEquals(expected, decrypted);
    }

    @Test
    void encryptDecrypt_withAad_roundTrips() {
        KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(null);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();
        byte[] aad = "context".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = dataProtectionKey.encrypt(plaintext, aad);

        byte[] decrypted = new byte[expected.length];
        int decryptedLength = dataProtectionKey.decrypt(encrypted, aad, decrypted);

        assertArrayEquals(expected, Arrays.copyOf(decrypted, decryptedLength));
    }

    @Test
    void decrypt_withMismatchedAad_throws() {
        KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(null);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = dataProtectionKey.encrypt(plaintext, "context-a".getBytes(StandardCharsets.UTF_8));

        byte[] result = new byte[plaintext.length];
        assertThrows(AuthenticationTagMismatchException.class,
                () -> dataProtectionKey.decrypt(encrypted, "context-b".getBytes(StandardCharsets.UTF_8), result));
    }

    @Test
    void encryptDecrypt_withSensitiveLoggingEnabled_stillRoundTrips() {
        try (SensitiveLoggingScope ignored = new SensitiveLoggingScope(true)) {
            KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(null);
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();

            byte[] encrypted = dataProtectionKey.encrypt(plaintext);
            byte[] decrypted = new byte[expected.length];
            int decryptedLength = dataProtectionKey.decrypt(encrypted, decrypted);

            assertArrayEquals(expected, Arrays.copyOf(decrypted, decryptedLength));
        }
    }

    @Test
    void encrypt_returnsExactlySizedArray() {
        KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(null);
        byte[] plaintext = "a longer plaintext value to encrypt".getBytes(StandardCharsets.UTF_8);
        int expectedLength = plaintext.length + 12 + 16; // AES-GCM nonce + tag overhead

        byte[] encrypted = dataProtectionKey.encrypt(plaintext);

        assertEquals(expectedLength, encrypted.length);
    }

    @Test
    void encryptAndDecrypt_reuseTheCachedSessionAcrossCalls() {
        // AesGcmCryptoProviderImpl only calls back into the key wrapper when it has no cached
        // session yet or the cached one has expired - not on every operation - so a wrapper's
        // key is revealed once here, then reused for every subsequent encrypt/decrypt.
        FakeKeyWrapper[] wrapperOut = new FakeKeyWrapper[1];
        KeyWrappedDataEncryptionKeyImpl dataProtectionKey = createKey(wrapperOut);
        byte[] encrypted1 = dataProtectionKey.encrypt("one".getBytes(StandardCharsets.UTF_8));
        byte[] encrypted2 = dataProtectionKey.encrypt("two".getBytes(StandardCharsets.UTF_8));

        dataProtectionKey.decrypt(encrypted1, new byte[3]);
        dataProtectionKey.decrypt(encrypted2, new byte[3]);

        assertEquals(1, wrapperOut[0].getDecryptCallCount());
    }
}
