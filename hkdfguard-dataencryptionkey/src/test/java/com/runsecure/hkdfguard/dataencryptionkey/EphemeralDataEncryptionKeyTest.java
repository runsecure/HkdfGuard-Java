package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IKeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoSessionProvider;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AuthenticationTagMismatchException;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.FakeKeyWrapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EphemeralDataEncryptionKeyTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BiFunction<IKeyWrapper, byte[], ICryptoSessionProvider> SESSION_PROVIDER_FACTORY =
            (keyWrapper, wrapped) -> new AesGcmCryptoSessionProvider(keyWrapper, wrapped, 60);

    private static FakeKeyWrapper randomWrapper() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return new FakeKeyWrapper(key);
    }

    @Test
    void constructor_generatesWrappedDekExactlyOnce() {
        FakeKeyWrapper wrapper = randomWrapper();

        new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);

        assertEquals(1, wrapper.getGenerateAndWrapCallCount());
    }

    @Test
    void encryptDecrypt_roundTrips() {
        FakeKeyWrapper wrapper = randomWrapper();
        EphemeralDataEncryptionKey key = new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();

        byte[] encrypted = key.encrypt(plaintext);
        byte[] decrypted = new byte[expected.length];
        int written = key.decrypt(encrypted, decrypted);

        assertEquals(expected.length, written);
        assertArrayEquals(expected, decrypted);
    }

    @Test
    void encryptDecrypt_withAad_roundTrips() {
        FakeKeyWrapper wrapper = randomWrapper();
        EphemeralDataEncryptionKey key = new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();
        byte[] aad = "context".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = key.encrypt(plaintext, aad);
        byte[] decrypted = new byte[expected.length];
        int written = key.decrypt(encrypted, aad, decrypted);

        assertArrayEquals(expected, Arrays.copyOf(decrypted, written));
    }

    @Test
    void decrypt_withMismatchedAad_throws() {
        FakeKeyWrapper wrapper = randomWrapper();
        EphemeralDataEncryptionKey key = new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);
        byte[] encrypted = key.encrypt("top secret".getBytes(StandardCharsets.UTF_8), "context-a".getBytes(StandardCharsets.UTF_8));

        assertThrows(AuthenticationTagMismatchException.class,
                () -> key.decrypt(encrypted, "context-b".getBytes(StandardCharsets.UTF_8), new byte[16]));
    }

    @Test
    void encryptAndDecrypt_reuseTheSameGeneratedKeyAcrossCalls() {
        FakeKeyWrapper wrapper = randomWrapper();
        EphemeralDataEncryptionKey key = new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);

        byte[] encrypted1 = key.encrypt("first".getBytes(StandardCharsets.UTF_8));
        byte[] encrypted2 = key.encrypt("second".getBytes(StandardCharsets.UTF_8));

        byte[] result1 = new byte[5];
        byte[] result2 = new byte[6];
        key.decrypt(encrypted1, result1);
        key.decrypt(encrypted2, result2);

        assertEquals("first", new String(result1, StandardCharsets.UTF_8));
        assertEquals("second", new String(result2, StandardCharsets.UTF_8));
        assertEquals(1, wrapper.getGenerateAndWrapCallCount());
    }

    @Test
    void encryptAndDecrypt_reuseTheCachedSessionAcrossCalls() {
        // AesGcmCryptoSessionProvider only calls back into the key wrapper when it has no cached
        // session yet or the cached one has expired - not on every operation - so the wrapper's
        // key is revealed once here, then reused for every subsequent encrypt/decrypt.
        FakeKeyWrapper wrapper = randomWrapper();
        EphemeralDataEncryptionKey key = new EphemeralDataEncryptionKey(wrapper, SESSION_PROVIDER_FACTORY);
        byte[] encrypted = key.encrypt("value".getBytes(StandardCharsets.UTF_8));

        key.decrypt(encrypted, new byte[5]);
        key.decrypt(encrypted, new byte[5]);

        assertEquals(1, wrapper.getDecryptCallCount());
    }
}
