package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.DataProtectionKey;
import com.runsecure.hkdfguard.cache.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.cache.testhelpers.PopulatingCache;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.KeyWrappedDataEncryptionKeyImpl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtectedCacheBaseTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static PopulatingCache createCache() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        DataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        return new PopulatingCache(dataProtectionKey);
    }

    @Test
    void decrypt_onMiss_callsTryPopulate_andReturnsPopulatedValue() {
        PopulatingCache cache = createCache();
        cache.setOnTryPopulate(name -> {
            cache.seed(name, "populated value".toCharArray());
            return true;
        });

        byte[] result = new byte[32];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals(1, cache.getTryPopulateCallCount());
        assertEquals("populated value", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_whenAlreadyCached_doesNotCallTryPopulate() {
        PopulatingCache cache = createCache();
        cache.seed("item", "already cached".toCharArray());
        cache.setOnTryPopulate(name -> {
            throw new IllegalStateException("should not be called");
        });

        byte[] result = new byte[32];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals(0, cache.getTryPopulateCallCount());
        assertEquals("already cached", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_whenTryPopulateReturnsFalse_returnsZero() {
        PopulatingCache cache = createCache();
        cache.setOnTryPopulate(name -> false);

        int written = cache.decrypt("item", new byte[32]);

        assertEquals(0, written);
        assertEquals(1, cache.getTryPopulateCallCount());
    }

    @Test
    void decrypt_whenTryPopulateReturnsTrueButDoesNotActuallyPopulate_returnsZero() {
        PopulatingCache cache = createCache();
        cache.setOnTryPopulate(name -> true); // lies - never calls seed

        int written = cache.decrypt("item", new byte[32]);

        assertEquals(0, written);
    }

    @Test
    void tryGetMaxDecryptedLength_onMiss_callsTryPopulate() {
        PopulatingCache cache = createCache();
        cache.setOnTryPopulate(name -> {
            cache.seed(name, "populated value".toCharArray());
            return true;
        });

        OptionalInt found = cache.tryGetMaxDecryptedLength("item");

        assertTrue(found.isPresent());
        assertTrue(found.getAsInt() > 0);
        assertEquals(1, cache.getTryPopulateCallCount());
    }

    @Test
    void defaultTryPopulate_returnsFalse_withoutOverride() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        DataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        PopulatingCache cache = new PopulatingCache(dataProtectionKey);
        cache.setOnTryPopulate(null);

        int written = cache.decrypt("item", new byte[16]);

        assertEquals(0, written);
    }
}
