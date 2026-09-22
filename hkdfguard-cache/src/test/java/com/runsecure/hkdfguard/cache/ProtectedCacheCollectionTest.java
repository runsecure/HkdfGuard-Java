package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.cache.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.cache.testhelpers.ThrowingReadOnlyCache;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoSessionProvider;
import com.runsecure.hkdfguard.dataencryptionkey.KeyWrappedDataEncryptionKey;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProtectedCacheCollectionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static ProtectedCache createCache() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        IDataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKey(
                new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        return new ProtectedCache(dataProtectionKey);
    }

    @Test
    void add_returnsSameInstance_forFluentChaining() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection();

        ProtectedCacheCollection returned = collection.add(createCache());

        assertSame(collection, returned);
    }

    @Test
    void decrypt_bytes_withNoSources_returnsZero() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection();

        int written = collection.decrypt("item", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decrypt_bytes_returnsFromFirstSourceThatHasIt() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        first.add("item", "from-first".getBytes(StandardCharsets.UTF_8));
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        byte[] result = new byte[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-first", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_bytes_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        byte[] result = new byte[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-second", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_bytes_withNoSourceHavingTheName_returnsZero() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(createCache()).add(createCache());

        int written = collection.decrypt("missing", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decrypt_chars_returnsFromFirstSourceThatHasIt() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        first.add("item", "from-first".toCharArray());
        second.add("item", "from-second".toCharArray());

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        char[] result = new char[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-first", new String(result, 0, written));
    }

    @Test
    void decrypt_chars_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        second.add("item", "from-second".toCharArray());

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        char[] result = new char[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-second", new String(result, 0, written));
    }

    @Test
    void decrypt_chars_withNoSourceHavingTheName_returnsZero() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(createCache()).add(createCache());

        int written = collection.decrypt("missing", new char[16]);

        assertEquals(0, written);
    }

    @Test
    void tryGetMaxDecryptedLength_withNoSources_returnsEmpty() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection();

        assertFalse(collection.tryGetMaxDecryptedLength("item").isPresent());
    }

    @Test
    void tryGetMaxDecryptedLength_returnsFromFirstSourceThatHasIt() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        first.add("item", "abc".getBytes(StandardCharsets.UTF_8));
        second.add("item", "a much longer value than the first source has".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        OptionalInt expectedMaxLength = first.tryGetMaxDecryptedLength("item");
        OptionalInt maxLength = collection.tryGetMaxDecryptedLength("item");

        assertTrue(maxLength.isPresent());
        assertEquals(expectedMaxLength.getAsInt(), maxLength.getAsInt());
    }

    @Test
    void tryGetMaxDecryptedLength_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCache first = createCache();
        ProtectedCache second = createCache();
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(first).add(second);

        OptionalInt maxLength = collection.tryGetMaxDecryptedLength("item");

        assertTrue(maxLength.isPresent());
        assertTrue(maxLength.getAsInt() > 0);
    }

    @Test
    void tryGetMaxDecryptedLength_withNoSourceHavingTheName_returnsEmpty() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection().add(createCache()).add(createCache());

        assertFalse(collection.tryGetMaxDecryptedLength("missing").isPresent());
    }

    @Test
    void decrypt_bytes_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache source = createCache();
            source.add("item", "top secret".getBytes(StandardCharsets.UTF_8));
            ProtectedCacheCollection collection = new ProtectedCacheCollection().add(source);

            byte[] result = new byte[32];
            int written = collection.decrypt("item", result);

            assertTrue(written > 0);
            assertEquals("top secret", new String(result, 0, written, StandardCharsets.UTF_8));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void decrypt_chars_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache source = createCache();
            source.add("item", "top secret".toCharArray());
            ProtectedCacheCollection collection = new ProtectedCacheCollection().add(source);

            char[] result = new char[32];
            int written = collection.decrypt("item", result);

            assertTrue(written > 0);
            assertEquals("top secret", new String(result, 0, written));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void decrypt_bytes_whenASourceThrows_recordsExceptionAndThrows() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection()
                .add(new ThrowingReadOnlyCache(new IllegalStateException("boom")));

        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new byte[16]));
    }

    @Test
    void decrypt_chars_whenASourceThrows_recordsExceptionAndThrows() {
        ProtectedCacheCollection collection = new ProtectedCacheCollection()
                .add(new ThrowingReadOnlyCache(new IllegalStateException("boom")));

        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new char[16]));
    }
}
