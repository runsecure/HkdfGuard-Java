package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import com.runsecure.hkdfguard.cache.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.cache.testhelpers.ThrowingReadOnlyCache;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.KeyWrappedDataEncryptionKeyImpl;
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

class ProtectedCacheCollectionImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static ProtectedCacheImpl createCache() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        DataEncryptionKey dataEncryptionKey = new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        return new ProtectedCacheImpl(dataEncryptionKey);
    }

    @Test
    void add_returnsSameInstance_forFluentChaining() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl();

        ProtectedCacheCollectionImpl returned = collection.add(createCache());

        assertSame(collection, returned);
    }

    @Test
    void decrypt_bytes_withNoSources_returnsZero() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl();

        int written = collection.decrypt("item", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decrypt_bytes_returnsFromFirstSourceThatHasIt() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        first.add("item", "from-first".getBytes(StandardCharsets.UTF_8));
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        byte[] result = new byte[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-first", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_bytes_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        byte[] result = new byte[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-second", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_bytes_withNoSourceHavingTheName_returnsZero() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(createCache()).add(createCache());

        int written = collection.decrypt("missing", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decrypt_chars_returnsFromFirstSourceThatHasIt() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        first.add("item", "from-first".toCharArray());
        second.add("item", "from-second".toCharArray());

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        char[] result = new char[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-first", new String(result, 0, written));
    }

    @Test
    void decrypt_chars_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        second.add("item", "from-second".toCharArray());

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        char[] result = new char[32];
        int written = collection.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("from-second", new String(result, 0, written));
    }

    @Test
    void decrypt_chars_withNoSourceHavingTheName_returnsZero() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(createCache()).add(createCache());

        int written = collection.decrypt("missing", new char[16]);

        assertEquals(0, written);
    }

    @Test
    void tryGetMaxDecryptedLength_withNoSources_returnsEmpty() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl();

        assertFalse(collection.tryGetMaxDecryptedLength("item").isPresent());
    }

    @Test
    void tryGetMaxDecryptedLength_returnsFromFirstSourceThatHasIt() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        first.add("item", "abc".getBytes(StandardCharsets.UTF_8));
        second.add("item", "a much longer value than the first source has".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        OptionalInt expectedMaxLength = first.tryGetMaxDecryptedLength("item");
        OptionalInt maxLength = collection.tryGetMaxDecryptedLength("item");

        assertTrue(expectedMaxLength.isPresent());
        assertTrue(maxLength.isPresent());
        assertEquals(expectedMaxLength.getAsInt(), maxLength.getAsInt());
    }

    @Test
    void tryGetMaxDecryptedLength_fallsThroughToLaterSourceWhenEarlierOnesLackTheName() {
        ProtectedCacheImpl first = createCache();
        ProtectedCacheImpl second = createCache();
        second.add("item", "from-second".getBytes(StandardCharsets.UTF_8));

        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(first).add(second);

        OptionalInt maxLength = collection.tryGetMaxDecryptedLength("item");

        assertTrue(maxLength.isPresent());
        assertTrue(maxLength.getAsInt() > 0);
    }

    @Test
    void tryGetMaxDecryptedLength_withNoSourceHavingTheName_returnsEmpty() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(createCache()).add(createCache());

        assertFalse(collection.tryGetMaxDecryptedLength("missing").isPresent());
    }

    @Test
    void decrypt_bytes_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCacheImpl source = createCache();
            source.add("item", "top secret".getBytes(StandardCharsets.UTF_8));
            ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(source);

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

            ProtectedCacheImpl source = createCache();
            source.add("item", "top secret".toCharArray());
            ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl().add(source);

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
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl()
                .add(new ThrowingReadOnlyCache(new IllegalStateException("boom")));

        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new byte[16]));
    }

    @Test
    void decrypt_chars_whenASourceThrows_recordsExceptionAndThrows() {
        ProtectedCacheCollectionImpl collection = new ProtectedCacheCollectionImpl()
                .add(new ThrowingReadOnlyCache(new IllegalStateException("boom")));

        assertThrows(IllegalStateException.class, () -> collection.decrypt("item", new char[16]));
    }
}
