package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.cache.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoSessionProvider;
import com.runsecure.hkdfguard.dataencryptionkey.KeyWrappedDataEncryptionKey;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import com.runsecure.hkdfguard.diagnostics.MetricNames;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.nio.BufferOverflowException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ProtectedCacheTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Mock
    private Logger logger;

    @Captor
    private ArgumentCaptor<Object> debugArgCaptor;

    private static ProtectedCache createCache() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        IDataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKey(
                new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        return new ProtectedCache(dataProtectionKey);
    }

    @Test
    void addDecrypt_bytes_roundTrips() {
        ProtectedCache cache = createCache();
        byte[] plaintext = "top secret bytes".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();

        cache.add("item", plaintext);

        byte[] result = new byte[expected.length];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals(expected.length, written);
        assertArrayEquals(expected, result);
    }

    @Test
    void addDecrypt_chars_roundTrips() {
        ProtectedCache cache = createCache();
        String plaintext = "top secret chars";

        cache.add("item", plaintext.toCharArray());

        char[] result = new char[plaintext.length()];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals(plaintext.length(), written);
        assertEquals(plaintext, new String(result, 0, written));
    }

    @Test
    void addDecrypt_chars_handlesMultiByteUtf8() {
        ProtectedCache cache = createCache();
        String plaintext = "héllo wörld 日本語";

        cache.add("item", plaintext.toCharArray());

        char[] result = new char[plaintext.length()];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals(plaintext, new String(result, 0, written));
    }

    @Test
    void add_bytes_calledTwiceWithSameName_throwsIllegalArgumentException() {
        ProtectedCache cache = createCache();

        cache.add("item", "first".getBytes(StandardCharsets.UTF_8));

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", "second".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void add_chars_calledTwiceWithSameName_throwsIllegalArgumentException() {
        ProtectedCache cache = createCache();

        cache.add("item", "first".toCharArray());

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", "second".toCharArray()));
    }

    @Test
    void add_bytes_calledTwiceWithDifferentCasedName_throwsIllegalArgumentException() {
        ProtectedCache cache = createCache();

        cache.add("Item", "first".getBytes(StandardCharsets.UTF_8));

        assertThrows(IllegalArgumentException.class, () -> cache.add("ITEM", "second".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void add_bytes_doesNotReplacePreviousValueWhenDuplicateNameRejected() {
        ProtectedCache cache = createCache();
        byte[] original = "original".getBytes(StandardCharsets.UTF_8);
        byte[] expected = original.clone();

        cache.add("item", original);
        assertThrows(IllegalArgumentException.class,
                () -> cache.add("item", "attempted-overwrite".getBytes(StandardCharsets.UTF_8)));

        byte[] result = new byte[expected.length];
        int written = cache.decrypt("item", result);
        assertArrayEquals(expected, Arrays.copyOf(result, written));
    }

    @Test
    void addOrUpdate_bytes_calledTwiceWithSameName_replacesPreviousValue() {
        ProtectedCache cache = createCache();

        cache.addOrUpdate("item", "first".getBytes(StandardCharsets.UTF_8));
        cache.addOrUpdate("item", "second-value".getBytes(StandardCharsets.UTF_8));

        OptionalInt maxLength = cache.tryGetMaxDecryptedLength("item");
        byte[] result = new byte[maxLength.getAsInt()];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("second-value", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void addOrUpdate_chars_calledTwiceWithSameName_replacesPreviousValue() {
        ProtectedCache cache = createCache();

        cache.addOrUpdate("item", "first".toCharArray());
        cache.addOrUpdate("item", "second-value".toCharArray());

        char[] result = new char[32];
        int written = cache.decrypt("item", result);

        assertTrue(written > 0);
        assertEquals("second-value", new String(result, 0, written));
    }

    @Test
    void addOrUpdate_afterAdd_replacesPreviousValueWithoutThrowing() {
        ProtectedCache cache = createCache();

        cache.add("item", "first".getBytes(StandardCharsets.UTF_8));
        assertDoesNotThrow(() -> cache.addOrUpdate("item", "second".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void namesAreCaseInsensitive_acrossAddAndDecrypt() {
        ProtectedCache cache = createCache();
        byte[] plaintext = "value".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();

        cache.add("Item-Name", plaintext);

        byte[] result = new byte[expected.length];
        int written = cache.decrypt("ITEM-name", result);

        assertTrue(written > 0);
        assertArrayEquals(expected, Arrays.copyOf(result, written));
    }

    @Test
    void namesAreCaseInsensitive_acrossAddOrUpdate() {
        ProtectedCache cache = createCache();

        cache.addOrUpdate("Item-Name", "first".getBytes(StandardCharsets.UTF_8));
        cache.addOrUpdate("ITEM-name", "second".getBytes(StandardCharsets.UTF_8));

        OptionalInt maxLength = cache.tryGetMaxDecryptedLength("item-name");
        byte[] result = new byte[maxLength.getAsInt()];
        int written = cache.decrypt("item-name", result);

        assertEquals("second", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decrypt_bytes_withUnknownName_returnsZero() {
        ProtectedCache cache = createCache();

        int written = cache.decrypt("missing", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decrypt_chars_withUnknownName_returnsZero() {
        ProtectedCache cache = createCache();

        int written = cache.decrypt("missing", new char[16]);

        assertEquals(0, written);
    }

    @Test
    void tryGetMaxDecryptedLength_withUnknownName_returnsEmpty() {
        ProtectedCache cache = createCache();

        assertFalse(cache.tryGetMaxDecryptedLength("missing").isPresent());
    }

    @Test
    void tryGetMaxDecryptedLength_isSafeUpperBoundForDecrypt() {
        ProtectedCache cache = createCache();
        byte[] plaintext = "some plaintext value".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();

        cache.add("item", plaintext);

        OptionalInt maxLength = cache.tryGetMaxDecryptedLength("item");
        assertTrue(maxLength.isPresent());

        byte[] result = new byte[maxLength.getAsInt()];
        int written = cache.decrypt("item", result);

        assertTrue(maxLength.getAsInt() >= written);
        assertArrayEquals(expected, Arrays.copyOf(result, written));
    }

    @Test
    void addDecrypt_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache cache = createCache();
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();

            cache.add("item", plaintext);
            byte[] result = new byte[expected.length];
            int written = cache.decrypt("item", result);

            assertTrue(written > 0);
            assertArrayEquals(expected, Arrays.copyOf(result, written));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void addOrUpdateDecrypt_chars_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache cache = createCache();
            String plaintext = "top secret chars";

            cache.addOrUpdate("item", plaintext.toCharArray());
            char[] result = new char[plaintext.length()];
            int written = cache.decrypt("item", result);

            assertTrue(written > 0);
            assertEquals(plaintext, new String(result, 0, written));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void add_chars_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache cache = createCache();
            String plaintext = "top secret chars";

            cache.add("item", plaintext.toCharArray());
            char[] result = new char[plaintext.length()];
            int written = cache.decrypt("item", result);

            assertTrue(written > 0);
            assertEquals(plaintext, new String(result, 0, written));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void addOrUpdate_bytes_withSensitiveLoggingEnabled_stillRoundTrips() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            ProtectedCache cache = createCache();
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();

            cache.addOrUpdate("item", plaintext);
            byte[] result = new byte[expected.length];
            int written = cache.decrypt("item", result);

            assertTrue(written > 0);
            assertArrayEquals(expected, Arrays.copyOf(result, written));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void decrypt_bytes_withTooSmallResultBuffer_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();
        cache.add("item", "top secret".getBytes(StandardCharsets.UTF_8));

        byte[] tooSmall = new byte[1];
        assertThrows(IllegalArgumentException.class, () -> cache.decrypt("item", tooSmall));
    }

    @Test
    void decrypt_chars_withTooSmallResultBuffer_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();
        cache.add("item", "top secret chars".toCharArray());

        char[] tooSmall = new char[1];
        assertThrows(BufferOverflowException.class, () -> cache.decrypt("item", tooSmall));
    }

    @Test
    void add_bytes_withNullName_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();

        assertThrows(NullPointerException.class, () -> cache.add(null, "value".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void add_chars_withNullName_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();

        assertThrows(NullPointerException.class, () -> cache.add(null, "value".toCharArray()));
    }

    @Test
    void addOrUpdate_bytes_withNullName_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();

        assertThrows(NullPointerException.class, () -> cache.addOrUpdate(null, "value".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void addOrUpdate_chars_withNullName_recordsExceptionAndThrows() {
        ProtectedCache cache = createCache();

        assertThrows(NullPointerException.class, () -> cache.addOrUpdate(null, "value".toCharArray()));
    }

    @Test
    void decrypt_bytes_withMissingName_andSensitiveLoggingEnabled_stillReturnsZero() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);
            ProtectedCache cache = createCache();

            int written = cache.decrypt("missing", new byte[16]);

            assertEquals(0, written);
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void concurrentAddAndDecrypt_acrossManyNames_allRoundTrip() {
        ProtectedCache cache = createCache();
        int itemCount = 200;

        IntStream.range(0, itemCount).parallel().forEach(i ->
                cache.add("item-" + i, ("value-" + i).getBytes(StandardCharsets.UTF_8)));

        IntStream.range(0, itemCount).parallel().forEach(i -> {
            OptionalInt maxLength = cache.tryGetMaxDecryptedLength("item-" + i);
            byte[] result = new byte[maxLength.getAsInt()];
            int written = cache.decrypt("item-" + i, result);
            assertTrue(written > 0);
            assertEquals("value-" + i, new String(result, 0, written, StandardCharsets.UTF_8));
        });
    }

    @Test
    void concurrentAdd_withSameName_exactlyOneSucceeds() {
        ProtectedCache cache = createCache();
        int attemptCount = 50;
        AtomicInteger succeeded = new AtomicInteger();

        IntStream.range(0, attemptCount).parallel().forEach(i -> {
            try {
                cache.add("shared-name", ("value-" + i).getBytes(StandardCharsets.UTF_8));
                succeeded.incrementAndGet();
            } catch (IllegalArgumentException e) {
                // expected for every attempt but the winner
            }
        });

        assertEquals(1, succeeded.get());
    }

    @Test
    void add_withNullLogger_stillWorks() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        IDataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKey(
                new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        ProtectedCache cache = new ProtectedCache(dataProtectionKey, null);

        assertDoesNotThrow(() -> cache.add("item", "value".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void add_withLoggerAndSensitiveLoggingEnabled_logsSensitiveOperation() {
        boolean original = HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(true);

            byte[] key = new byte[32];
            RANDOM.nextBytes(key);
            FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
            IDataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKey(
                    new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
            ProtectedCache cache = new ProtectedCache(dataProtectionKey, logger);

            cache.add("item", "value".getBytes(StandardCharsets.UTF_8));

            verify(logger).debug(any(String.class), debugArgCaptor.capture(), debugArgCaptor.capture());
            List<Object> args = debugArgCaptor.getAllValues();
            assertEquals(ActivityNames.Cache.ADD, args.get(0));
            assertEquals("item", args.get(1));
        } finally {
            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void add_withLoggerWhenDuplicateNameThrows_logsOperationFailed() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        FakeKeyWrapper wrapper = new FakeKeyWrapper(key);
        IDataProtectionKey dataProtectionKey = new KeyWrappedDataEncryptionKey(
                new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
        ProtectedCache cache = new ProtectedCache(dataProtectionKey, logger);
        cache.add("item", "first".getBytes(StandardCharsets.UTF_8));

        assertThrows(IllegalArgumentException.class, () -> cache.add("item", "second".getBytes(StandardCharsets.UTF_8)));

        ArgumentCaptor<Throwable> exceptionCaptor = ArgumentCaptor.forClass(Throwable.class);
        verify(logger).error(any(String.class), any(String.class), exceptionCaptor.capture());
        assertTrue(exceptionCaptor.getValue() instanceof IllegalArgumentException);
    }

    @Nested
    class MetricsTest {

        private InMemoryMetricReader metricReader;

        @BeforeEach
        void setUp() {
            GlobalOpenTelemetry.resetForTest();
            metricReader = InMemoryMetricReader.create();
            OpenTelemetrySdk.builder()
                    .setMeterProvider(SdkMeterProvider.builder()
                            .registerMetricReader(metricReader)
                            .build())
                    .buildAndRegisterGlobal();
        }

        @AfterEach
        void tearDown() {
            GlobalOpenTelemetry.resetForTest();
        }

        @Test
        void add_incrementsCacheOperationsCounter_onSuccessAndFailure() {
            ProtectedCache cache = createCache();
            cache.add("item", "value".getBytes(StandardCharsets.UTF_8));
            assertThrows(IllegalArgumentException.class, () -> cache.add("item", "value".getBytes(StandardCharsets.UTF_8)));

            List<MetricData> metrics = metricReader.collectAllMetrics().stream()
                    .filter(m -> m.getName().equals(MetricNames.Cache.OPERATIONS))
                    .toList();
            assertFalse(metrics.isEmpty());

            List<LongPointData> points = metrics.get(0).getLongSumData().getPoints().stream().toList();

            assertTrue(points.stream().anyMatch(p -> p.getValue() == 1
                    && ActivityNames.Cache.ADD.equals(p.getAttributes().get(AttributeKey.stringKey(AttributeNames.OPERATION_NAME)))
                    && "success".equals(p.getAttributes().get(AttributeKey.stringKey(AttributeNames.RESULT)))));

            assertTrue(points.stream().anyMatch(p -> p.getValue() == 1
                    && ActivityNames.Cache.ADD.equals(p.getAttributes().get(AttributeKey.stringKey(AttributeNames.OPERATION_NAME)))
                    && "error".equals(p.getAttributes().get(AttributeKey.stringKey(AttributeNames.RESULT)))));
        }
    }
}
