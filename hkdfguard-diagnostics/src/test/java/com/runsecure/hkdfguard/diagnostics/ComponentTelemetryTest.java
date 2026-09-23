package com.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class ComponentTelemetryTest {

    private InMemorySpanExporter spanExporter;
    private OpenTelemetrySdk openTelemetrySdk;

    static Stream<ComponentTelemetry> allComponents() {
        return Stream.of(
                HkdfGuardTelemetry.ROOT,
                HkdfGuardTelemetry.CACHE,
                HkdfGuardTelemetry.DATA_PROTECTION,
                HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION,
                HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256,
                HkdfGuardTelemetry.KEY_WRAPPING);
    }

    @BeforeEach
    void setUp() {
        GlobalOpenTelemetry.resetForTest();
        spanExporter = InMemorySpanExporter.create();
        openTelemetrySdk = OpenTelemetrySdk.builder()
                .setTracerProvider(SdkTracerProvider.builder()
                        .addSpanProcessor(SimpleSpanProcessor.create(spanExporter))
                        .build())
                .buildAndRegisterGlobal();
    }

    @AfterEach
    void tearDown() {
        if (openTelemetrySdk != null) {
            openTelemetrySdk.close();
        }
        GlobalOpenTelemetry.resetForTest();
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void tracerAndMeter_sourceNameIsStable(ComponentTelemetry component) {
        assertNotNull(component.getSourceName());
        assertFalse(component.getSourceName().isEmpty());
        assertDoesNotThrow(component::getTracer);
        assertDoesNotThrow(component::getMeter);
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void recordException_withNullSpan_doesNotThrow(ComponentTelemetry component) {
        assertDoesNotThrow(() -> component.recordException(null, new IllegalStateException("boom")));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void recordException_withRealSpan_recordsExceptionAndErrorStatus(ComponentTelemetry component) {
        Span span = component.getTracer().spanBuilder("test-span").startSpan();
        Exception exception = new IllegalStateException("boom");

        component.recordException(span, exception);
        span.end();

        SpanData spanData = singleFinishedSpan();
        assertEquals(StatusCode.ERROR, spanData.getStatus().getStatusCode());
        assertTrue(spanData.getEvents().stream().anyMatch(e -> e.getName().equals("exception")));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_withNullSpan_doesNotThrow(ComponentTelemetry component) {
        assertDoesNotThrow(() -> component.logSensitiveOperation(null, "test-op"));
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_whenDisabled_doesNotAddEvent(ComponentTelemetry component) {
        boolean original = component.isEnableSensitiveLogging();
        try {
            component.setEnableSensitiveLogging(false);

            Span span = component.getTracer().spanBuilder("test-span").startSpan();
            component.logSensitiveOperation(span, "test-op", ComponentTelemetry.Detail.of("key", "value"));
            span.end();

            SpanData spanData = singleFinishedSpan();
            assertTrue(spanData.getEvents().isEmpty());
        } finally {
            component.setEnableSensitiveLogging(original);
        }
    }

    @ParameterizedTest
    @MethodSource("allComponents")
    void logSensitiveOperation_whenEnabled_addsFixedNameEventWithOperationAndDetailTags(ComponentTelemetry component) {
        boolean original = component.isEnableSensitiveLogging();
        try {
            component.setEnableSensitiveLogging(true);

            Span span = component.getTracer().spanBuilder("test-span").startSpan();
            component.logSensitiveOperation(span, "test-op", ComponentTelemetry.Detail.of(AttributeNames.NAME, "item"));
            span.end();

            SpanData spanData = singleFinishedSpan();
            List<EventData> events = spanData.getEvents();
            assertEquals(1, events.size());

            EventData loggedEvent = events.get(0);
            assertEquals(EventNames.SENSITIVE_OPERATION, loggedEvent.getName());
            assertEquals("test-op", loggedEvent.getAttributes().get(io.opentelemetry.api.common.AttributeKey.stringKey(AttributeNames.OPERATION_NAME)));
            assertEquals("item", loggedEvent.getAttributes().get(io.opentelemetry.api.common.AttributeKey.stringKey(AttributeNames.NAME)));
        } finally {
            component.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void enableSensitiveLogging_rootSharesFlagWithCacheDataProtectionAndEncryptedConfiguration() {
        boolean original = HkdfGuardTelemetry.ROOT.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.ROOT.setEnableSensitiveLogging(true);
            assertTrue(HkdfGuardTelemetry.CACHE.isEnableSensitiveLogging());
            assertTrue(HkdfGuardTelemetry.DATA_PROTECTION.isEnableSensitiveLogging());
            assertTrue(HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.isEnableSensitiveLogging());

            HkdfGuardTelemetry.CACHE.setEnableSensitiveLogging(false);
            assertFalse(HkdfGuardTelemetry.ROOT.isEnableSensitiveLogging());
            assertFalse(HkdfGuardTelemetry.DATA_PROTECTION.isEnableSensitiveLogging());
            assertFalse(HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION.isEnableSensitiveLogging());
        } finally {
            HkdfGuardTelemetry.ROOT.setEnableSensitiveLogging(original);
        }
    }

    @Test
    void enableSensitiveLogging_cryptoSessionAndKeyWrapping_areIndependentFromRootAndEachOther() {
        boolean originalRoot = HkdfGuardTelemetry.ROOT.isEnableSensitiveLogging();
        boolean originalCryptoSession = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.isEnableSensitiveLogging();
        boolean originalKeyWrapping = HkdfGuardTelemetry.KEY_WRAPPING.isEnableSensitiveLogging();
        try {
            HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.setEnableSensitiveLogging(false);
            HkdfGuardTelemetry.KEY_WRAPPING.setEnableSensitiveLogging(false);

            HkdfGuardTelemetry.ROOT.setEnableSensitiveLogging(true);
            assertFalse(HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.isEnableSensitiveLogging());
            assertFalse(HkdfGuardTelemetry.KEY_WRAPPING.isEnableSensitiveLogging());

            HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.setEnableSensitiveLogging(true);
            assertFalse(HkdfGuardTelemetry.KEY_WRAPPING.isEnableSensitiveLogging());
        } finally {
            HkdfGuardTelemetry.ROOT.setEnableSensitiveLogging(originalRoot);
            HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256.setEnableSensitiveLogging(originalCryptoSession);
            HkdfGuardTelemetry.KEY_WRAPPING.setEnableSensitiveLogging(originalKeyWrapping);
        }
    }

    private SpanData singleFinishedSpan() {
        List<SpanData> spans = spanExporter.getFinishedSpanItems();
        assertEquals(1, spans.size());
        return spans.get(0);
    }
}
