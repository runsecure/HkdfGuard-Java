package com.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;

import java.util.function.Consumer;

/**
 * One component's telemetry surface: a Tracer and Meter sharing that component's scope name, an
 * enableSensitiveLogging toggle, and the recordException/logSensitiveOperation helpers every
 * operation across the library calls through. The Tracer/Meter are resolved from
 * {@link GlobalOpenTelemetry} on every call rather than cached at construction, so tests (and
 * applications) that configure the global {@code OpenTelemetry} instance after this class's
 * static fields have already been initialized still observe it.
 */
public final class ComponentTelemetry {

    private final ComponentTelemetry sharedFlagOwner;
    private volatile boolean ownEnableSensitiveLogging;

    /** This component's Tracer/Meter scope name - e.g. "HkdfGuard.Cache". */
    private final String sourceName;

    /** @param sourceName This component's Tracer/Meter scope name. */
    ComponentTelemetry(String sourceName) {
        this(sourceName, null);
    }

    /**
     * @param sourceName This component's Tracer/Meter scope name.
     * @param sharedFlagOwner enableSensitiveLogging delegates to this component's own flag
     *     instead of keeping an independent one - e.g. Cache/DataProtection/EncryptedConfiguration
     *     all share Root's flag. May be {@code null} to keep an independent flag.
     */
    ComponentTelemetry(String sourceName, ComponentTelemetry sharedFlagOwner) {
        this.sourceName = sourceName;
        this.sharedFlagOwner = sharedFlagOwner;
    }

    public String getSourceName() {
        return sourceName;
    }

    public Tracer getTracer() {
        return GlobalOpenTelemetry.getTracer(sourceName);
    }

    public Meter getMeter() {
        return GlobalOpenTelemetry.getMeter(sourceName);
    }

    /**
     * When enabled, sensitive operations emit additional debug telemetry (operation metadata such
     * as buffer lengths and identifiers). Raw key, plaintext, and ciphertext bytes are never
     * logged, regardless of this setting. Components constructed with a sharedFlagOwner read and
     * write that owner's flag instead of keeping their own.
     */
    public boolean isEnableSensitiveLogging() {
        return sharedFlagOwner != null ? sharedFlagOwner.isEnableSensitiveLogging() : ownEnableSensitiveLogging;
    }

    public void setEnableSensitiveLogging(boolean value) {
        if (sharedFlagOwner != null) {
            sharedFlagOwner.setEnableSensitiveLogging(value);
        } else {
            ownEnableSensitiveLogging = value;
        }
    }

    /**
     * Records an exception on the current span and marks it as errored.
     */
    public void recordException(Span span, Throwable exception) {
        if (span == null) {
            return;
        }
        span.recordException(exception);
        span.setStatus(StatusCode.ERROR, exception.getMessage());
    }

    /**
     * Emits a fixed-name ({@link EventNames#SENSITIVE_OPERATION}) debug event when
     * {@link #isEnableSensitiveLogging()} is set, carrying operationName and every detail as
     * attributes. Only pass non-sensitive metadata (lengths, identifiers, timings) as details -
     * never raw key, plaintext, or ciphertext bytes.
     */
    public void logSensitiveOperation(Span span, String operationName, Detail... details) {
        if (!isEnableSensitiveLogging() || span == null) {
            return;
        }

        AttributesBuilder builder = Attributes.builder().put(AttributeNames.OPERATION_NAME, operationName);
        for (Detail detail : details) {
            detail.applyTo(builder);
        }

        span.addEvent(EventNames.SENSITIVE_OPERATION, builder.build());
    }

    /**
     * A single (key, value) detail attribute for {@link #logSensitiveOperation}, standing in for
     * the loosely-typed {@code (string Key, object? Value)} tuple the C# original accepts - Java
     * attribute values are statically typed, so a Detail is created via one of the typed factory
     * methods below.
     */
    public static final class Detail {
        private final Consumer<AttributesBuilder> apply;

        private Detail(Consumer<AttributesBuilder> apply) {
            this.apply = apply;
        }

        void applyTo(AttributesBuilder builder) {
            apply.accept(builder);
        }

        public static Detail of(String key, String value) {
            return new Detail(builder -> builder.put(key, value == null ? "" : value));
        }

        public static Detail of(String key, long value) {
            return new Detail(builder -> builder.put(key, value));
        }

        public static Detail of(String key, boolean value) {
            return new Detail(builder -> builder.put(key, value));
        }

        public static Detail of(String key, double value) {
            return new Detail(builder -> builder.put(key, value));
        }
    }
}
