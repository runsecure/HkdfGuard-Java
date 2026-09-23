package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import com.runsecure.hkdfguard.abstractions.ProtectedCache;
import com.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.CacheMetrics;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardLoggerExtensions;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;
import org.slf4j.Logger;

/**
 * Default ProtectedCache. Backed by a single, already-built DataEncryptionKey - every
 * add/addOrUpdate encrypts through it (see ProtectedCacheBase), every decrypt reveals through it.
 * add uses putIfAbsent as its atomicity gate so a duplicate name is rejected even under
 * concurrent callers; addOrUpdate's upsert and decrypt's reads are otherwise lock-free, so this
 * holds up under highly concurrent access in every direction. Nothing here ever holds plaintext
 * beyond the duration of a single add/addOrUpdate/decrypt call.
 *
 * <p>The pattern class for HkdfGuard.Diagnostics's metrics/logging extension points: logger is
 * optional (defaults to null via the single-arg constructor) and, when supplied, receives a
 * debug log per sensitive operation and an error log per failure alongside the existing
 * span/CacheMetrics telemetry.
 */
public final class ProtectedCacheImpl extends ProtectedCacheBase implements ProtectedCache {

    private final Logger logger;

    public ProtectedCacheImpl(DataEncryptionKey dataEncryptionKey) {
        this(dataEncryptionKey, null);
    }

    public ProtectedCacheImpl(DataEncryptionKey dataEncryptionKey, Logger logger) {
        super(dataEncryptionKey);
        this.logger = logger;
    }

    @Override
    public void add(String name, byte[] plaintext) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.ADD).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.ADD,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                    ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length));
            if (logger != null) {
                HkdfGuardLoggerExtensions.sensitiveOperationLogged(logger, ActivityNames.Cache.ADD, name);
            }
        }

        try {
            if (cache.putIfAbsent(name, encrypt(plaintext)) != null) {
                throw new IllegalArgumentException("An item with the name '" + name + "' has already been added.");
            }

            recordOperation(ActivityNames.Cache.ADD, true);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            if (logger != null) {
                HkdfGuardLoggerExtensions.operationFailed(logger, ActivityNames.Cache.ADD, ex);
            }
            recordOperation(ActivityNames.Cache.ADD, false);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public void add(String name, char[] plaintext) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.ADD).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.ADD,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                    ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length));
            if (logger != null) {
                HkdfGuardLoggerExtensions.sensitiveOperationLogged(logger, ActivityNames.Cache.ADD, name);
            }
        }

        try {
            if (cache.putIfAbsent(name, encryptChars(plaintext)) != null) {
                throw new IllegalArgumentException("An item with the name '" + name + "' has already been added.");
            }

            recordOperation(ActivityNames.Cache.ADD, true);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            if (logger != null) {
                HkdfGuardLoggerExtensions.operationFailed(logger, ActivityNames.Cache.ADD, ex);
            }
            recordOperation(ActivityNames.Cache.ADD, false);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public void addOrUpdate(String name, byte[] plaintext) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.ADD_OR_UPDATE).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.ADD_OR_UPDATE,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                    ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length));
            if (logger != null) {
                HkdfGuardLoggerExtensions.sensitiveOperationLogged(logger, ActivityNames.Cache.ADD_OR_UPDATE, name);
            }
        }

        try {
            cache.put(name, encrypt(plaintext));
            recordOperation(ActivityNames.Cache.ADD_OR_UPDATE, true);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            if (logger != null) {
                HkdfGuardLoggerExtensions.operationFailed(logger, ActivityNames.Cache.ADD_OR_UPDATE, ex);
            }
            recordOperation(ActivityNames.Cache.ADD_OR_UPDATE, false);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public void addOrUpdate(String name, char[] plaintext) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.ADD_OR_UPDATE).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.ADD_OR_UPDATE,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                    ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length));
            if (logger != null) {
                HkdfGuardLoggerExtensions.sensitiveOperationLogged(logger, ActivityNames.Cache.ADD_OR_UPDATE, name);
            }
        }

        try {
            cache.put(name, encryptChars(plaintext));
            recordOperation(ActivityNames.Cache.ADD_OR_UPDATE, true);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            if (logger != null) {
                HkdfGuardLoggerExtensions.operationFailed(logger, ActivityNames.Cache.ADD_OR_UPDATE, ex);
            }
            recordOperation(ActivityNames.Cache.ADD_OR_UPDATE, false);
            throw ex;
        } finally {
            span.end();
        }
    }

    private static void recordOperation(String operationName, boolean success) {
        CacheMetrics.recordOperation(operationName, success);
    }
}
