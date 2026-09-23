package com.runsecure.hkdfguard.cache;

import com.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;

/**
 * Aggregates multiple ProtectedReadOnlyCache sources into a single read-only surface. add
 * registers a source and returns this same instance for fluent chaining (e.g.
 * {@code new ProtectedCacheCollectionImpl().add(a).add(b)}). decrypt/tryGetMaxDecryptedLength check
 * each registered source in the order it was added, returning the first match. This never owns
 * or writes any encrypted values of its own - add here only registers a source, it never protects
 * or stores a value - so mutation of actual cached values stays entirely a concern of whichever
 * underlying source(s) actually support it (e.g. a writable ProtectedCacheImpl mixed in as one of the
 * sources).
 */
public final class ProtectedCacheCollectionImpl implements ProtectedReadOnlyCache {

    private final List<ProtectedReadOnlyCache> sources = new ArrayList<>();

    /**
     * Registers source as an additional lookup source, checked after every source already added.
     *
     * @return This same ProtectedCacheCollectionImpl, for fluent chaining
     */
    public ProtectedCacheCollectionImpl add(ProtectedReadOnlyCache source) {
        sources.add(source);
        return this;
    }

    @Override
    public int decrypt(String name, byte[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.DECRYPT).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.DECRYPT,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name));
        }

        try {
            for (ProtectedReadOnlyCache source : sources) {
                int written = source.decrypt(name, result);
                if (written > 0) {
                    return written;
                }
            }

            return 0;
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public int decrypt(String name, char[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CACHE;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.DECRYPT).startSpan();
        if (telemetry.isEnableSensitiveLogging()) {
            telemetry.logSensitiveOperation(span, ActivityNames.Cache.DECRYPT,
                    ComponentTelemetry.Detail.of(AttributeNames.NAME, name));
        }

        try {
            for (ProtectedReadOnlyCache source : sources) {
                int written = source.decrypt(name, result);
                if (written > 0) {
                    return written;
                }
            }

            return 0;
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public OptionalInt tryGetMaxDecryptedLength(String name) {
        for (ProtectedReadOnlyCache source : sources) {
            OptionalInt found = source.tryGetMaxDecryptedLength(name);
            if (found.isPresent()) {
                return found;
            }
        }

        return OptionalInt.empty();
    }
}
