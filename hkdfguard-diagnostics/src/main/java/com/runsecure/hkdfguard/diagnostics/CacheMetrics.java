package com.runsecure.hkdfguard.diagnostics;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;

/**
 * Cache component instrument, built fresh from {@code HkdfGuardTelemetry.CACHE.getMeter()} on
 * every call rather than cached in a static field - a {@link LongCounter} obtained from
 * {@link io.opentelemetry.api.GlobalOpenTelemetry} stays permanently bound to whichever
 * {@code OpenTelemetry} instance was live at the moment it was built, even across a later
 * {@code GlobalOpenTelemetry.resetForTest()} and reconfiguration, so a static-final instance
 * built too early (e.g. by an unrelated test touching this class first) would silently stop
 * reporting. Resolving it per call keeps it consistent with {@link ComponentTelemetry}'s own
 * getTracer/getMeter, and costs nothing that matters: instrument creation is cheap and interned
 * by the SDK.
 *
 * <p>recordOperation counts every ProtectedCacheImpl add/addOrUpdate call, tagged with
 * {@link AttributeNames#OPERATION_NAME} (which ActivityNames.Cache constant ran) and
 * {@link AttributeNames#RESULT} ("success" or "error").
 */
public final class CacheMetrics {

    private CacheMetrics() {
    }

    public static void recordOperation(String operationName, boolean success) {
        LongCounter operations = HkdfGuardTelemetry.CACHE
                .getMeter()
                .counterBuilder(MetricNames.Cache.OPERATIONS)
                .setUnit("{operation}")
                .setDescription("Number of ProtectedCacheImpl operations, tagged by operation and result.")
                .build();

        operations.add(1,
                Attributes.of(
                        AttributeKey.stringKey(AttributeNames.OPERATION_NAME), operationName,
                        AttributeKey.stringKey(AttributeNames.RESULT), success ? "success" : "error"));
    }
}
