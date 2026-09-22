package com.runsecure.hkdfguard.diagnostics;

/**
 * Metric instrument names, following the same {@code hkdfguard.<component>.<noun>} convention as
 * {@link ActivityNames}.
 */
public final class MetricNames {

    private MetricNames() {
    }

    public static final class Cache {
        private Cache() {
        }

        public static final String OPERATIONS = "hkdfguard.cache.operations";
    }
}
