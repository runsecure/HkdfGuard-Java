package com.runsecure.hkdfguard.diagnostics;

/**
 * Fixed span event names. Unlike the operation-specific {@link ActivityNames}, an event's own
 * name stays constant regardless of which operation raised it - the operation itself is carried
 * as the {@link AttributeNames#OPERATION_NAME} attribute instead - so event names stay
 * low-cardinality and stable for dashboards/queries.
 */
public final class EventNames {

    private EventNames() {
    }

    public static final String SENSITIVE_OPERATION = "hkdfguard.sensitive_operation";
}
