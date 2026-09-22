package com.runsecure.hkdfguard.diagnostics;

import org.slf4j.Logger;

/**
 * Shared SLF4J logging helpers, used by every component that chooses to accept an optional
 * Logger (e.g. ProtectedCache's constructor). Mirrors logSensitiveOperation/recordException's
 * gating: sensitiveOperationLogged is only worth calling when
 * {@link ComponentTelemetry#isEnableSensitiveLogging()} is set, while operationFailed is
 * unconditional - failures are always worth logging.
 */
public final class HkdfGuardLoggerExtensions {

    private HkdfGuardLoggerExtensions() {
    }

    public static void sensitiveOperationLogged(Logger logger, String operationName, String name) {
        logger.debug("{} completed for {}.", operationName, name);
    }

    public static void operationFailed(Logger logger, String operationName, Throwable exception) {
        logger.error("{} failed.", operationName, exception);
    }
}
