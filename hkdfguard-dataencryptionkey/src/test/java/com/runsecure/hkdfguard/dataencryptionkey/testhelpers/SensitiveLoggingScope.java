package com.runsecure.hkdfguard.dataencryptionkey.testhelpers;

import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;

/**
 * Temporarily sets HkdfGuardTelemetry.DATA_PROTECTION.setEnableSensitiveLogging, restoring the
 * original value on close - so a test can exercise a production method's "if enabled, log" branch
 * without leaking that shared flag into other tests. Safe only because JUnit doesn't run this
 * module's tests in parallel by default - isEnableSensitiveLogging has no synchronization of its
 * own.
 */
public final class SensitiveLoggingScope implements AutoCloseable {

    private final boolean original;

    public SensitiveLoggingScope(boolean enabled) {
        this.original = HkdfGuardTelemetry.DATA_PROTECTION.isEnableSensitiveLogging();
        HkdfGuardTelemetry.DATA_PROTECTION.setEnableSensitiveLogging(enabled);
    }

    @Override
    public void close() {
        HkdfGuardTelemetry.DATA_PROTECTION.setEnableSensitiveLogging(original);
    }
}
