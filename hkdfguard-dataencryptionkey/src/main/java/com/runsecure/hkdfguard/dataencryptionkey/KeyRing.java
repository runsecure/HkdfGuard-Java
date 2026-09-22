package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.abstractions.IDataProtector;
import com.runsecure.hkdfguard.abstractions.IEncryptedFormatProvider;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;

/**
 * Tracks IDataProtectionKey instances by version for highly concurrent workloads (thousands of
 * operations per second). get is served straight off a ConcurrentHashMap, so the hot read path
 * never blocks - no telemetry on that path either, only on a get miss, since that's the
 * exceptional case and startup overhead there is irrelevant. add is serialized through a
 * Semaphore - key registration only happens at startup/rotation, not per-operation, so the gate
 * (and its telemetry) costs nothing where it matters.
 *
 * <p>The ring tracks its own current version intrinsically: whichever registered version number
 * is highest becomes getCurrentVersion, automatically, the moment it's added - there is no
 * separate call to designate one, so it can never fall out of sync with what's actually
 * registered.
 */
public final class KeyRing {

    private static final int NO_CURRENT_VERSION = Integer.MIN_VALUE;

    private final IEncryptedFormatProvider formatProvider;
    private final ConcurrentMap<Integer, IDataProtectionKey> keysByVersion = new ConcurrentHashMap<>();
    private final Semaphore addGate = new Semaphore(1);

    private volatile int currentVersion = NO_CURRENT_VERSION;

    public KeyRing(IEncryptedFormatProvider formatProvider) {
        this.formatProvider = formatProvider;
    }

    /**
     * The highest version registered so far - what encrypt-side operations (e.g.
     * DataProtector.encrypt) protect new data with.
     *
     * @throws IllegalStateException No key has been added yet
     */
    public int getCurrentVersion() {
        int current = currentVersion;
        if (current == NO_CURRENT_VERSION) {
            throw new IllegalStateException("No current version has been set. Add a key first.");
        }
        return current;
    }

    /**
     * Registers a key for the given version. If version is higher than every version registered
     * so far, it intrinsically becomes the new current version.
     *
     * @param version The key version to register
     * @param key The IDataProtectionKey for this version
     * @throws IllegalArgumentException A key for this version is already registered
     */
    public void add(int version, IDataProtectionKey key) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.KEY_RING_ADD).startSpan();

        addGate.acquireUninterruptibly();
        try {
            if (keysByVersion.putIfAbsent(version, key) != null) {
                throw new IllegalArgumentException("A key for version " + version + " is already registered.");
            }

            boolean becameCurrent = currentVersion == NO_CURRENT_VERSION || version > currentVersion;
            if (becameCurrent) {
                currentVersion = version;
            }

            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.KEY_RING_ADD,
                        ComponentTelemetry.Detail.of(AttributeNames.KEY_VERSION, version),
                        ComponentTelemetry.Detail.of(AttributeNames.KEY_RING_BECAME_CURRENT, becameCurrent));
            }
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            addGate.release();
            span.end();
        }
    }

    /**
     * Retrieves the key registered for the given version.
     *
     * @param version The key version to retrieve
     * @return The registered IDataProtectionKey
     * @throws NoSuchElementException No key is registered for this version
     */
    public IDataProtectionKey get(int version) {
        IDataProtectionKey key = keysByVersion.get(version);
        if (key != null) {
            return key;
        }

        NoSuchElementException notFound = new NoSuchElementException("No key is registered for version " + version + ".");
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.KEY_RING_GET).startSpan();
        telemetry.recordException(span, notFound);
        span.end();
        throw notFound;
    }

    /**
     * Attempts to retrieve the key registered for the given version without throwing - for the
     * high-frequency hot path, where exception overhead (and telemetry) on a routine miss is
     * unacceptable.
     *
     * @param version The key version to retrieve
     * @return The registered IDataProtectionKey, or empty if none is registered for this version
     */
    public Optional<IDataProtectionKey> tryGet(int version) {
        return Optional.ofNullable(keysByVersion.get(version));
    }

    /**
     * Retrieves the current version together with its IDataProtectionKey atomically - what
     * encrypt-side operations (e.g. DataProtector.encrypt) resolve fresh on every call, so they
     * always reflect the latest rotation rather than a version captured once at construction.
     *
     * @throws IllegalStateException No key has been added yet
     */
    public CurrentKey getCurrent() {
        try {
            int version = getCurrentVersion();
            return new CurrentKey(version, get(version));
        } catch (IllegalStateException ex) {
            ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
            Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.KEY_RING_GET_CURRENT).startSpan();
            telemetry.recordException(span, ex);
            span.end();
            throw ex;
        }
    }

    /**
     * Creates an IDataProtector bound to this KeyRing - the only way to obtain one, since
     * DataProtector's constructor is package-private to this module. encrypt resolves the current
     * version fresh via getCurrent on every call (not a version captured once here), and
     * formats/parses via the IEncryptedFormatProvider this ring was constructed with.
     *
     * @param name Used as this protector's Additional Auth Data on every encrypt/decrypt
     */
    public IDataProtector createProtector(String name) {
        return new DataProtector(name, this, formatProvider);
    }

    public record CurrentKey(int version, IDataProtectionKey key) {
    }
}
