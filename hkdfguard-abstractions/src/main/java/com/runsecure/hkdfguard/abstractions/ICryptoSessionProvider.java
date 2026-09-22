package com.runsecure.hkdfguard.abstractions;

/**
 * Tracks a single cached ICryptoSession, refreshing it (from a fresh key reveal/unwrap) once it
 * expires, and closing the outgoing session as it does. Callers should call getSession on every
 * operation rather than caching the returned ICryptoSession themselves, so they always see a
 * non-expired one.
 */
public interface ICryptoSessionProvider extends AutoCloseable {

    /**
     * Returns the current, non-expired ICryptoSession, refreshing it first if the previously
     * cached one has expired (or none has been created yet).
     */
    ICryptoSession getSession();

    @Override
    void close();
}
