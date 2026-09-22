package com.runsecure.hkdfguard.cache.testhelpers;

import com.runsecure.hkdfguard.abstractions.IProtectedReadOnlyCache;

import java.util.OptionalInt;

/**
 * An IProtectedReadOnlyCache whose every member throws - exercises ProtectedCacheCollection's
 * catch blocks without depending on a specific real failure mode.
 */
public final class ThrowingReadOnlyCache implements IProtectedReadOnlyCache {

    private final RuntimeException exception;

    public ThrowingReadOnlyCache(RuntimeException exception) {
        this.exception = exception;
    }

    @Override
    public int decrypt(String name, byte[] result) {
        throw exception;
    }

    @Override
    public int decrypt(String name, char[] result) {
        throw exception;
    }

    @Override
    public OptionalInt tryGetMaxDecryptedLength(String name) {
        throw exception;
    }
}
