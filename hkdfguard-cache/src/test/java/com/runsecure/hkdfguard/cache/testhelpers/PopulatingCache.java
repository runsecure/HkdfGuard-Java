package com.runsecure.hkdfguard.cache.testhelpers;

import com.runsecure.hkdfguard.abstractions.IDataProtectionKey;
import com.runsecure.hkdfguard.abstractions.ProtectedCacheBase;

import java.util.function.Predicate;

/**
 * A minimal ProtectedCacheBase subclass whose tryPopulate is driven directly by the test - lets
 * tests exercise the base class's cache-miss-then-populate path without depending on any real
 * external source.
 */
public final class PopulatingCache extends ProtectedCacheBase {

    private int tryPopulateCallCount;
    private Predicate<String> onTryPopulate;

    public PopulatingCache(IDataProtectionKey dataProtectionKey) {
        super(dataProtectionKey);
    }

    public int getTryPopulateCallCount() {
        return tryPopulateCallCount;
    }

    public void setOnTryPopulate(Predicate<String> onTryPopulate) {
        this.onTryPopulate = onTryPopulate;
    }

    public void seed(String name, char[] plaintext) {
        cache.put(name, encryptChars(plaintext));
    }

    @Override
    protected boolean tryPopulate(String name) {
        tryPopulateCallCount++;
        return onTryPopulate != null && onTryPopulate.test(name);
    }
}
