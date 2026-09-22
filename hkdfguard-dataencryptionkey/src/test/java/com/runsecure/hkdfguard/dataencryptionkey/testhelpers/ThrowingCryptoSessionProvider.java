package com.runsecure.hkdfguard.dataencryptionkey.testhelpers;

import com.runsecure.hkdfguard.abstractions.ICryptoSession;
import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;

/**
 * An ICryptoSessionProvider whose getSession always throws - isolates
 * KeyWrappedDataEncryptionKey's own catch/recordException/rethrow behavior from any particular
 * ICryptoSessionProvider implementation's failure timing (e.g. AesGcmCryptoSessionProvider fails
 * at construction rather than at getSession, since it builds its first session eagerly).
 */
public final class ThrowingCryptoSessionProvider implements ICryptoSessionProvider {

    private final RuntimeException exception;

    public ThrowingCryptoSessionProvider(RuntimeException exception) {
        this.exception = exception;
    }

    @Override
    public ICryptoSession getSession() {
        throw exception;
    }

    @Override
    public void close() {
    }
}
