package com.runsecure.hkdfguard.dataencryptionkey.testhelpers;

import com.runsecure.hkdfguard.abstractions.IEncryptedFormatProvider;
import com.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import com.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProvider;

/**
 * A real DefaultFormatProvider wrapped with call tracking, so a test can prove a component (e.g.
 * KeyRing/KeyRingBuilder) actually uses the specific IEncryptedFormatProvider instance it was
 * given, rather than some other one.
 */
public final class RecordingFormatProvider implements IEncryptedFormatProvider {

    private final DefaultFormatProvider inner = new DefaultFormatProvider();

    private boolean formatCalled;
    private boolean parseCalled;

    public boolean isFormatCalled() {
        return formatCalled;
    }

    public boolean isParseCalled() {
        return parseCalled;
    }

    @Override
    public String format(KeyTrackingValue value) {
        formatCalled = true;
        return inner.format(value);
    }

    @Override
    public KeyTrackingValue parse(char[] encrypted) {
        parseCalled = true;
        return inner.parse(encrypted);
    }

    @Override
    public int getMaxDecryptedLength(char[] encrypted) {
        return inner.getMaxDecryptedLength(encrypted);
    }
}
