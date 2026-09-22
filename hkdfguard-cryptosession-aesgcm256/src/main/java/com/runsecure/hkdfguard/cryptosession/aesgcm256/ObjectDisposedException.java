package com.runsecure.hkdfguard.cryptosession.aesgcm256;

/**
 * Thrown when an operation is attempted on an object that has already been closed. Unchecked,
 * matching the C# original's use of the unchecked {@code ObjectDisposedException}.
 */
public class ObjectDisposedException extends IllegalStateException {

    public ObjectDisposedException(String objectName) {
        super("Cannot access a disposed object. Object name: '" + objectName + "'.");
    }
}
