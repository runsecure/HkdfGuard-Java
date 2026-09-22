package com.runsecure.hkdfguard.keywrapping.v1;

/**
 * Thrown when a call into the native HkdfGuard KMS library returns a non-OK status. Unchecked,
 * matching the C# original's use of the unchecked {@code CryptographicException}.
 */
public class NativeKmsException extends RuntimeException {

    public NativeKmsException(String message) {
        super(message);
    }
}
