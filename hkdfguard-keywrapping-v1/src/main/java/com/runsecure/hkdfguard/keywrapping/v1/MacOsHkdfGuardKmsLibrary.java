package com.runsecure.hkdfguard.keywrapping.v1;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

/**
 * Binds HkdfGuard.Kms.MacOS.v1.dylib (see HkdfGuardKeyProtectionEnclave.h), which holds the
 * per-service KEK as a Secure Enclave key. Each distinct service string gets its own,
 * independent Secure Enclave key - wrapping under one service's identifier and unwrapping under
 * a different one fails by design ({@link #ERR_DECRYPTION_FAILED}).
 */
final class MacOsHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {

    private static final String LIBRARY_NAME = "HkdfGuard.Kms.MacOS.v1";

    static final int ERR_INVALID_INPUT_LENGTH = -1;
    static final int ERR_OUTPUT_BUFFER_TOO_SMALL = -2;
    static final int ERR_KEY_UNAVAILABLE = -3;
    static final int ERR_PUBLIC_KEY_UNAVAILABLE = -4;
    static final int ERR_ENCRYPTION_FAILED = -5;
    static final int ERR_DECRYPTION_FAILED = -6;
    static final int ERR_UNEXPECTED_OUTPUT_LENGTH = -7;
    static final int ERR_MISSING_SERVICE_IDENTIFIER = -8;

    private interface NativeApi extends Library {
        int hkdfguard_wrap_dek(byte[] service, byte[] dek, int dekLen, byte[] output, IntByReference outLen);

        int hkdfguard_unwrap_dek(byte[] service, byte[] wrapped, int wrappedLen, byte[] output, IntByReference outLen);

        int hkdfguard_generate_and_wrap_dek(byte[] service, byte[] output, IntByReference outLen);
    }

    private final NativeApi api = Native.load(LIBRARY_NAME, NativeApi.class);

    @Override
    NativeCallResult wrapDek(String service, byte[] dek, byte[] destination) {
        IntByReference outLen = new IntByReference(destination.length);
        int status = api.hkdfguard_wrap_dek(utf8NullTerminated(service), dek, dek.length, destination, outLen);
        return new NativeCallResult(status, outLen.getValue());
    }

    @Override
    NativeCallResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
        IntByReference outLen = new IntByReference(destination.length);
        int status = api.hkdfguard_unwrap_dek(utf8NullTerminated(service), wrapped, wrapped.length, destination, outLen);
        return new NativeCallResult(status, outLen.getValue());
    }

    @Override
    NativeCallResult generateAndWrapDek(String service, byte[] destination) {
        IntByReference outLen = new IntByReference(destination.length);
        int status = api.hkdfguard_generate_and_wrap_dek(utf8NullTerminated(service), destination, outLen);
        return new NativeCallResult(status, outLen.getValue());
    }
}
