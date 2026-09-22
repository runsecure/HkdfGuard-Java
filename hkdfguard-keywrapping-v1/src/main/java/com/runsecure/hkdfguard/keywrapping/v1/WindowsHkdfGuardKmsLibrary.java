package com.runsecure.hkdfguard.keywrapping.v1;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

/**
 * Binds HkdfGuard.Kms.Windows.v1.dll (see hkdfguard.h), which holds the per-service KEK as a
 * persistent, machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto
 * Provider (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
 */
final class WindowsHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {

    private static final String LIBRARY_NAME = "HkdfGuard.Kms.Windows.v1";

    static final int ERR_INVALID_ARG = -1;
    static final int ERR_BUFFER_TOO_SMALL = -2;
    static final int ERR_PROVIDER = -3;
    static final int ERR_CRYPTO = -4;
    static final int ERR_AUTH_FAILED = -5;
    static final int ERR_MALFORMED = -6;
    static final int ERR_INTERNAL = -7;

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
