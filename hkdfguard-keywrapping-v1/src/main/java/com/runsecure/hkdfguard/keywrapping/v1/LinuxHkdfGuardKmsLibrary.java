package com.runsecure.hkdfguard.keywrapping.v1;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

/**
 * Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
 * provider on the host - TPM2 &gt; PKCS#11 &gt; external secret &gt; software &gt; ephemeral - to hold the
 * per-service KEK. No Rust type, TPM handle, or OpenSSL structure ever crosses this boundary, and
 * no panic ever crosses it either: every native call below returns a plain status code.
 */
final class LinuxHkdfGuardKmsLibrary extends AbstractHkdfGuardKmsLibrary {

    private static final String LIBRARY_NAME = "HkdfGuardKeyProtectionLinux";

    static final int ERR_INVALID_ARGUMENT = -1;
    static final int ERR_BUFFER_TOO_SMALL = -2;
    static final int ERR_PROVIDER_UNAVAILABLE = -3;
    static final int ERR_PROVIDER_ERROR = -4;
    static final int ERR_CRYPTO_ERROR = -5;
    static final int ERR_INTERNAL_ERROR = -6;
    static final int ERR_INVALID_UTF8 = -7;
    static final int ERR_MISSING_SERVICE_NAME = -8;

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
