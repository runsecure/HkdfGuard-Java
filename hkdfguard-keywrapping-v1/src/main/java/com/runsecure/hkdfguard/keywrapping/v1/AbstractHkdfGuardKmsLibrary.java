package com.runsecure.hkdfguard.keywrapping.v1;

import java.nio.charset.StandardCharsets;

/**
 * Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
 * unwraps a fixed-length DEK under a persistent, per-service KEK held outside the JVM process (a
 * TPM2 key, a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek /
 * hkdfguard_unwrap_dek / hkdfguard_generate_and_wrap_dek native functions - identical in shape
 * across platforms, but each library's negative status codes mean different things, so callers
 * must consult the concrete implementation they're using to interpret a non-{@link #OK} result.
 */
abstract class AbstractHkdfGuardKmsLibrary {

    static final int DEK_LENGTH = 32;

    /** Status code common to every platform's native library: the call succeeded. */
    static final int OK = 0;

    /**
     * Wraps dek under the persistent KEK identified by service.
     *
     * @param service Non-empty, cross-platform identity of the KEK.
     * @param dek The plaintext DEK to wrap (must be exactly {@link #DEK_LENGTH} bytes).
     * @param destination Buffer to receive the wrapped payload.
     * @return The native call's status ({@link #OK} on success, otherwise a negative,
     *     implementation-specific error code) and the number of bytes written to destination -
     *     or, on a buffer-too-small failure, the required capacity instead.
     */
    abstract NativeCallResult wrapDek(String service, byte[] dek, byte[] destination);

    /**
     * Unwraps a payload previously produced by {@link #wrapDek} for the same service, recovering
     * the original DEK.
     *
     * @param service Must match the value used when the payload was wrapped.
     * @param wrapped The wrapped payload bytes.
     * @param destination Buffer to receive the recovered DEK.
     * @return The native call's status ({@link #OK} on success, otherwise a negative,
     *     implementation-specific error code) and, on success, always {@link #DEK_LENGTH} bytes
     *     written - or, on a buffer-too-small failure, the required capacity instead.
     */
    abstract NativeCallResult unwrapDek(String service, byte[] wrapped, byte[] destination);

    /**
     * Generates a fresh, cryptographically random DEK and immediately wraps it under the
     * persistent KEK identified by service. The plaintext DEK never crosses this boundary -
     * recover it later via {@link #unwrapDek} with the same service.
     *
     * @param destination Buffer to receive the wrapped payload.
     * @return The native call's status ({@link #OK} on success, otherwise a negative,
     *     implementation-specific error code) and the number of bytes written to destination -
     *     or, on a buffer-too-small failure, the required capacity instead.
     */
    abstract NativeCallResult generateAndWrapDek(String service, byte[] destination);

    /**
     * Encodes value as a null-terminated UTF-8 byte array, matching the C# original's
     * {@code StringMarshalling.Utf8} - JNA's own implicit String marshalling instead defaults to
     * the platform charset, which isn't guaranteed to be UTF-8 on every platform.
     */
    static byte[] utf8NullTerminated(String value) {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        byte[] terminated = new byte[utf8.length + 1];
        System.arraycopy(utf8, 0, terminated, 0, utf8.length);
        return terminated;
    }

    record NativeCallResult(int status, int bytesWritten) {
    }
}
