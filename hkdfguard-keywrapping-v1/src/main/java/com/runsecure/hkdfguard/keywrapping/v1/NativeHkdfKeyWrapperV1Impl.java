package com.runsecure.hkdfguard.keywrapping.v1;

import com.runsecure.hkdfguard.abstractions.KeyWrapper;

/**
 * Protects (encrypt) a fresh DEK, or reveals (decrypt) a previously-wrapped one, via the current
 * OS's native HkdfGuard KMS library (see NativeHost) - a TPM2, Secure Enclave, or Platform Crypto
 * Provider key held entirely outside this process, identified only by a service name. No
 * salt/blob machinery is involved: the native library owns the KEK, the wrapped payload's format,
 * and its own key derivation. Since decrypt takes its wrapped payload as an explicit argument
 * rather than one bound at construction, a single instance freely handles both directions, and
 * any number of different wrapped payloads sharing the same service name. The native ABI has no
 * concept of AAD, so the 3-arg overloads accept only an empty aad; anything else throws
 * UnsupportedOperationException.
 */
public final class NativeHkdfKeyWrapperV1Impl implements KeyWrapper {

    private static final byte[] EMPTY_AAD = new byte[0];

    private final String serviceName;
    private final AbstractHkdfGuardKmsLibrary library;

    public NativeHkdfKeyWrapperV1Impl(String serviceName) {
        this(serviceName, NativeHost.getLibrary());
    }

    NativeHkdfKeyWrapperV1Impl(String serviceName, AbstractHkdfGuardKmsLibrary library) {
        this.serviceName = serviceName;
        this.library = library;
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        return encrypt(plaintext, result, EMPTY_AAD);
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result, byte[] aad) {
        requireEmptyAad(aad);

        AbstractHkdfGuardKmsLibrary.NativeCallResult wrapResult = library.wrapDek(serviceName, plaintext, result);
        if (wrapResult.status() != AbstractHkdfGuardKmsLibrary.OK) {
            throw new NativeKmsException("Native KMS wrap failed with status " + wrapResult.status() + ".");
        }

        return wrapResult.bytesWritten();
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result) {
        return decrypt(wrapped, result, EMPTY_AAD);
    }

    @Override
    public int decrypt(byte[] wrapped, byte[] result, byte[] aad) {
        requireEmptyAad(aad);

        AbstractHkdfGuardKmsLibrary.NativeCallResult unwrapResult = library.unwrapDek(serviceName, wrapped, result);
        if (unwrapResult.status() != AbstractHkdfGuardKmsLibrary.OK) {
            throw new NativeKmsException("Native KMS unwrap failed with status " + unwrapResult.status() + ".");
        }

        return unwrapResult.bytesWritten();
    }

    @Override
    public int generateAndWrap(byte[] result) {
        AbstractHkdfGuardKmsLibrary.NativeCallResult wrapResult = library.generateAndWrapDek(serviceName, result);
        if (wrapResult.status() != AbstractHkdfGuardKmsLibrary.OK) {
            throw new NativeKmsException("Native KMS generate-and-wrap failed with status " + wrapResult.status() + ".");
        }

        return wrapResult.bytesWritten();
    }

    private static void requireEmptyAad(byte[] aad) {
        if (aad != null && aad.length > 0) {
            throw new UnsupportedOperationException(
                    "NativeHkdfKeyWrapperV1Impl's native KMS library has no concept of additional authenticated data.");
        }
    }
}
