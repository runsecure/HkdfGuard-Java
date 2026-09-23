package com.runsecure.hkdfguard.keywrapping.v1;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NativeHkdfKeyWrapperV1ImplTest {

    /**
     * A fake native library standing in for the real .so/.dylib/.dll, so these tests exercise
     * NativeHkdfKeyWrapperV1Impl's own logic (status-code handling) without a native dependency.
     */
    private static final class FakeLibrary extends AbstractHkdfGuardKmsLibrary {
        String lastService;
        byte[] lastInput;
        int statusToReturn = OK;
        byte[] outputToWrite;

        @Override
        NativeCallResult wrapDek(String service, byte[] dek, byte[] destination) {
            lastService = service;
            lastInput = dek;
            return respond(destination);
        }

        @Override
        NativeCallResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
            lastService = service;
            lastInput = wrapped;
            return respond(destination);
        }

        @Override
        NativeCallResult generateAndWrapDek(String service, byte[] destination) {
            lastService = service;
            lastInput = null;
            return respond(destination);
        }

        private NativeCallResult respond(byte[] destination) {
            if (statusToReturn != OK) {
                return new NativeCallResult(statusToReturn, 0);
            }
            System.arraycopy(outputToWrite, 0, destination, 0, outputToWrite.length);
            return new NativeCallResult(OK, outputToWrite.length);
        }
    }

    @Test
    void encrypt_delegatesToWrapDekAndReturnsBytesWritten() {
        FakeLibrary library = new FakeLibrary();
        library.outputToWrite = new byte[]{1, 2, 3, 4};
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("my-service", library);

        byte[] plaintext = new byte[32];
        byte[] result = new byte[16];
        int written = sut.encrypt(plaintext, result);

        assertEquals(4, written);
        assertArrayEquals(new byte[]{1, 2, 3, 4}, java.util.Arrays.copyOf(result, 4));
        assertEquals("my-service", library.lastService);
        assertEquals(plaintext, library.lastInput);
    }

    @Test
    void encrypt_withNonOkStatus_throwsNativeKmsException() {
        FakeLibrary library = new FakeLibrary();
        library.statusToReturn = -4;
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("svc", library);

        NativeKmsException exception = assertThrows(NativeKmsException.class,
                () -> sut.encrypt(new byte[32], new byte[64]));
        assertEquals("Native KMS wrap failed with status -4.", exception.getMessage());
    }

    @Test
    void decrypt_delegatesToUnwrapDekAndReturnsBytesWritten() {
        FakeLibrary library = new FakeLibrary();
        library.outputToWrite = new byte[32];
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("my-service", library);

        byte[] wrapped = new byte[64];
        byte[] result = new byte[32];
        int written = sut.decrypt(wrapped, result);

        assertEquals(32, written);
        assertEquals(wrapped, library.lastInput);
    }

    @Test
    void decrypt_withNonOkStatus_throwsNativeKmsException() {
        FakeLibrary library = new FakeLibrary();
        library.statusToReturn = -6;
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("svc", library);

        NativeKmsException exception = assertThrows(NativeKmsException.class,
                () -> sut.decrypt(new byte[64], new byte[32]));
        assertEquals("Native KMS unwrap failed with status -6.", exception.getMessage());
    }

    @Test
    void generateAndWrap_delegatesToGenerateAndWrapDekAndReturnsBytesWritten() {
        FakeLibrary library = new FakeLibrary();
        library.outputToWrite = new byte[]{5, 6, 7};
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("my-service", library);

        byte[] result = new byte[16];
        int written = sut.generateAndWrap(result);

        assertEquals(3, written);
        assertEquals("my-service", library.lastService);
    }

    @Test
    void generateAndWrap_withNonOkStatus_throwsNativeKmsException() {
        FakeLibrary library = new FakeLibrary();
        library.statusToReturn = -3;
        NativeHkdfKeyWrapperV1Impl sut = new NativeHkdfKeyWrapperV1Impl("svc", library);

        NativeKmsException exception = assertThrows(NativeKmsException.class,
                () -> sut.generateAndWrap(new byte[64]));
        assertEquals("Native KMS generate-and-wrap failed with status -3.", exception.getMessage());
    }
}
