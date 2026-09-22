package com.runsecure.hkdfguard.abstractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProtectedCacheBaseTest {

    @Mock
    private IDataProtectionKey dataProtectionKey;

    /**
     * A no-op "encryption" stand-in: encrypt/decrypt just copy bytes through unchanged, so the
     * test can assert on plaintext round-tripping without a real cipher.
     */
    private static final class TestCache extends ProtectedCacheBase {
        TestCache(IDataProtectionKey dataProtectionKey) {
            super(dataProtectionKey);
        }

        void put(String name, byte[] encrypted) {
            cache.put(name, encrypted);
        }

        byte[] callEncryptChars(char[] plaintext) {
            return encryptChars(plaintext);
        }
    }

    @Test
    void decryptBytes_missingName_returnsZero() {
        TestCache sut = new TestCache(dataProtectionKey);

        int written = sut.decrypt("missing", new byte[16]);

        assertEquals(0, written);
    }

    @Test
    void decryptBytes_presentName_isCaseInsensitive() {
        TestCache sut = new TestCache(dataProtectionKey);
        byte[] encrypted = {1, 2, 3};
        sut.put("MyName", encrypted);
        when(dataProtectionKey.decrypt(any(byte[].class), any(byte[].class)))
                .thenAnswer(invocation -> {
                    byte[] src = invocation.getArgument(0);
                    byte[] dest = invocation.getArgument(1);
                    System.arraycopy(src, 0, dest, 0, src.length);
                    return src.length;
                });

        byte[] result = new byte[3];
        int written = sut.decrypt("myname", result);

        assertEquals(3, written);
        assertArrayEquals(encrypted, result);
    }

    @Test
    void decryptChars_decodesUtf8DirectlyIncludingMultiByteChars() {
        TestCache sut = new TestCache(dataProtectionKey);
        String plaintext = "héllo wörld éèê";
        byte[] utf8Bytes = plaintext.getBytes(StandardCharsets.UTF_8);
        sut.put("greeting", utf8Bytes);
        when(dataProtectionKey.decrypt(any(byte[].class), any(byte[].class)))
                .thenAnswer(invocation -> {
                    byte[] src = invocation.getArgument(0);
                    byte[] dest = invocation.getArgument(1);
                    System.arraycopy(src, 0, dest, 0, src.length);
                    return src.length;
                });

        char[] result = new char[plaintext.length()];
        int written = sut.decrypt("greeting", result);

        assertEquals(plaintext.length(), written);
        assertEquals(plaintext, new String(result, 0, written));
    }

    @Test
    void tryGetMaxDecryptedLength_missingName_returnsEmpty() {
        TestCache sut = new TestCache(dataProtectionKey);

        OptionalInt result = sut.tryGetMaxDecryptedLength("missing");

        assertFalse(result.isPresent());
    }

    @Test
    void tryGetMaxDecryptedLength_presentName_returnsEncryptedLength() {
        TestCache sut = new TestCache(dataProtectionKey);
        sut.put("name", new byte[]{1, 2, 3, 4, 5});

        OptionalInt result = sut.tryGetMaxDecryptedLength("name");

        assertTrue(result.isPresent());
        assertEquals(5, result.getAsInt());
    }

    @Test
    void tryPopulate_defaultImplementation_returnsFalse() {
        TestCache sut = new TestCache(dataProtectionKey);

        assertEquals(0, sut.decrypt("anything", new byte[16]));
    }

    @Test
    void encryptChars_zeroesSourcePlaintextAfterEncrypting() {
        TestCache sut = new TestCache(dataProtectionKey);
        when(dataProtectionKey.encrypt(any(byte[].class))).thenAnswer(invocation -> {
            byte[] plaintextBytes = invocation.getArgument(0);
            assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), plaintextBytes);
            return new byte[]{9, 9, 9};
        });

        char[] plaintext = "secret".toCharArray();
        byte[] encrypted = sut.callEncryptChars(plaintext);

        assertArrayEquals(new byte[]{9, 9, 9}, encrypted);
        assertArrayEquals(new char[]{0, 0, 0, 0, 0, 0}, plaintext);
    }
}
