package com.runsecure.hkdfguard.abstractions;

import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Shared ProtectedReadOnlyCache plumbing for every cache in this library: a single
 * DataProtectionKey, a case-insensitively-keyed concurrent map of encrypted bytes, and the
 * encrypt/decrypt/telemetry logic every concrete cache needs. decrypt/tryGetMaxDecryptedLength
 * fall back to tryPopulate on a miss before giving up - the default implementation here just
 * returns false (nothing to pull from), but a subclass backed by an external source (e.g. a
 * remote secret store) overrides it to fetch the plaintext value and encrypt it into cache on
 * demand, so nothing here ever holds plaintext beyond the duration of a single call.
 */
public abstract class ProtectedCacheBase implements ProtectedReadOnlyCache {

    private final DataProtectionKey dataProtectionKey;

    /**
     * The encrypted values this cache holds, keyed case-insensitively. Protected so concrete
     * caches (e.g. ProtectedCacheImpl's add/addOrUpdate) can populate it directly.
     */
    protected final Map<String, byte[]> cache = new ConcurrentSkipListMap<>(String.CASE_INSENSITIVE_ORDER);

    protected ProtectedCacheBase(DataProtectionKey dataProtectionKey) {
        this.dataProtectionKey = dataProtectionKey;
    }

    /**
     * Called when name isn't already in cache, before decrypt/tryGetMaxDecryptedLength give up
     * and return false/empty. The default implementation does nothing - override to pull a value
     * in from an external source and populate cache (e.g. via encrypt/encryptChars) before
     * returning true.
     *
     * @param name The name that was missing from cache
     * @return True if name was successfully populated into cache as a result of this call
     */
    protected boolean tryPopulate(String name) {
        return false;
    }

    @Override
    public int decrypt(String name, byte[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.ROOT;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.DECRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.Cache.DECRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.NAME, name));
            }

            byte[] encrypted = tryGetEncrypted(name);
            if (encrypted == null) {
                return 0;
            }

            return dataProtectionKey.decrypt(encrypted, result);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public int decrypt(String name, char[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.ROOT;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.Cache.DECRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.Cache.DECRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.NAME, name));
            }

            byte[] encrypted = tryGetEncrypted(name);
            if (encrypted == null) {
                return 0;
            }

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // encrypted.length is a safe upper bound for the decrypted UTF-8 byte count.
            byte[] plaintextBytes = new byte[encrypted.length];
            try {
                int decryptedLength = dataProtectionKey.decrypt(encrypted, plaintextBytes);
                return utf8Decode(plaintextBytes, decryptedLength, result);
            } finally {
                ArrayUtility.zeroMemory(plaintextBytes);
            }
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public OptionalInt tryGetMaxDecryptedLength(String name) {
        byte[] encrypted = tryGetEncrypted(name);
        return encrypted != null ? OptionalInt.of(encrypted.length) : OptionalInt.empty();
    }

    private byte[] tryGetEncrypted(String name) {
        byte[] encrypted = cache.get(name);
        if (encrypted != null) {
            return encrypted;
        }

        if (tryPopulate(name)) {
            return cache.get(name);
        }

        return null;
    }

    /**
     * Encrypts plaintext through this cache's DataProtectionKey.
     */
    protected byte[] encrypt(byte[] plaintext) {
        return dataProtectionKey.encrypt(plaintext);
    }

    /**
     * Encrypts plaintext (as UTF-8 bytes) through this cache's DataProtectionKey. plaintext is
     * zeroed as a side effect - callers that only hold a String must copy it into a caller-owned
     * char[] first, since a String's own backing storage can't be safely cleared.
     */
    protected byte[] encryptChars(char[] plaintext) {
        try {
            byte[] plaintextBytes = utf8Encode(plaintext);
            return dataProtectionKey.encrypt(plaintextBytes);
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    /**
     * Encodes chars as UTF-8 bytes without ever passing through an immutable String, so the
     * source char[] remains the only copy of the plaintext until the caller zeroes it.
     */
    private static byte[] utf8Encode(char[] chars) {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
        ByteBuffer buffer;
        try {
            buffer = encoder.encode(CharBuffer.wrap(chars));
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid char sequence for UTF-8 encoding", e);
        }
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }

    /**
     * Decodes UTF-8 bytes[0, length) directly into dest, without materializing an intermediate
     * String.
     *
     * @return The number of chars written to dest
     * @throws BufferOverflowException dest is too small to hold the decoded chars
     */
    private static int utf8Decode(byte[] bytes, int length, char[] dest) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        ByteBuffer in = ByteBuffer.wrap(bytes, 0, length);
        CharBuffer out = CharBuffer.wrap(dest);

        CoderResult result = decoder.decode(in, out, true);
        if (result.isOverflow()) {
            throw new BufferOverflowException();
        }
        if (result.isError()) {
            try {
                result.throwException();
            } catch (CharacterCodingException e) {
                throw new IllegalArgumentException("Invalid UTF-8 byte sequence", e);
            }
        }

        result = decoder.flush(out);
        if (result.isOverflow()) {
            throw new BufferOverflowException();
        }

        return out.position();
    }
}
