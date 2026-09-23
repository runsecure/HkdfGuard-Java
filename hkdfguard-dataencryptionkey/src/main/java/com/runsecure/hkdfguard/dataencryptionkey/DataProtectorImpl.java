package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import com.runsecure.hkdfguard.abstractions.DataProtector;
import com.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import com.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.StandardCharsets;

/**
 * Default DataProtector. Package-private: only KeyRing (KeyRing.createProtector) can construct
 * one, so callers only ever see it as a DataProtector - guaranteeing every instance is actually
 * bound to a real KeyRing rather than constructed loose. name is UTF-8-encoded once into aad and
 * used for every encrypt/decrypt, so a value protected under one name/purpose fails to decrypt
 * under another. encrypt resolves keyRing.getCurrent() fresh on every call rather than capturing
 * a version once at construction, so it always protects new data with whatever the ring's latest
 * rotation is; decrypt instead resolves whichever version the formatted ciphertext itself names,
 * so old versions stay readable regardless.
 */
final class DataProtectorImpl implements DataProtector {

    private final String name;
    private final KeyRing keyRing;
    private final EncryptedFormatProvider formatProvider;
    private final byte[] aad;

    DataProtectorImpl(String name, KeyRing keyRing, EncryptedFormatProvider formatProvider) {
        this.name = name;
        this.keyRing = keyRing;
        this.formatProvider = formatProvider;
        this.aad = name.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String encrypt(char[] plaintext) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.PROTECTOR_ENCRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.PROTECTOR_ENCRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                        ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length));
            }

            KeyRing.CurrentKey current = keyRing.getCurrent();

            byte[] plaintextBytes = utf8Encode(plaintext);
            // plaintextBytes is zeroed as a side effect of the encrypt call it's passed to.
            byte[] encryptedBytes = current.key().encrypt(plaintextBytes, aad);

            return formatProvider.format(new KeyTrackingValue(current.version(), encryptedBytes));
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public int decrypt(char[] encrypted, char[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.PROTECTOR_DECRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.PROTECTOR_DECRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.NAME, name),
                        ComponentTelemetry.Detail.of(AttributeNames.ENCRYPTED_LENGTH, encrypted.length));
            }

            KeyTrackingValue value = formatProvider.parse(encrypted);
            DataEncryptionKey key = keyRing.get(value.keyVersion());

            // AEAD ciphertext is always at least as long as the plaintext it encloses, so
            // value.value().length is a safe upper bound for the decrypted UTF-8 byte count.
            byte[] plaintextBytes = new byte[value.value().length];
            try {
                int bytesWritten = key.decrypt(value.value(), aad, plaintextBytes);
                return utf8Decode(plaintextBytes, bytesWritten, result);
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
    public int getMaxDecryptedLength(char[] encrypted) {
        return formatProvider.getMaxDecryptedLength(encrypted);
    }

    // Encodes chars as UTF-8 bytes without ever passing through an immutable String, so the
    // source char[] remains the only copy of the plaintext until the caller zeroes it - same
    // reasoning as ProtectedCacheBase.encryptChars in hkdfguard-abstractions.
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

    // Decodes UTF-8 bytes[0, length) directly into dest, without materializing an intermediate
    // String - same reasoning as ProtectedCacheBase.decrypt(String, char[]).
    private static int utf8Decode(byte[] bytes, int length, char[] dest) {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        ByteBuffer in = ByteBuffer.wrap(bytes, 0, length);
        CharBuffer out = CharBuffer.wrap(dest);

        CoderResult result = decoder.decode(in, out, true);
        if (result.isOverflow()) {
            throw new java.nio.BufferOverflowException();
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
            throw new java.nio.BufferOverflowException();
        }

        return out.position();
    }
}
