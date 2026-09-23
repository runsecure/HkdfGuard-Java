package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * An AES-256-GCM cipher session backed by a single 32-byte key, supplied once at construction.
 * This instance is meant to be held for a while - see AesGcmCryptoProviderImpl - and closed (zeroing
 * the key) once no longer needed rather than rebuilt on every operation. Session lifetime/expiry
 * is entirely owned by AesGcmCryptoProviderImpl; this type just holds a key and encrypts/decrypts
 * with it until closed.
 *
 * <p>Unlike the C# original, which builds one native AesGcm instance in the constructor and
 * reuses it for every call, this port builds a fresh BouncyCastle {@link GCMModeCipher} per
 * encrypt/decrypt call. BouncyCastle's lightweight cipher objects are stateful across their
 * init/processBytes/doFinal sequence and are not safe for concurrent use by multiple threads on
 * one instance - which a single AesGcmCryptoSession can be, since AesGcmCryptoProviderImpl hands the
 * same instance to any number of concurrent callers. The one genuinely expensive, worth-reusing
 * part - the AES key schedule - BouncyCastle recomputes on every {@code init()} regardless of
 * whether the engine object itself is reused, so nothing is lost by building fresh per call.
 */
final class AesGcmCryptoSession implements AutoCloseable {

    static final int TAG_SIZE = 16;
    static final int NONCE_SIZE = 12;
    private static final int KEY_LENGTH = 32;

    private static final byte[] EMPTY_AAD = new byte[0];
    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] key;

    private volatile boolean disposed;

    /**
     * @param key The 32-byte AES-256 key this session encrypts/decrypts with - ownership
     *     transfers to this instance, which zeroes it on close.
     * @throws IllegalArgumentException key is empty/all-zero, or not exactly 32 bytes
     */
    AesGcmCryptoSession(byte[] key) {
        if (ArrayUtility.isNullOrEmpty(key)) {
            throw new IllegalArgumentException("AES key must not be empty or all zero.");
        }
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("AES key must be exactly " + KEY_LENGTH + " bytes.");
        }

        this.key = key;
    }

    int encrypt(byte[] plaintext, byte[] result) {
        return encrypt(plaintext, EMPTY_AAD, result);
    }

    int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.CryptoSessionAesGcm256.ENCRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.CryptoSessionAesGcm256.ENCRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.PLAINTEXT_LENGTH, plaintext.length),
                        ComponentTelemetry.Detail.of(AttributeNames.AAD_LENGTH, aad.length));
            }

            try {
                return coreEncrypt(plaintext, aad, result);
            } catch (RuntimeException ex) {
                telemetry.recordException(span, ex);
                throw ex;
            } finally {
                ArrayUtility.zeroMemory(plaintext);
            }
        } finally {
            span.end();
        }
    }

    private int coreEncrypt(byte[] plaintext, byte[] aad, byte[] result) {
        if (ArrayUtility.isNullOrEmpty(plaintext)) {
            throw new IllegalArgumentException("Plaintext must not be empty or all zero.");
        }
        if (result.length < NONCE_SIZE + plaintext.length + TAG_SIZE) {
            throw new IllegalArgumentException("Result buffer too small.");
        }
        if (disposed) {
            throw new ObjectDisposedException("AesGcmCryptoSession");
        }

        // Layout: [nonce | ciphertext | tag]
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);

        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(true, new AEADParameters(new KeyParameter(key), TAG_SIZE * 8, nonce, aad));

        int written = cipher.processBytes(plaintext, 0, plaintext.length, result, NONCE_SIZE);
        try {
            written += cipher.doFinal(result, NONCE_SIZE + written);
        } catch (InvalidCipherTextException e) {
            // Encryption never verifies a tag, so doFinal can't actually fail this way here -
            // doFinal's signature declares the checked exception regardless, so it must be handled.
            throw new IllegalStateException("Unexpected GCM encryption failure.", e);
        }

        return NONCE_SIZE + written;
    }

    int decrypt(byte[] ciphertext, byte[] result) {
        return decrypt(ciphertext, EMPTY_AAD, result);
    }

    int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.CryptoSessionAesGcm256.DECRYPT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.CryptoSessionAesGcm256.DECRYPT,
                        ComponentTelemetry.Detail.of(AttributeNames.CIPHERTEXT_LENGTH, ciphertext.length),
                        ComponentTelemetry.Detail.of(AttributeNames.AAD_LENGTH, aad.length));
            }

            return coreDecrypt(ciphertext, aad, result);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    private int coreDecrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        if (ArrayUtility.isNullOrEmpty(ciphertext)) {
            throw new IllegalArgumentException("Ciphertext must not be empty or all zero.");
        }
        if (ciphertext.length < NONCE_SIZE + TAG_SIZE) {
            throw new IllegalArgumentException("Ciphertext too short.");
        }

        int resultLength = ciphertext.length - NONCE_SIZE - TAG_SIZE;
        if (result.length < resultLength) {
            throw new IllegalArgumentException("Result buffer too small.");
        }
        if (disposed) {
            throw new ObjectDisposedException("AesGcmCryptoSession");
        }

        byte[] nonce = Arrays.copyOfRange(ciphertext, 0, NONCE_SIZE);
        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(false, new AEADParameters(new KeyParameter(key), TAG_SIZE * 8, nonce, aad));

        int cipherAndTagLength = resultLength + TAG_SIZE;
        try {
            int written = cipher.processBytes(ciphertext, NONCE_SIZE, cipherAndTagLength, result, 0);
            written += cipher.doFinal(result, written);
            return written;
        } catch (InvalidCipherTextException e) {
            throw new AuthenticationTagMismatchException(
                    "The authentication tag does not match the given ciphertext or associated data.", e);
        }
    }

    @Override
    public void close() {
        disposed = true;
        ArrayUtility.zeroMemory(key);
    }
}
