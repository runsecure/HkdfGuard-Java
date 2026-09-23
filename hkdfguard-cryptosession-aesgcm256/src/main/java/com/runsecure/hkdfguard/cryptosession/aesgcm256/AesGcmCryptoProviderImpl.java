package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background scheduled
 * task, ticking every expirySeconds, proactively reveals the DEK fresh (via
 * keyWrapper.decrypt(wrapped, ...)) and builds the next AesGcmCryptoSession before the current
 * one expires, then swaps it in and closes the outgoing one (zeroing its key) - so encrypt/decrypt
 * themselves never pay the unwrap cost or need to check/refresh anything. Thread-safe: concurrent
 * refreshes (background or foreground - foreground refreshes happen only in the constructor)
 * never race to unwrap/swap the session twice, and readers of the current session go through a
 * volatile reference, so every caller sees a fully-built session.
 */
public final class AesGcmCryptoProviderImpl implements CryptoProvider {

    private static final int KEY_LENGTH = 32;
    private static final int EXTRA_ALLOCATION_LENGTH = AesGcmCryptoSession.NONCE_SIZE + AesGcmCryptoSession.TAG_SIZE;

    private static final ThreadFactory DAEMON_THREAD_FACTORY = runnable -> {
        Thread thread = new Thread(runnable, "hkdfguard-aesgcm256-refresh");
        thread.setDaemon(true);
        return thread;
    };

    private final KeyWrapper keyWrapper;
    private final byte[] wrapped;
    private final Object gate = new Object();
    private final ScheduledExecutorService refreshExecutor;

    private volatile AesGcmCryptoSession current;

    /**
     * @param keyWrapper Reveals wrapped's DEK - see KeyWrapper.decrypt.
     * @param wrapped The wrapped DEK payload this provider's sessions decrypt.
     * @param expirySeconds How long each refreshed session stays valid for, in the range 1-300.
     *     Also the background refresh interval: a fresh session is unwrapped this often, ahead of
     *     the current one's expiry. This provider holds only one active session at a time, so
     *     this is the sole place that range is enforced - AesGcmCryptoSession itself no longer
     *     validates it.
     * @throws IllegalArgumentException expirySeconds is not between 1 and 300
     */
    public AesGcmCryptoProviderImpl(KeyWrapper keyWrapper, byte[] wrapped, int expirySeconds) {
        if (expirySeconds < 1 || expirySeconds > 300) {
            throw new IllegalArgumentException("expirySeconds must be between 1 and 300, was " + expirySeconds + ".");
        }

        this.keyWrapper = keyWrapper;
        this.wrapped = wrapped;

        refresh();

        this.refreshExecutor = Executors.newSingleThreadScheduledExecutor(DAEMON_THREAD_FACTORY);
        refreshExecutor.scheduleAtFixedRate(this::backgroundRefresh, expirySeconds, expirySeconds, TimeUnit.SECONDS);
    }

    /**
     * Builds a provider around notWrapped directly - notWrapped is already a plaintext DEK,
     * never wrapped or unwrapped through keyWrapper (which this constructor holds only so
     * close's zeroing symmetry with the wrapped case still applies to notWrapped). There is no
     * background refresh: the key never changes, so there is nothing to refresh.
     *
     * @param keyWrapper Held only for symmetry - never called.
     * @param notWrapped The plaintext DEK this provider's session encrypts/decrypts with.
     */
    AesGcmCryptoProviderImpl(KeyWrapper keyWrapper, byte[] notWrapped) {
        this.keyWrapper = keyWrapper;
        this.wrapped = notWrapped;
        this.current = new AesGcmCryptoSession(notWrapped);
        this.refreshExecutor = null;
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] result) {
        AesGcmCryptoSession session = current;
        if (session == null) {
            throw new ObjectDisposedException("AesGcmCryptoProviderImpl");
        }
        return session.encrypt(plaintext, result);
    }

    @Override
    public int encrypt(byte[] plaintext, byte[] aad, byte[] result) {
        AesGcmCryptoSession session = current;
        if (session == null) {
            throw new ObjectDisposedException("AesGcmCryptoProviderImpl");
        }
        return session.encrypt(plaintext, aad, result);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] result) {
        AesGcmCryptoSession session = current;
        if (session == null) {
            throw new ObjectDisposedException("AesGcmCryptoProviderImpl");
        }
        return session.decrypt(ciphertext, result);
    }

    @Override
    public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
        AesGcmCryptoSession session = current;
        if (session == null) {
            throw new ObjectDisposedException("AesGcmCryptoProviderImpl");
        }
        return session.decrypt(ciphertext, aad, result);
    }

    @Override
    public int getEncryptedAllocationLength(int length) {
        return length + EXTRA_ALLOCATION_LENGTH;
    }

    @Override
    public int getDecryptedAllocationLength(int length) {
        return length - EXTRA_ALLOCATION_LENGTH;
    }

    // A ScheduledExecutorService's scheduleAtFixedRate silently suppresses every future tick the
    // moment one execution throws - worse than a crash, since nothing ever refreshes again and
    // nothing reports it. Swallow (after recording) instead, and leave `current` as-is: the next
    // background tick remains the fallback, and this provider correctly keeps serving whatever
    // session it last successfully built.
    private void backgroundRefresh() {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.CryptoSessionAesGcm256.BACKGROUND_REFRESH).startSpan();
        try {
            refresh();
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
        } finally {
            span.end();
        }
    }

    private void refresh() {
        synchronized (gate) {
            byte[] key = new byte[KEY_LENGTH];
            keyWrapper.decrypt(wrapped, key);
            AesGcmCryptoSession fresh = new AesGcmCryptoSession(key);

            AesGcmCryptoSession outgoing = current;
            current = fresh;
            if (outgoing != null) {
                outgoing.close();
            }
        }
    }

    @Override
    public void close() {
        if (refreshExecutor != null) {
            refreshExecutor.shutdownNow();
        }

        ArrayUtility.zeroMemory(wrapped);

        synchronized (gate) {
            if (current != null) {
                current.close();
            }
            current = null;
        }
    }
}
