package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.ICryptoSession;
import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IKeyWrapper;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;

/**
 * Tracks one cached AesGcmCryptoSession, bound to a single wrapped DEK. A background scheduled
 * task, ticking every expirySeconds, proactively reveals the DEK fresh (via
 * keyWrapper.decrypt(wrapped, ...)) and builds the next AesGcmCryptoSession before the current
 * one expires, then swaps it in and closes the outgoing one (zeroing its key) - so getSession
 * itself almost never pays the unwrap cost or observes an expired session. getSession still
 * double-checks and refreshes synchronously on the rare chance a call lands in the (sub-
 * millisecond) gap between expiry and the background task's next tick. Thread-safe: concurrent
 * refreshes (background or foreground) never race to unwrap/swap the same session twice.
 */
public final class AesGcmCryptoSessionProvider implements ICryptoSessionProvider {

    private static final int KEY_LENGTH = 32;

    private static final ThreadFactory DAEMON_THREAD_FACTORY = runnable -> {
        Thread thread = new Thread(runnable, "hkdfguard-aesgcm256-refresh");
        thread.setDaemon(true);
        return thread;
    };

    private final IKeyWrapper keyWrapper;
    private final byte[] wrapped;
    private final int expirySeconds;
    private final Object gate = new Object();
    private final ScheduledExecutorService refreshExecutor;

    private ICryptoSession current;

    /**
     * @param keyWrapper Reveals wrapped's DEK - see IKeyWrapper.decrypt.
     * @param wrapped The wrapped DEK payload this provider's sessions decrypt.
     * @param expirySeconds How long each refreshed session stays valid for, in the range 1-300.
     *     Also the background refresh interval: a fresh session is unwrapped this often, ahead of
     *     the current one's expiry. This provider holds only one active session at a time, so
     *     this is the sole place that range is enforced - AesGcmCryptoSession itself no longer
     *     validates it.
     * @throws IllegalArgumentException expirySeconds is not between 1 and 300
     */
    public AesGcmCryptoSessionProvider(IKeyWrapper keyWrapper, byte[] wrapped, int expirySeconds) {
        if (expirySeconds < 1 || expirySeconds > 300) {
            throw new IllegalArgumentException("expirySeconds must be between 1 and 300, was " + expirySeconds + ".");
        }

        this.keyWrapper = keyWrapper;
        this.wrapped = wrapped;
        this.expirySeconds = expirySeconds;

        refresh();

        this.refreshExecutor = Executors.newSingleThreadScheduledExecutor(DAEMON_THREAD_FACTORY);
        refreshExecutor.scheduleAtFixedRate(this::backgroundRefresh, expirySeconds, expirySeconds, TimeUnit.SECONDS);
    }

    @Override
    public ICryptoSession getSession() {
        synchronized (gate) {
            if (current != null && current.getExpiresAt().isAfter(Instant.now())) {
                return current;
            }

            refresh();
            return current;
        }
    }

    // A ScheduledExecutorService's scheduleAtFixedRate silently suppresses every future tick the
    // moment one execution throws - worse than a crash, since nothing ever refreshes again and
    // nothing reports it. Swallow (after recording) instead: getSession's own expiry
    // check/refresh remains the fallback, and correctly surfaces the failure to whichever caller
    // next needs a session.
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
            ICryptoSession fresh = new AesGcmCryptoSession(key, expirySeconds);

            ICryptoSession outgoing = current;
            current = fresh;
            if (outgoing != null) {
                outgoing.close();
            }
        }
    }

    @Override
    public void close() {
        refreshExecutor.shutdownNow();

        synchronized (gate) {
            if (current != null) {
                current.close();
            }
            current = null;
        }
    }
}
