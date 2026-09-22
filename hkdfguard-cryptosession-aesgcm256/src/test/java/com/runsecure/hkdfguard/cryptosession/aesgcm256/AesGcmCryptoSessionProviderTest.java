package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import com.runsecure.hkdfguard.abstractions.ICryptoSession;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCryptoSessionProviderTest {

    @Test
    void constructor_buildsInitialSessionEagerly() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();

        try (AesGcmCryptoSessionProvider provider =
                     new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            assertEquals(1, wrapper.getDecryptCallCount());
        }
    }

    @Test
    void constructor_whenKeyWrapperFails_throws() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        wrapper.setThrowOnDecrypt(new IllegalStateException("reveal failed"));

        assertThrows(IllegalStateException.class,
                () -> new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
    }

    @Test
    void constructor_withExpirySecondsOutOfRange_throwsIllegalArgumentException() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();

        for (int expirySeconds : new int[]{0, -1, 301}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), expirySeconds));
        }
    }

    @Test
    void getSession_withinExpiry_returnsTheSameCachedSession() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoSessionProvider provider =
                     new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            ICryptoSession first = provider.getSession();
            ICryptoSession second = provider.getSession();

            assertSame(first, second);
            assertEquals(1, wrapper.getDecryptCallCount());
        }
    }

    @Test
    void getSession_afterExpiry_revealsFreshKeyAndDisposesThePreviousSession() throws InterruptedException {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoSessionProvider provider =
                     new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 1)) {
            ICryptoSession first = provider.getSession();

            Thread.sleep(1500);
            ICryptoSession second = provider.getSession();

            assertNotSame(first, second);
            assertEquals(2, wrapper.getDecryptCallCount());
            assertThrows(ObjectDisposedException.class,
                    () -> first.encrypt("hello".getBytes(StandardCharsets.UTF_8), new byte[33]));
        }
    }

    @Test
    void backgroundTask_proactivelyRefreshesTheSessionWithoutAnyGetSessionCall() throws InterruptedException {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoSessionProvider provider =
                     new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 1)) {
            // No getSession call at all - only the constructor's eager build (decryptCallCount ==
            // 1) and the background task, ticking every expirySeconds, should have run by now.
            Thread.sleep(1500);

            assertEquals(2, wrapper.getDecryptCallCount());
        }
    }

    @Test
    void close_disposesTheCurrentSessionAndStopsTheBackgroundTask() throws InterruptedException {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        AesGcmCryptoSessionProvider provider =
                new AesGcmCryptoSessionProvider(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 1);

        provider.close();
        Thread.sleep(1500);

        // Only the constructor's eager build - the background task must not have fired after close.
        assertEquals(1, wrapper.getDecryptCallCount());
    }
}
