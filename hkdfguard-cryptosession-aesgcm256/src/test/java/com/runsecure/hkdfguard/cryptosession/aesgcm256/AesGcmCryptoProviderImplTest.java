package com.runsecure.hkdfguard.cryptosession.aesgcm256;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCryptoProviderImplTest {

    @Test
    void constructor_buildsInitialSessionEagerly() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();

        try (AesGcmCryptoProviderImpl ignored =
                     new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            assertEquals(1, wrapper.getDecryptCallCount());
        }
    }

    @Test
    @SuppressWarnings("resource")
    void constructor_whenKeyWrapperFails_throws() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        wrapper.setThrowOnDecrypt(new IllegalStateException("reveal failed"));

        assertThrows(IllegalStateException.class,
                () -> new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60));
    }

    @Test
    @SuppressWarnings("resource")
    void constructor_withExpirySecondsOutOfRange_throwsIllegalArgumentException() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();

        for (int expirySeconds : new int[]{0, -1, 301}) {
            assertThrows(IllegalArgumentException.class,
                    () -> new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), expirySeconds));
        }
    }

    @Test
    void backgroundTask_proactivelyRefreshesTheSessionWithoutAnyEncryptOrDecryptCall() throws InterruptedException {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoProviderImpl ignored =
                     new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 1)) {
            // No encrypt/decrypt call at all - only the constructor's eager build
            // (decryptCallCount == 1) and the background task, ticking every expirySeconds,
            // should have run by now.
            Thread.sleep(1500);

            assertEquals(2, wrapper.getDecryptCallCount());
        }
    }

    @Test
    void close_disposesTheCurrentSessionAndStopsTheBackgroundTask() throws InterruptedException {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        AesGcmCryptoProviderImpl provider =
                new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 1);

        provider.close();
        Thread.sleep(1500);

        // Only the constructor's eager build - the background task must not have fired after close.
        assertEquals(1, wrapper.getDecryptCallCount());
    }

    @Test
    void getEncryptedAllocationLength_addsNonceAndTagOverhead() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoProviderImpl provider =
                     new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            assertEquals(10 + 12 + 16, provider.getEncryptedAllocationLength(10));
        }
    }

    @Test
    void getDecryptedAllocationLength_removesNonceAndTagOverhead() {
        FakeKeyWrapper wrapper = new FakeKeyWrapper();
        try (AesGcmCryptoProviderImpl provider =
                     new AesGcmCryptoProviderImpl(wrapper, "wrapped".getBytes(StandardCharsets.UTF_8), 60)) {
            assertEquals(10, provider.getDecryptedAllocationLength(10 + 12 + 16));
        }
    }
}
