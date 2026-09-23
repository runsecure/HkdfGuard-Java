package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.DataProtectionKey;
import com.runsecure.hkdfguard.abstractions.DataProtector;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.RecordingFormatProvider;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.SensitiveLoggingScope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRingTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static DataProtectionKey createFakeKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(new FakeKeyWrapper(key), "wrapped".getBytes(StandardCharsets.UTF_8), 60));
    }

    @Test
    void getCurrentVersion_beforeAnyAdd_throwsIllegalStateException() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        assertThrows(IllegalStateException.class, ring::getCurrentVersion);
    }

    @Test
    void add_firstKey_becomesCurrentVersion() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(1, createFakeKey());

        assertEquals(1, ring.getCurrentVersion());
    }

    @Test
    void add_higherVersion_becomesNewCurrent() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(1, createFakeKey());
        ring.add(5, createFakeKey());

        assertEquals(5, ring.getCurrentVersion());
    }

    @Test
    void add_lowerVersionAfterHigher_doesNotChangeCurrent() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(5, createFakeKey());
        ring.add(1, createFakeKey());

        assertEquals(5, ring.getCurrentVersion());
    }

    @Test
    void add_withSensitiveLoggingEnabled_stillWorksCorrectly() {
        try (SensitiveLoggingScope ignored = new SensitiveLoggingScope(true)) {
            KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
            ring.add(1, createFakeKey());

            assertEquals(1, ring.getCurrentVersion());
        }
    }

    @Test
    void add_duplicateVersion_throwsIllegalArgumentException() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(1, createFakeKey());

        assertThrows(IllegalArgumentException.class, () -> ring.add(1, createFakeKey()));
    }

    @Test
    void get_registeredVersion_returnsSameInstance() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        DataProtectionKey key = createFakeKey();
        ring.add(1, key);

        assertSame(key, ring.get(1));
    }

    @Test
    void get_unregisteredVersion_throwsNoSuchElementException() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        assertThrows(NoSuchElementException.class, () -> ring.get(999));
    }

    @Test
    void tryGet_registeredVersion_returnsKey() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        DataProtectionKey key = createFakeKey();
        ring.add(1, key);

        Optional<DataProtectionKey> found = ring.tryGet(1);
        assertTrue(found.isPresent());
        assertSame(key, found.get());
    }

    @Test
    void tryGet_unregisteredVersion_returnsEmpty() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        assertFalse(ring.tryGet(999).isPresent());
    }

    @Test
    void getCurrent_returnsCurrentVersionAndKey() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        DataProtectionKey key = createFakeKey();
        ring.add(3, key);

        KeyRing.CurrentKey current = ring.getCurrent();

        assertEquals(3, current.version());
        assertSame(key, current.key());
    }

    @Test
    void getCurrent_withNoKeysAdded_throwsIllegalStateException() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        assertThrows(IllegalStateException.class, ring::getCurrent);
    }

    @Test
    void createProtector_producesWorkingProtectorBoundToThisRing() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(1, createFakeKey());

        DataProtector protector = ring.createProtector("purpose");
        String formatted = protector.encrypt("hello".toCharArray());

        char[] result = new char[protector.getMaxDecryptedLength(formatted.toCharArray())];
        int written = protector.decrypt(formatted.toCharArray(), result);

        assertEquals("hello", new String(result, 0, written));
    }

    @Test
    void createProtector_usesRingsConfiguredFormatProvider() {
        RecordingFormatProvider recordingFormatProvider = new RecordingFormatProvider();
        KeyRing ring = new KeyRing(recordingFormatProvider);
        ring.add(1, createFakeKey());

        String formatted = ring.createProtector("purpose").encrypt("hello".toCharArray());
        assertTrue(recordingFormatProvider.isFormatCalled());

        ring.createProtector("purpose").decrypt(formatted.toCharArray(), new char[16]);
        assertTrue(recordingFormatProvider.isParseCalled());
    }
}
