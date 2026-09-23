package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.DataProtectionKey;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.RecordingFormatProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyRingBuilderTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final BiFunction<KeyWrapper, byte[], CryptoProvider> SESSION_PROVIDER_FACTORY =
            (keyWrapper, wrapped) -> new AesGcmCryptoProviderImpl(keyWrapper, wrapped, 60);

    private static FakeKeyWrapper randomWrapper() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return new FakeKeyWrapper(key);
    }

    @Test
    void withServiceName_setsServiceName() {
        KeyRingBuilder builder = new KeyRingBuilder().withServiceName("my-service");

        assertEquals("my-service", builder.getServiceName());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 300})
    void withCachedKeyExpiry_withinRange_setsCachedKeyExpiry(int cachedKeyExpiry) {
        KeyRingBuilder builder = new KeyRingBuilder().withCachedKeyExpiry(cachedKeyExpiry);

        assertEquals(cachedKeyExpiry, builder.getCachedKeyExpiry());
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 301})
    void withCachedKeyExpiry_outOfRange_throws(int cachedKeyExpiry) {
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withCachedKeyExpiry(cachedKeyExpiry));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 180})
    void withKeyRotationDays_withinRange_setsKeyRotationDays(int keyRotationDays) {
        KeyRingBuilder builder = new KeyRingBuilder().withKeyRotationDays(keyRotationDays);

        assertEquals(keyRotationDays, builder.getKeyRotationDays());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 181})
    void withKeyRotationDays_outOfRange_throws(int keyRotationDays) {
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withKeyRotationDays(keyRotationDays));
    }

    @Test
    void build_withoutKeyWrapper_throws() {
        KeyRingBuilder builder = new KeyRingBuilder()
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withEphemeralKey(1);

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void build_withoutSessionProviderFactory_throws() {
        KeyRingBuilder builder = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withEphemeralKey(1);

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void build_withoutKeyFilesOrEphemeralKeys_throws() {
        KeyRingBuilder builder = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY);

        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void build_withKeyFile_registersVersionFromFile(@TempDir Path tempDir) throws IOException {
        Path path = tempDir.resolve("key1");
        Files.writeString(path, "wrapped");

        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withKeyFile(1, path)
                .build();

        assertEquals(1, ring.getCurrentVersion());
    }

    @Test
    void build_withMultipleKeyFiles_highestVersionBecomesCurrent(@TempDir Path tempDir) throws IOException {
        Path path1 = tempDir.resolve("key1");
        Path path2 = tempDir.resolve("key2");
        Files.writeString(path1, "wrapped-v1");
        Files.writeString(path2, "wrapped-v2");

        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withKeyFile(1, path1)
                .withKeyFile(2, path2)
                .build();

        assertEquals(2, ring.getCurrentVersion());
    }

    @Test
    void build_withEphemeralKey_registersVersion() {
        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withEphemeralKey(1)
                .build();

        assertEquals(1, ring.getCurrentVersion());
    }

    @Test
    void build_withEphemeralKey_producesAWorkingKey() {
        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withEphemeralKey(1)
                .build();

        DataProtectionKey key = ring.get(1);
        byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
        byte[] expected = plaintext.clone();

        byte[] encrypted = key.encrypt(plaintext);
        byte[] decrypted = new byte[expected.length];
        int written = key.decrypt(encrypted, decrypted);

        assertEquals(expected.length, written);
        assertArrayEquals(expected, decrypted);
    }

    @Test
    void build_withKeyFileAndHigherVersionEphemeralKey_ephemeralBecomesCurrent(@TempDir Path tempDir) throws IOException {
        Path path = tempDir.resolve("key1");
        Files.writeString(path, "wrapped");

        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withKeyFile(1, path)
                .withEphemeralKey(2)
                .build();

        assertEquals(2, ring.getCurrentVersion());
    }

    @Test
    void build_usesConfiguredFormatProvider() {
        RecordingFormatProvider recordingFormatProvider = new RecordingFormatProvider();

        KeyRing ring = new KeyRingBuilder()
                .withKeyWrapper(randomWrapper())
                .withSessionProviderFactory(SESSION_PROVIDER_FACTORY)
                .withEphemeralKey(1)
                .withFormatProvider(recordingFormatProvider)
                .build();

        ring.createProtector("purpose").encrypt("hello".toCharArray());

        assertTrue(recordingFormatProvider.isFormatCalled());
    }
}
