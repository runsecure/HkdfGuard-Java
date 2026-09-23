package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class PipelineKeyFactoryTest {

    private static final CryptoProviderFactory CRYPTO_PROVIDER_FACTORY = new AesGcmCryptoProviderFactoryImpl();

    @Test
    void create_generatesA32ByteDek() {
        PipelineKeyFactory factory = new PipelineKeyFactory();

        try (PipelineDataEncryptionKeyImpl key = factory.create(CRYPTO_PROVIDER_FACTORY)) {
            assertEquals(32, key.asBytes().length);

            boolean allZero = true;
            for (byte b : key.asBytes()) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            assertFalse(allZero);
        }
    }

    @Test
    void create_generatesADifferentDekEachTime() {
        PipelineKeyFactory factory = new PipelineKeyFactory();

        try (PipelineDataEncryptionKeyImpl key1 = factory.create(CRYPTO_PROVIDER_FACTORY);
             PipelineDataEncryptionKeyImpl key2 = factory.create(CRYPTO_PROVIDER_FACTORY)) {
            assertNotEquals(Arrays.toString(key1.asBytes()), Arrays.toString(key2.asBytes()));
        }
    }

    @Test
    void create_producesAWorkingKey() {
        PipelineKeyFactory factory = new PipelineKeyFactory();

        try (PipelineDataEncryptionKeyImpl key = factory.create(CRYPTO_PROVIDER_FACTORY)) {
            byte[] plaintext = "top secret".getBytes(StandardCharsets.UTF_8);
            byte[] expected = plaintext.clone();

            byte[] encrypted = key.encrypt(plaintext);
            byte[] decrypted = new byte[expected.length];
            int written = key.decrypt(encrypted, decrypted);

            assertEquals(expected.length, written);
            assertArrayEquals(expected, decrypted);
        }
    }

    @Test
    void create_keyCanBeClosedWithoutThrowing() {
        PipelineKeyFactory factory = new PipelineKeyFactory();
        PipelineDataEncryptionKeyImpl key = factory.create(CRYPTO_PROVIDER_FACTORY);

        assertDoesNotThrow(key::close);
    }
}
