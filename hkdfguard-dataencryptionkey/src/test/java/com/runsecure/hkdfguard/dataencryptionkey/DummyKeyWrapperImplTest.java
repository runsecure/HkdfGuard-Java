package com.runsecure.hkdfguard.dataencryptionkey;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * DummyKeyWrapperImpl stands in for the KeyWrapper the pipeline flow's
 * CryptoProviderFactory.createForPipeline requires but never actually calls (the DEK is used
 * as-is, never wrapped) - every member is an inert no-op.
 */
class DummyKeyWrapperImplTest {

    @Test
    void encrypt_returnsZero() {
        DummyKeyWrapperImpl wrapper = new DummyKeyWrapperImpl();

        assertEquals(0, wrapper.encrypt(new byte[32], new byte[64]));
    }

    @Test
    void decrypt_returnsZero() {
        DummyKeyWrapperImpl wrapper = new DummyKeyWrapperImpl();

        assertEquals(0, wrapper.decrypt(new byte[32], new byte[32]));
    }

    @Test
    void generateAndWrap_returnsZero() {
        DummyKeyWrapperImpl wrapper = new DummyKeyWrapperImpl();

        assertEquals(0, wrapper.generateAndWrap(new byte[32]));
    }
}
