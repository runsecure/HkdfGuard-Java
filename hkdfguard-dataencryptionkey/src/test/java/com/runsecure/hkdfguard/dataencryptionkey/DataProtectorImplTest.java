package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.DataProtector;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AuthenticationTagMismatchException;
import com.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.FakeKeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.SensitiveLoggingScope;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Exercises DataProtector's failure paths (dataencryptionkey.DataProtectorImpl is package-private -
 * reachable only through KeyRing.createProtector, matching how it's actually used in practice).
 */
class DataProtectorImplTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static KeyRing createRingWithOneKey() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        ring.add(1, new KeyWrappedDataEncryptionKeyImpl(
                new AesGcmCryptoProviderImpl(new FakeKeyWrapper(key), "wrapped".getBytes(StandardCharsets.UTF_8), 60)));
        return ring;
    }

    @Test
    void encrypt_onEmptyRing_throwsIllegalStateException() {
        KeyRing ring = new KeyRing(new DefaultFormatProviderImpl());
        DataProtector protector = ring.createProtector("purpose");

        assertThrows(IllegalStateException.class, () -> protector.encrypt("hello".toCharArray()));
    }

    @Test
    void decrypt_withMalformedInput_throwsIllegalArgumentException() {
        DataProtector protector = createRingWithOneKey().createProtector("purpose");

        assertThrows(IllegalArgumentException.class,
                () -> protector.decrypt("not-a-valid-format".toCharArray(), new char[16]));
    }

    @Test
    void decrypt_forUnregisteredVersion_throwsNoSuchElementException() {
        DataProtector protector = createRingWithOneKey().createProtector("purpose");
        String formatted = protector.encrypt("hello".toCharArray());

        // Claim a version that was never registered in this ring.
        String tampered = formatted.replace("::v1::", "::v99::");

        assertThrows(NoSuchElementException.class, () -> protector.decrypt(tampered.toCharArray(), new char[16]));
    }

    @Test
    void encryptDecrypt_withSensitiveLoggingEnabled_stillRoundTrips() {
        try (SensitiveLoggingScope ignored = new SensitiveLoggingScope(true)) {
            DataProtector protector = createRingWithOneKey().createProtector("purpose");
            String formatted = protector.encrypt("hello".toCharArray());

            char[] result = new char[16];
            int written = protector.decrypt(formatted.toCharArray(), result);

            assertEquals("hello", new String(result, 0, written));
        }
    }

    @Test
    void decrypt_withDifferentProtectorName_throwsDueToAadMismatch() {
        KeyRing ring = createRingWithOneKey();
        String formatted = ring.createProtector("purpose-a").encrypt("hello".toCharArray());

        assertThrows(AuthenticationTagMismatchException.class,
                () -> ring.createProtector("purpose-b").decrypt(formatted.toCharArray(), new char[16]));
    }
}
