package com.runsecure.hkdfguard.dataencryptionkey.formatprovider;

import com.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import com.runsecure.hkdfguard.dataencryptionkey.testhelpers.SensitiveLoggingScope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultFormatProviderImplTest {

    private final DefaultFormatProviderImpl provider = new DefaultFormatProviderImpl();

    @Test
    void formatParseGetMaxDecryptedLength_withSensitiveLoggingEnabled_stillWorkCorrectly() {
        try (SensitiveLoggingScope ignored = new SensitiveLoggingScope(true)) {
            KeyTrackingValue value = new KeyTrackingValue(2, "abc".getBytes(StandardCharsets.UTF_8));
            String formatted = provider.format(value);
            KeyTrackingValue parsed = provider.parse(formatted.toCharArray());
            int maxLength = provider.getMaxDecryptedLength(formatted.toCharArray());

            assertArrayEquals(value.value(), parsed.value());
            assertEquals(parsed.value().length, maxLength);
        }
    }

    @Test
    void formatThenParse_roundTrips() {
        KeyTrackingValue value = new KeyTrackingValue(7, "hello".getBytes(StandardCharsets.UTF_8));

        String formatted = provider.format(value);
        assertTrue(formatted.startsWith("enc::v7::"));

        KeyTrackingValue parsed = provider.parse(formatted.toCharArray());
        assertEquals(7, parsed.keyVersion());
        assertArrayEquals(value.value(), parsed.value());
    }

    @Test
    void format_withEmptyValue_roundTrips() {
        KeyTrackingValue value = new KeyTrackingValue(1, new byte[0]);

        String formatted = provider.format(value);
        KeyTrackingValue parsed = provider.parse(formatted.toCharArray());

        assertEquals(1, parsed.keyVersion());
        assertEquals(0, parsed.value().length);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "no-delimiters-at-all", "enc::onlyonepart", "wrong::v1::AAAA", "enc::1::AAAA", "enc::vNotANumber::AAAA"})
    void parse_withMalformedInput_throwsIllegalArgumentException(String input) {
        assertThrows(IllegalArgumentException.class, () -> provider.parse(input.toCharArray()));
    }

    @Test
    void parse_withInvalidBase64_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> provider.parse("enc::v1::not-valid-base64!!!".toCharArray()));
    }

    @Test
    void getMaxDecryptedLength_matchesParsedValueLength() {
        byte[] randomData = new byte[40];
        new SecureRandom().nextBytes(randomData);
        KeyTrackingValue value = new KeyTrackingValue(3, randomData);
        String formatted = provider.format(value);

        int maxLength = provider.getMaxDecryptedLength(formatted.toCharArray());
        KeyTrackingValue parsed = provider.parse(formatted.toCharArray());

        assertEquals(parsed.value().length, maxLength);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "enc::onlyonepart", "enc::1::AAAA"})
    void getMaxDecryptedLength_withMalformedInput_throwsIllegalArgumentException(String input) {
        assertThrows(IllegalArgumentException.class, () -> provider.getMaxDecryptedLength(input.toCharArray()));
    }

    @Test
    void getMaxDecryptedLength_withInvalidBase64_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> provider.getMaxDecryptedLength("enc::v1::not-valid-base64!!!".toCharArray()));
    }
}
