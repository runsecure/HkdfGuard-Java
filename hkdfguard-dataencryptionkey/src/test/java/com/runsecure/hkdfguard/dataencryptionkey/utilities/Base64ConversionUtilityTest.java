package com.runsecure.hkdfguard.dataencryptionkey.utilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Base64ConversionUtilityTest {

    @ParameterizedTest
    @CsvSource({
            "AAAA, true",
            "AAA=, true",
            "'', true",
            "'not valid base64!!!', false",
    })
    void isBase64_charSequence_validatesCorrectly(String input, boolean expected) {
        assertEquals(expected, Base64ConversionUtility.isBase64(input));
    }

    @Test
    void isBase64_byteArray_validatesCorrectly() {
        assertTrue(Base64ConversionUtility.isBase64("AAAA".getBytes(StandardCharsets.UTF_8)));
        assertFalse(Base64ConversionUtility.isBase64("!!!!".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void getBinaryLength_emptyInput_returnsZero() {
        assertEquals(0, Base64ConversionUtility.getBinaryLength(""));
    }

    @ParameterizedTest
    @CsvSource({
            "QQ==, 1",
            "QUI=, 2",
            "QUJD, 3",
    })
    void getBinaryLength_computesCorrectLength(String base64, int expectedLength) {
        assertEquals(expectedLength, Base64ConversionUtility.getBinaryLength(base64));
    }

    @Test
    void getBinaryLength_notMultipleOfFour_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> Base64ConversionUtility.getBinaryLength("AAA"));
    }

    @Test
    void getBase64Length_emptyInput_returnsZero() {
        assertEquals(0, Base64ConversionUtility.getBase64Length(new byte[0]));
    }

    @ParameterizedTest
    @CsvSource({
            "1, 4",
            "2, 4",
            "3, 4",
            "4, 8",
    })
    void getBase64Length_computesCorrectLength(int byteLength, int expectedCharLength) {
        assertEquals(expectedCharLength, Base64ConversionUtility.getBase64Length(new byte[byteLength]));
    }

    @Test
    void toBase64String_thenFromBase64_roundTrips() {
        byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
        String base64 = Base64ConversionUtility.toBase64String(data);
        byte[] destination = new byte[Base64ConversionUtility.getBinaryLength(base64)];

        int written = Base64ConversionUtility.fromBase64(base64, destination);

        assertEquals(data.length, written);
        assertArrayEquals(data, destination);
    }

    @Test
    void fromBase64_withInvalidInput_throwsIllegalArgumentException() {
        byte[] destination = new byte[16];
        assertThrows(IllegalArgumentException.class,
                () -> Base64ConversionUtility.fromBase64("not valid base64!!!", destination));
    }

    @Test
    void fromBase64_withTooSmallDestination_throwsIllegalArgumentException() {
        byte[] destination = new byte[1];
        assertThrows(IllegalArgumentException.class, () -> Base64ConversionUtility.fromBase64("QUJD", destination));
    }

    @Test
    void toBase64Chars_thenFromBase64_roundTrips() {
        byte[] data = "round trip".getBytes(StandardCharsets.UTF_8);
        char[] destination = new char[Base64ConversionUtility.getBase64Length(data)];

        int written = Base64ConversionUtility.toBase64Chars(data, destination);

        assertEquals(destination.length, written);

        String base64 = new String(destination, 0, written);
        byte[] decoded = new byte[Base64ConversionUtility.getBinaryLength(base64)];
        Base64ConversionUtility.fromBase64(base64, decoded);
        assertArrayEquals(data, decoded);
    }

    @Test
    void toBase64Chars_withTooSmallDestination_throwsIllegalArgumentException() {
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        char[] destination = new char[1];

        assertThrows(IllegalArgumentException.class, () -> Base64ConversionUtility.toBase64Chars(data, destination));
    }
}
