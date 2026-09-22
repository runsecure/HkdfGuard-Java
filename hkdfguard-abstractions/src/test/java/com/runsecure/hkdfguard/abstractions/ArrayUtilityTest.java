package com.runsecure.hkdfguard.abstractions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArrayUtilityTest {

    @Test
    void isNullOrEmpty_bytes_withAllZeroArray_returnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new byte[16]));
    }

    @Test
    void isNullOrEmpty_bytes_withEmptyArray_returnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new byte[0]));
    }

    @Test
    void isNullOrEmpty_bytes_withNonZeroByte_returnsFalse() {
        byte[] bytes = new byte[16];
        bytes[10] = 1;

        assertFalse(ArrayUtility.isNullOrEmpty(bytes));
    }

    @Test
    void isNullOrEmpty_chars_withAllZeroArray_returnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new char[16]));
    }

    @Test
    void isNullOrEmpty_chars_withEmptyArray_returnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new char[0]));
    }

    @Test
    void isNullOrEmpty_chars_withNonZeroChar_returnsFalse() {
        char[] chars = new char[16];
        chars[3] = 'a';

        assertFalse(ArrayUtility.isNullOrEmpty(chars));
    }

    @Test
    void zeroMemory_bytes_clearsEveryByte() {
        byte[] bytes = {1, 2, 3, 4, 5};

        ArrayUtility.zeroMemory(bytes);

        assertArrayEquals(new byte[5], bytes);
    }

    @Test
    void zeroMemory_bytes_withEmptyArray_doesNotThrow() {
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory(new byte[0]));
    }

    @Test
    void zeroMemory_chars_clearsEveryChar() {
        char[] chars = "hello".toCharArray();

        ArrayUtility.zeroMemory(chars);

        assertArrayEquals(new char[5], chars);
    }

    @Test
    void zeroMemory_chars_withEmptyArray_doesNotThrow() {
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory(new char[0]));
    }
}
