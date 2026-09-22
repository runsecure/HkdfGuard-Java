package com.runsecure.hkdfguard.abstractions;

import java.util.Arrays;

public final class ArrayUtility {

    private ArrayUtility() {
    }

    public static boolean isNullOrEmpty(byte[] input) {
        return isNullOrEmpty(input, 0, input.length);
    }

    public static boolean isNullOrEmpty(byte[] input, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (input[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isNullOrEmpty(char[] input) {
        return isNullOrEmpty(input, 0, input.length);
    }

    public static boolean isNullOrEmpty(char[] input, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (input[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void zeroMemory(byte[] input) {
        Arrays.fill(input, (byte) 0);
    }

    public static void zeroMemory(char[] input) {
        Arrays.fill(input, '\0');
    }
}
