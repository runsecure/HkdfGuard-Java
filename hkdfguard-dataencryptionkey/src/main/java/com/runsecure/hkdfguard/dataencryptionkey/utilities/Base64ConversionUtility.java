package com.runsecure.hkdfguard.dataencryptionkey.utilities;

import java.util.Base64;

public final class Base64ConversionUtility {

    private Base64ConversionUtility() {
    }

    /**
     * Checks whether text holds valid base64.
     *
     * @param base64 The text to validate
     * @return True if base64 is valid base64 text
     */
    public static boolean isBase64(CharSequence base64) {
        try {
            Base64.getDecoder().decode(base64.toString());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks whether a byte array holds base64 text encoded as ASCII/UTF-8 bytes.
     *
     * @param base64 The bytes to validate
     * @return True if every byte is a valid base64 character byte
     */
    public static boolean isBase64(byte[] base64) {
        try {
            Base64.getDecoder().decode(base64);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Computes the decoded binary length for base64-encoded text.
     *
     * @param base64 The base64 text
     * @return The number of bytes the decoded data will occupy
     * @throws IllegalArgumentException base64's length is not a multiple of 4
     */
    public static int getBinaryLength(CharSequence base64) {
        if (base64.isEmpty()) {
            return 0;
        }
        if (base64.length() % 4 != 0) {
            throw new IllegalArgumentException("Base64 input length must be a multiple of 4.");
        }

        int padding = 0;
        if (base64.charAt(base64.length() - 1) == '=') padding++;
        if (base64.charAt(base64.length() - 2) == '=') padding++;

        return base64.length() / 4 * 3 - padding;
    }

    /**
     * Computes the base64-encoded char length for a byte array.
     *
     * @param data The binary data to be encoded
     * @return The number of chars the base64 encoded output will occupy
     */
    public static int getBase64Length(byte[] data) {
        return data.length == 0 ? 0 : (data.length + 2) / 3 * 4;
    }

    /**
     * Decodes base64 text into its binary representation.
     *
     * @param base64 The base64 text to decode
     * @param destination The array to receive the decoded bytes
     * @return Number of bytes written to destination
     * @throws IllegalArgumentException base64 is not valid base64, or destination is too small
     */
    public static int fromBase64(CharSequence base64, byte[] destination) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64.toString());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Input is not valid base64, or the destination array is too small.", e);
        }

        if (decoded.length > destination.length) {
            throw new IllegalArgumentException("Input is not valid base64, or the destination array is too small.");
        }

        System.arraycopy(decoded, 0, destination, 0, decoded.length);
        return decoded.length;
    }

    /**
     * Encodes binary data as a base64 string.
     *
     * @param data The binary data to encode
     * @return The base64 encoded string
     */
    public static String toBase64String(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Encodes binary data as base64 into a char array.
     *
     * @param data The binary data to encode
     * @param destination The array to receive the base64 encoded chars
     * @return Number of chars written to destination
     * @throws IllegalArgumentException destination is too small
     */
    public static int toBase64Chars(byte[] data, char[] destination) {
        String encoded = Base64.getEncoder().encodeToString(data);
        if (encoded.length() > destination.length) {
            throw new IllegalArgumentException("Destination array too small.");
        }

        encoded.getChars(0, encoded.length(), destination, 0);
        return encoded.length();
    }
}
