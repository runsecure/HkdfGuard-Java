package com.runsecure.hkdfguard.keywrapping.v1;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeHostTest {

    @ParameterizedTest
    @CsvSource({
            "Windows 11, WINDOWS",
            "Windows Server 2022, WINDOWS",
            "Linux, LINUX",
            "Mac OS X, MAC_OS",
            "Darwin, MAC_OS",
    })
    void resolvePlatform_selectsMatchingPlatform(String osName, NativeHost.Platform expected) {
        assertEquals(expected, NativeHost.resolvePlatform(osName));
    }

    @ParameterizedTest
    @ValueSource(strings = {"SunOS", "FreeBSD", "AIX", ""})
    void resolvePlatform_withUnsupportedOs_throwsUnsupportedOperationException(String osName) {
        UnsupportedOperationException exception = assertThrows(UnsupportedOperationException.class,
                () -> NativeHost.resolvePlatform(osName));
        assertTrue(exception.getMessage().contains(osName));
    }
}
