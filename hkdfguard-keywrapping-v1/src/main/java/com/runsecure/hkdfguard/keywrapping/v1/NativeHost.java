package com.runsecure.hkdfguard.keywrapping.v1;

import java.util.Locale;

/**
 * Resolves the current OS's native HkdfGuard KMS library exactly once per process (binding the
 * wrong platform's library would fail on first native call anyway, so there's nothing to gain by
 * re-resolving per instance).
 */
final class NativeHost {

    private NativeHost() {
    }

    enum Platform {
        WINDOWS,
        LINUX,
        MAC_OS
    }

    private static final class Holder {
        private static final AbstractHkdfGuardKmsLibrary INSTANCE = construct(resolvePlatform(osName()));
    }

    static AbstractHkdfGuardKmsLibrary getLibrary() {
        return Holder.INSTANCE;
    }

    /**
     * Maps an {@code os.name}-style string to the matching platform, without touching any native
     * library - kept separate from {@link #construct} so this selection logic can be exercised
     * without a native library present.
     */
    static Platform resolvePlatform(String osName) {
        String normalized = osName.toLowerCase(Locale.ROOT);

        // "windows", not just "win" - "Darwin" also contains "win" and must not match here.
        if (normalized.contains("windows")) {
            return Platform.WINDOWS;
        }
        if (normalized.contains("linux")) {
            return Platform.LINUX;
        }
        if (normalized.contains("mac") || normalized.contains("darwin")) {
            return Platform.MAC_OS;
        }

        throw new UnsupportedOperationException(
                "HkdfGuard.KeyWrapping.V1 has no native KMS library for '" + osName + "'.");
    }

    private static AbstractHkdfGuardKmsLibrary construct(Platform platform) {
        return switch (platform) {
            case WINDOWS -> new WindowsHkdfGuardKmsLibrary();
            case LINUX -> new LinuxHkdfGuardKmsLibrary();
            case MAC_OS -> new MacOsHkdfGuardKmsLibrary();
        };
    }

    private static String osName() {
        return System.getProperty("os.name", "");
    }
}
