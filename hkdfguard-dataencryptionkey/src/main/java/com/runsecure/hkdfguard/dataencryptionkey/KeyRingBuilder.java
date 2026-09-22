package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.ICryptoSessionProvider;
import com.runsecure.hkdfguard.abstractions.IEncryptedFormatProvider;
import com.runsecure.hkdfguard.abstractions.IKeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

/**
 * Builds a KeyRing from wrapped-DEK files on disk, suitable for registering as a singleton in a
 * DI container at startup. There is one IKeyWrapper shared by every registered file - it's bound
 * only to a KEK (e.g. NativeHkdfKeyWrapperV1's service name), not to any one wrapped payload, so
 * it can reveal any number of different files' DEKs (see IKeyWrapper). Each registered file gets
 * its own ICryptoSessionProvider (minted by sessionProviderFactory, bound to that file's own
 * wrapped bytes) and becomes its own KeyWrappedDataEncryptionKey. withEphemeralKey registers a
 * version whose own key material is instead generated fresh in memory on first use (see
 * EphemeralDataEncryptionKey) - it shares the same IKeyWrapper/sessionProviderFactory, so no
 * extra configuration is needed for it.
 *
 * <p>getServiceName/getCachedKeyExpiry/getKeyRotationDays describe this ring's key
 * identity/policy - they're carried on the builder for callers to read back, but are not
 * consumed by build itself, since IKeyWrapper already knows what KEK it's bound to.
 */
public final class KeyRingBuilder {

    private final List<KeyFile> keyFiles = new ArrayList<>();
    private final List<Integer> ephemeralVersions = new ArrayList<>();

    private IKeyWrapper keyWrapper;
    private BiFunction<IKeyWrapper, byte[], ICryptoSessionProvider> sessionProviderFactory;
    private IEncryptedFormatProvider formatProvider = new DefaultFormatProvider();

    private String serviceName;
    private Integer cachedKeyExpiry;
    private Integer keyRotationDays;

    public String getServiceName() {
        return serviceName;
    }

    public Integer getCachedKeyExpiry() {
        return cachedKeyExpiry;
    }

    public Integer getKeyRotationDays() {
        return keyRotationDays;
    }

    /**
     * The service name identifying this ring's KEK to the native KMS library.
     */
    public KeyRingBuilder withServiceName(String serviceName) {
        this.serviceName = serviceName;
        return this;
    }

    /**
     * How many seconds a revealed key may be cached in memory before it must be re-derived.
     *
     * @throws IllegalArgumentException cachedKeyExpiry is not between 0 and 300
     */
    public KeyRingBuilder withCachedKeyExpiry(int cachedKeyExpiry) {
        if (cachedKeyExpiry < 0 || cachedKeyExpiry > 300) {
            throw new IllegalArgumentException(
                    "cachedKeyExpiry must be between 0 and 300 seconds, was " + cachedKeyExpiry + ".");
        }

        this.cachedKeyExpiry = cachedKeyExpiry;
        return this;
    }

    /**
     * How many days may pass before this ring's key must be rotated.
     *
     * @throws IllegalArgumentException keyRotationDays is not between 1 and 180
     */
    public KeyRingBuilder withKeyRotationDays(int keyRotationDays) {
        if (keyRotationDays < 1 || keyRotationDays > 180) {
            throw new IllegalArgumentException(
                    "keyRotationDays must be between 1 and 180 days, was " + keyRotationDays + ".");
        }

        this.keyRotationDays = keyRotationDays;
        return this;
    }

    /**
     * Supplies the IKeyWrapper shared by every registered key file when build runs.
     */
    public KeyRingBuilder withKeyWrapper(IKeyWrapper keyWrapper) {
        this.keyWrapper = keyWrapper;
        return this;
    }

    /**
     * Supplies the factory used to build each key file's own ICryptoSessionProvider, called once
     * per registered file with the shared IKeyWrapper and that file's own wrapped bytes - e.g.
     * {@code (kw, wrapped) -> new AesGcmCryptoSessionProvider(kw, wrapped, 60)}.
     */
    public KeyRingBuilder withSessionProviderFactory(BiFunction<IKeyWrapper, byte[], ICryptoSessionProvider> sessionProviderFactory) {
        this.sessionProviderFactory = sessionProviderFactory;
        return this;
    }

    /**
     * Overrides the IEncryptedFormatProvider the built KeyRing uses for createProtector. Defaults
     * to DefaultFormatProvider.
     */
    public KeyRingBuilder withFormatProvider(IEncryptedFormatProvider formatProvider) {
        this.formatProvider = formatProvider;
        return this;
    }

    /**
     * Registers a version whose wrapped DEK will be read from pathToFile when build runs. The
     * highest version registered across every withKeyFile call intrinsically becomes the built
     * KeyRing's current version.
     *
     * @param version The KeyRing version to register this key under
     * @param pathToFile Path to this version's wrapped DEK file
     */
    public KeyRingBuilder withKeyFile(int version, Path pathToFile) {
        keyFiles.add(new KeyFile(version, pathToFile));
        return this;
    }

    /**
     * Registers a version whose own key material is generated fresh in memory the first time
     * it's used, and never written to or read from disk (see EphemeralDataEncryptionKey). The
     * highest version registered across every withKeyFile/withEphemeralKey call intrinsically
     * becomes the built KeyRing's current version.
     *
     * @param version The KeyRing version to register this key under
     */
    public KeyRingBuilder withEphemeralKey(int version) {
        ephemeralVersions.add(version);
        return this;
    }

    /**
     * Reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
     * returns a populated KeyRing.
     *
     * @throws IllegalStateException No key wrapper, no session provider factory, or no key
     *     files/ephemeral keys were configured
     */
    public KeyRing build() {
        if (keyWrapper == null) {
            throw new IllegalStateException("A key wrapper is required - call withKeyWrapper first.");
        }
        if (sessionProviderFactory == null) {
            throw new IllegalStateException("A session provider factory is required - call withSessionProviderFactory first.");
        }
        if (keyFiles.isEmpty() && ephemeralVersions.isEmpty()) {
            throw new IllegalStateException(
                    "At least one key file or ephemeral key is required - call withKeyFile or withEphemeralKey first.");
        }

        KeyRing ring = new KeyRing(formatProvider);

        for (KeyFile keyFile : keyFiles) {
            byte[] wrapped = readAllBytes(keyFile.path());
            ICryptoSessionProvider sessionProvider = sessionProviderFactory.apply(keyWrapper, wrapped);
            ring.add(keyFile.version(), new KeyWrappedDataEncryptionKey(sessionProvider));
        }

        for (int version : ephemeralVersions) {
            ring.add(version, new EphemeralDataEncryptionKey(keyWrapper, sessionProviderFactory));
        }

        return ring;
    }

    private static byte[] readAllBytes(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private record KeyFile(int version, Path path) {
    }
}
