package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;
import com.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import com.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a KeyRing from wrapped-DEK files on disk, suitable for registering as a singleton in a
 * DI container at startup. There is one KeyWrapper shared by every registered file - it's bound
 * only to a KEK (e.g. NativeHkdfKeyWrapperV1Impl's service name), not to any one wrapped payload, so
 * it can reveal any number of different files' DEKs (see KeyWrapper). Each registered file gets
 * its own CryptoProvider (minted by the configured CryptoProviderFactory, bound to that file's
 * own wrapped bytes) and becomes its own KeyWrappedDataEncryptionKeyImpl. withEphemeralKey
 * registers a version whose own key material is instead generated fresh in memory on first use
 * (via CryptoProviderFactory.createEphemeral) - it shares the same
 * KeyWrapper/CryptoProviderFactory, so no extra configuration is needed for it.
 *
 * <p>getServiceName/getCachedKeyExpiry/getKeyRotationDays describe this ring's key
 * identity/policy - they're carried on the builder for callers to read back, but only
 * cachedKeyExpiry is consumed by build itself (as every provider's refresh interval), since
 * KeyWrapper already knows what KEK it's bound to.
 */
public final class KeyRingBuilder {

    private final List<KeyFile> keyFiles = new ArrayList<>();
    private final List<Integer> ephemeralVersions = new ArrayList<>();

    private KeyWrapper keyWrapper;
    private CryptoProviderFactory cryptoProviderFactory;
    private EncryptedFormatProvider formatProvider = new DefaultFormatProviderImpl();

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
     * Supplies the KeyWrapper shared by every registered key file when build runs.
     */
    public KeyRingBuilder withKeyWrapper(KeyWrapper keyWrapper) {
        this.keyWrapper = keyWrapper;
        return this;
    }

    /**
     * Supplies the factory used to build each key file's own CryptoProvider, called once per
     * registered file with the shared KeyWrapper and that file's own wrapped bytes.
     */
    public KeyRingBuilder withCryptoProviderFactory(CryptoProviderFactory cryptoProviderFactory) {
        this.cryptoProviderFactory = cryptoProviderFactory;
        return this;
    }

    /**
     * Overrides the EncryptedFormatProvider the built KeyRing uses for createProtector. Defaults
     * to DefaultFormatProviderImpl.
     */
    public KeyRingBuilder withFormatProvider(EncryptedFormatProvider formatProvider) {
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
     * it's used, and never written to or read from disk. The highest version registered across
     * every withKeyFile/withEphemeralKey call intrinsically becomes the built KeyRing's current
     * version.
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
     * @throws IllegalStateException No key wrapper, no crypto provider factory, no key
     *     files/ephemeral keys, or no cached key expiry were configured
     */
    public KeyRing build() {
        if (keyWrapper == null) {
            throw new IllegalStateException("A key wrapper is required - call withKeyWrapper first.");
        }
        if (cryptoProviderFactory == null) {
            throw new IllegalStateException("A crypto provider factory is required - call withCryptoProviderFactory first.");
        }
        if (keyFiles.isEmpty() && ephemeralVersions.isEmpty()) {
            throw new IllegalStateException(
                    "At least one key file or ephemeral key is required - call withKeyFile or withEphemeralKey first.");
        }
        if (cachedKeyExpiry == null) {
            throw new IllegalStateException("A cached key expiry is required - call withCachedKeyExpiry first.");
        }

        KeyRing ring = new KeyRing(formatProvider);

        for (KeyFile keyFile : keyFiles) {
            byte[] wrapped = readAllBytes(keyFile.path());
            CryptoProvider provider = cryptoProviderFactory.create(keyWrapper, wrapped, cachedKeyExpiry);
            ring.add(keyFile.version(), new KeyWrappedDataEncryptionKeyImpl(provider));
        }

        for (int version : ephemeralVersions) {
            CryptoProvider provider = cryptoProviderFactory.createEphemeral(keyWrapper, cachedKeyExpiry);
            ring.add(version, new KeyWrappedDataEncryptionKeyImpl(provider));
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
