package com.runsecure.hkdfguard.dataencryptionkey;

import com.runsecure.hkdfguard.abstractions.CryptoProvider;

/**
 * A DataEncryptionKey backed by one wrapped DEK payload. provider owns revealing that payload's
 * key (from a fresh unwrap, on its own internal refresh schedule) and performing the actual data
 * encrypt/decrypt with it - see CryptoProvider.
 */
public final class KeyWrappedDataEncryptionKeyImpl extends EncryptionKeyBase {

    public KeyWrappedDataEncryptionKeyImpl(CryptoProvider provider) {
        super(provider);
    }
}
