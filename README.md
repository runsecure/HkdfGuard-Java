# HkdfGuard-Java

A TPM- and hardware-backed Key Derivation and Cryptographic Secrets Protection Library for Java (Java 17+), ported from the original C# HkdfGuard implementation.

HkdfGuard provides defense-in-depth protection for application secrets in memory, at rest, and during transit across data pipelines. By anchoring cryptographic keys to platform-native security hardware (such as TPM 2.0 on Windows and Linux, or Apple Secure Enclave on macOS), HkdfGuard ensures that root keys never live in process memory unencrypted.

---

## Key Features

- **Hardware-Rooted Security (TPM / Enclave)**: Binds cryptographic operations to OS/hardware KMS providers (Windows Platform Crypto Provider / TPM2, Linux TSS2 / TPM2, macOS Apple Secure Enclave).
- **Two-Tier Key Hierarchy (KEK / DEK)**: Uses hardware-protected Key Encryption Keys (KEKs) to wrap and unwrap Data Encryption Keys (DEKs).
- **Proactive In-Memory Key Rotation**: Background schedulers periodically refresh and re-unwrap DEKs before expiry, zeroing expired key material in memory.
- **Memory Safety & Wiping**: Designed to prevent sensitive strings from remaining in immutable `java.lang.String` pools by utilizing `char[]` and `byte[]` buffers with deterministic memory zeroing (`ArrayUtility.zeroMemory`).
- **AAD-Bound Purpose Separation**: Data protectors bind contextual purpose names as Additional Authenticated Data (AAD), mitigating cross-purpose cipher reuse and replay attacks.
- **Zero-Downtime Key Rotation**: `KeyRing` supports multiple key versions concurrently—new encryptions use the latest active key version while historic ciphertexts are automatically decrypted using their respective registered versions.
- **Protected In-Memory Cache**: Concurrent cache implementations (`ProtectedCacheImpl`) keep stored secrets encrypted in memory, decrypting them transiently only when accessed.
- **Observability & Diagnostics**: Built-in OpenTelemetry tracing, metrics, and SLF4J diagnostic logging with support for sensitive payload redaction.

---

## Architecture Overview

```
                      +------------------------------------------+
                      | Hardware Security Module (TPM / Enclave) |
                      +------------------------------------------+
                                           |
                                  (Wraps / Unwraps)
                                           v
+---------------------+       +---------------------------+
| Native KMS Library  | <---> |   KeyWrapper (NativeHost) |
+---------------------+       +---------------------------+
                                           |
                                  (Provides DEK)
                                           v
                              +---------------------------+
                              |       CryptoProvider      |  <-- Scheduled session refresh
                              | (AesGcmCryptoProviderImpl)|      & proactive key zeroing
                              +---------------------------+
                                           |
                                   (AEAD Encrypt/Decrypt)
                                           v
                              +---------------------------+
                              |     DataProtectionKey     |
                              | (KeyWrapped / Ephemeral)  |
                              +---------------------------+
                                           |
                               (Version Management / AAD)
                                           v
               +-------------------------------------------------------+
               |                       KeyRing                         |
               +-------------------------------------------------------+
                        /                                     \
                       v                                       v
        +-----------------------------+         +-----------------------------+
        |        DataProtector        |         |       ProtectedCache        |
        | (Strings / Char Buffers)    |         | (Encrypted In-Memory Cache) |
        +-----------------------------+         +-----------------------------+
```

### Key Concepts

1. **KEK (Key Encryption Key)**: A hardware-backed key managed by the OS/TPM, referenced by a service name. The plaintext KEK never enters userland Java memory.
2. **DEK (Data Encryption Key)**: A 256-bit symmetric key wrapped by the KEK. DEKs can be persisted to disk, generated ephemerally in memory, or initialized via pipeline utilities.
3. **CryptoSession / CryptoProvider**: Active AEAD (AES-256-GCM) cipher session holding the unwrapped DEK. Automatically rotates and wipes expired sessions on a configured schedule (1–300 seconds).
4. **KeyRing**: Manages multiple versioned keys. Supports adding new key versions over time without breaking decryption of previously protected data.
5. **Formatted Encrypted Value**: Standardized string serialization format (`enc::v<version>::<base64-ciphertext>`), handled by `EncryptedFormatProvider`.

---

## Module Breakdown

The project is structured as a Maven multi-module repository:

| Module                                  | Description                                                                                                                                                                                            |
|:----------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`hkdfguard-abstractions`**            | Core interfaces (`DataProtector`, `DataProtectionKey`, `CryptoProvider`, `KeyWrapper`, `ProtectedCache`, `EncryptedFormatProvider`) and utilities (`ArrayUtility`).                                 |
| **`hkdfguard-diagnostics`**             | OpenTelemetry tracing and metrics instrumentation, event constants, and SLF4J logging extensions.                                                                                                    |
| **`hkdfguard-keywrapping-v1`**          | JNA native bindings to platform KMS libraries (`WindowsHkdfGuardKmsLibrary`, `LinuxHkdfGuardKmsLibrary`, `MacOsHkdfGuardKmsLibrary`) through `NativeHost` and `NativeHkdfKeyWrapperV1Impl`.          |
| **`hkdfguard-cryptosession-aesgcm256`** | AES-256-GCM authenticated cipher session (`AesGcmCryptoSession`) and cached background-refresh provider (`AesGcmCryptoProviderImpl`).                                                                |
| **`hkdfguard-dataencryptionkey`**       | High-level data protection implementations: `KeyRing`, `KeyRingBuilder`, `DataProtectorImpl`, `EphemeralDataEncryptionKeyImpl`, `KeyWrappedDataEncryptionKeyImpl`, `PipelineDataEncryptionKeyImpl`, and default format providers. |
| **`hkdfguard-cache`**                   | Thread-safe, encrypted in-memory caches (`ProtectedCacheImpl`, `ProtectedCacheCollectionImpl`).                                                                                                      |

---

## Requirements

- **Java Runtime / SDK**: Java 17 or higher.
- **Build Tool**: Apache Maven 3.8+.
- **Native KMS Library**: Platform-specific native library (`HkdfGuard.Kms.dll`, `libHkdfGuard.Kms.so`, or `libHkdfGuard.Kms.dylib`) available in your system library path or JNA library path if using native hardware key wrapping.

---

## Quickstart & Usage Examples

### 1. Building a `KeyRing` and Protecting Data

```
import com.runsecure.hkdfguard.abstractions.DataProtector;
import com.runsecure.hkdfguard.abstractions.KeyWrapper;
import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.KeyRing;
import com.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import com.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;

import java.nio.file.Path;
import java.util.Arrays;

public class Example {
    public static void main(String[] args) {
        // 1. Initialize native key wrapper bound to your hardware service name
        KeyWrapper keyWrapper = new NativeHkdfKeyWrapperV1Impl("MyApplicationService");

        // 2. Build the KeyRing
        KeyRing keyRing = new KeyRingBuilder()
                .withServiceName("MyApplicationService")
                .withKeyWrapper(keyWrapper)
                .withSessionProviderFactory((kw, wrapped) -> new AesGcmCryptoProviderImpl(kw, wrapped, 60))
                .withKeyFile(1, Path.of("/etc/keys/app_v1.dek"))
                .withKeyFile(2, Path.of("/etc/keys/app_v2.dek"))
                .build();

        // 3. Create a purpose-bound DataProtector (AAD binding)
        DataProtector protector = keyRing.createProtector("DatabaseConnectionPassword");

        // 4. Encrypt sensitive plaintext
        char[] secret = "SuperSecretDatabasePassword123!".toCharArray();
        String encrypted = protector.encrypt(secret);
        ArrayUtility.zeroMemory(secret); // Wipe plaintext memory

        System.out.println("Encrypted format: " + encrypted);
        // Output format: enc::v2::...

        // 5. Decrypt into a caller-managed char buffer
        char[] encryptedChars = encrypted.toCharArray();
        int maxLen = protector.getMaxDecryptedLength(encryptedChars);
        char[] decrypted = new char[maxLen];

        try {
            int actualLen = protector.decrypt(encryptedChars, decrypted);
            char[] plaintextSecret = Arrays.copyOf(decrypted, actualLen);
            
            // Use decrypted secret...
            
            ArrayUtility.zeroMemory(plaintextSecret);
        } finally {
            ArrayUtility.zeroMemory(decrypted);
            ArrayUtility.zeroMemory(encryptedChars);
        }
    }
}
```

### 2. Using In-Memory `ProtectedCache`

```
import com.runsecure.hkdfguard.abstractions.DataProtectionKey;
import com.runsecure.hkdfguard.abstractions.ProtectedCache;
import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.cache.ProtectedCacheImpl;

public class CacheExample {
    public void run(DataProtectionKey protectionKey) {
        ProtectedCache cache = new ProtectedCacheImpl(protectionKey);

        // Secrets are encrypted immediately upon storage; plaintext is zeroed
        char[] token = "api-token-xyz-987".toCharArray();
        cache.add("payment-gateway-token", token);

        // Decrypt only on demand
        char[] buffer = new char[64];
        try {
            int len = cache.decrypt("payment-gateway-token", buffer);
            // Process transient secret...
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }
}
```

### 3. Pipeline Provisioning (`PipelineDataEncryptionKeyImpl`)

For bootstrapping or provisioning pipelines before a hardware KEK exists, `PipelineDataEncryptionKeyImpl` can encrypt secrets in-flight and export the raw DEK for later registration with the native KMS CLI:

```
import com.runsecure.hkdfguard.abstractions.ArrayUtility;
import com.runsecure.hkdfguard.cryptosession.aesgcm256.AesGcmCryptoProviderImpl;
import com.runsecure.hkdfguard.dataencryptionkey.PipelineDataEncryptionKeyImpl;

public class PipelineExample {
    public void run() {
        try (PipelineDataEncryptionKeyImpl pipelineKey = new PipelineDataEncryptionKeyImpl(
                (kw, wrapped) -> new AesGcmCryptoProviderImpl(kw, wrapped, 60))) {
            
            // Encrypt configuration or setup credentials
            byte[] ciphertext = pipelineKey.encrypt("initial-config".getBytes());

            // Export raw DEK at the end of the pipeline to wrap with KMS CLI
            byte[] rawDek = pipelineKey.asBytes();
            
            // Handoff rawDek to native initialize tool...
        } // pipelineKey automatically zeroes DEK memory on close
    }
}
```

---

## Telemetry & Diagnostics

HkdfGuard includes built-in OpenTelemetry instrumentation for operations across all modules.

- **Component Telemetry**: Rooted under `HkdfGuardTelemetry` (`ROOT`, `CACHE`, `DATA_PROTECTION`, `CRYPTO_SESSION_AES_GCM256`, `KEY_WRAPPING`).
- **Sensitive Data Redaction**: By default, sensitive attributes and operations are omitted or redacted in traces and logs unless explicitly enabled via `ComponentTelemetry.setEnableSensitiveLogging(true)`.
- **Metrics**: Standard cache hit/miss/operation metrics recorded via `CacheMetrics`.

---

## Building and Testing

### Build with Maven
```bash
mvn clean compile
```

### Run Unit Tests
```bash
mvn test
```

### Packaging JARs
```bash
mvn clean package
```

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
