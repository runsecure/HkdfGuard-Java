package com.runsecure.hkdfguard.cryptosession.aesgcm256;

/**
 * Thrown when GCM decryption's authentication tag doesn't match the given ciphertext or
 * associated data - meaning the ciphertext was tampered with, or the wrong key/nonce/AAD was
 * used. Unchecked, matching the C# original's use of the unchecked
 * {@code AuthenticationTagMismatchException}.
 */
public class AuthenticationTagMismatchException extends RuntimeException {

    public AuthenticationTagMismatchException(String message, Throwable cause) {
        super(message, cause);
    }
}
