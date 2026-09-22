package com.runsecure.hkdfguard.abstractions;

public record KeyTrackingValue(int keyVersion, byte[] value) {
}
