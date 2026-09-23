package com.runsecure.hkdfguard.dataencryptionkey.formatprovider;

import com.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import com.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import com.runsecure.hkdfguard.dataencryptionkey.utilities.Base64ConversionUtility;
import com.runsecure.hkdfguard.diagnostics.ActivityNames;
import com.runsecure.hkdfguard.diagnostics.AttributeNames;
import com.runsecure.hkdfguard.diagnostics.ComponentTelemetry;
import com.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.opentelemetry.api.trace.Span;

public class DefaultFormatProviderImpl implements EncryptedFormatProvider {

    private static final String ENC_PREFIX = "enc";
    private static final String DELIMITER = "::";
    private static final String VERSION_PREFIX = "v";

    @Override
    public String format(KeyTrackingValue value) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.FORMAT_PROVIDER_FORMAT).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.FORMAT_PROVIDER_FORMAT,
                        ComponentTelemetry.Detail.of(AttributeNames.KEY_VERSION, value.keyVersion()),
                        ComponentTelemetry.Detail.of(AttributeNames.VALUE_LENGTH, value.value().length));
            }

            String base64 = Base64ConversionUtility.toBase64String(value.value());
            return ENC_PREFIX + DELIMITER + VERSION_PREFIX + value.keyVersion() + DELIMITER + base64;
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public KeyTrackingValue parse(char[] encrypted) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer().spanBuilder(ActivityNames.DataProtection.FORMAT_PROVIDER_PARSE).startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.FORMAT_PROVIDER_PARSE,
                        ComponentTelemetry.Detail.of(AttributeNames.ENCRYPTED_LENGTH, encrypted.length));
            }

            Segments segments = parseSegments(new String(encrypted));

            if (!Base64ConversionUtility.isBase64(segments.base64())) {
                throw new IllegalArgumentException("Encrypted value is not valid base64.");
            }

            byte[] value = new byte[Base64ConversionUtility.getBinaryLength(segments.base64())];
            Base64ConversionUtility.fromBase64(segments.base64(), value);

            return new KeyTrackingValue(segments.version(), value);
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    @Override
    public int getMaxDecryptedLength(char[] encrypted) {
        ComponentTelemetry telemetry = HkdfGuardTelemetry.DATA_PROTECTION;
        Span span = telemetry.getTracer()
                .spanBuilder(ActivityNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH)
                .startSpan();
        try {
            if (telemetry.isEnableSensitiveLogging()) {
                telemetry.logSensitiveOperation(span, ActivityNames.DataProtection.FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH,
                        ComponentTelemetry.Detail.of(AttributeNames.ENCRYPTED_LENGTH, encrypted.length));
            }

            Segments segments = parseSegments(new String(encrypted));

            if (!Base64ConversionUtility.isBase64(segments.base64())) {
                throw new IllegalArgumentException("Encrypted value is not valid base64.");
            }

            return Base64ConversionUtility.getBinaryLength(segments.base64());
        } catch (RuntimeException ex) {
            telemetry.recordException(span, ex);
            throw ex;
        } finally {
            span.end();
        }
    }

    // Shared by parse and getMaxDecryptedLength so both agree on exactly what counts as
    // well-formed - only getMaxDecryptedLength skips the actual base64 decode/allocation.
    private static Segments parseSegments(String encrypted) {
        int firstDelimiterIndex = encrypted.indexOf(DELIMITER);
        if (firstDelimiterIndex < 0) {
            throw malformed();
        }

        String afterPrefix = encrypted.substring(firstDelimiterIndex + DELIMITER.length());
        int secondDelimiterIndex = afterPrefix.indexOf(DELIMITER);
        if (secondDelimiterIndex < 0) {
            throw malformed();
        }

        String prefix = encrypted.substring(0, firstDelimiterIndex);
        String versionSegment = afterPrefix.substring(0, secondDelimiterIndex);
        String base64Segment = afterPrefix.substring(secondDelimiterIndex + DELIMITER.length());

        if (!prefix.equals(ENC_PREFIX) || !versionSegment.startsWith(VERSION_PREFIX)) {
            throw malformed();
        }

        int version;
        try {
            version = Integer.parseInt(versionSegment.substring(VERSION_PREFIX.length()));
        } catch (NumberFormatException e) {
            throw malformed();
        }

        return new Segments(version, base64Segment);
    }

    private static IllegalArgumentException malformed() {
        return new IllegalArgumentException("Invalid encrypted format. Expected '"
                + ENC_PREFIX + DELIMITER + VERSION_PREFIX + "<version>" + DELIMITER + "<base64>'.");
    }

    private record Segments(int version, String base64) {
    }
}
