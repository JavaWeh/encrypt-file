package com.lczy.encryptfile.crypto;

import java.time.Instant;

/**
 * Outer LCZY container metadata. The metadata is intentionally small and may be
 * kept clear text; sensitive file names and offsets live in the encrypted index.
 *
 * @author JavaWeh
 */
public record LczyMetadata(
        String format,
        int version,
        String algorithm,
        Instant createdAt,
        int entryCount,
        int indexCipherLength,
        String keyId
) {

    public LczyMetadata(
            String format,
            int version,
            String algorithm,
            Instant createdAt,
            int entryCount,
            int indexCipherLength
    ) {
        this(format, version, algorithm, createdAt, entryCount, indexCipherLength, null);
    }
}
