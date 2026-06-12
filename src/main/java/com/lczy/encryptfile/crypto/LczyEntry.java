package com.lczy.encryptfile.crypto;

/**
 * One manifest entry for an encrypted file block in the LCZY file data area.
 *
 * @param path normalized resource path
 * @param offset byte offset relative to the encrypted file data area
 * @param encryptedSize encrypted block size, including the GCM authentication tag
 * @param compressedSize file size after compression and before encryption
 * @param originalSize original file size before compression
 * @param sha256 SHA-256 digest of the original file bytes, encoded as lower-case hex
 * @param iv per-file AES-GCM IV
 * @author JavaWeh
 */
public record LczyEntry(
        String path,
        long offset,
        int encryptedSize,
        int compressedSize,
        long originalSize,
        String sha256,
        byte[] iv
) {
}
