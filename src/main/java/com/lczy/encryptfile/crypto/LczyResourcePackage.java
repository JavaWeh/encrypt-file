package com.lczy.encryptfile.crypto;

import java.util.Map;

/**
 * Fully decrypted LCZY package model.
 *
 * <p>Use this when all files are needed. For random access, prefer
 * {@link LczyResourceService#readFile(byte[], String)}.</p>
 *
 * @author JavaWeh
 */
public record LczyResourcePackage(
        LczyMetadata metadata,
        LczyManifest manifest,
        Map<String, byte[]> files
) {
}
