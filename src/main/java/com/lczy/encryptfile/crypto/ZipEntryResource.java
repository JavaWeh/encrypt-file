package com.lczy.encryptfile.crypto;

/**
 * In-memory resource used when callers want to build an LCZY package directly
 * without first creating a ZIP archive.
 *
 * @author JavaWeh
 */
public record ZipEntryResource(String path, byte[] content) {
}
