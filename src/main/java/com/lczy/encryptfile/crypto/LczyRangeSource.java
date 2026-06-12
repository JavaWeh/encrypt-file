package com.lczy.encryptfile.crypto;

import java.io.IOException;

/**
 * Random range access for LCZY packages stored outside the local filesystem,
 * such as object storage Range GET.
 */
public interface LczyRangeSource {

    long size() throws IOException;

    byte[] read(long position, int length) throws IOException;
}
