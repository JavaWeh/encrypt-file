package com.lczy.encryptfile.crypto;

import java.io.IOException;
import java.io.InputStream;

/**
 * Random range access for LCZY packages stored outside the local filesystem,
 * such as object storage Range GET.
 */
public interface LczyRangeSource {

    int DEFAULT_RANGE_CHUNK_SIZE = 64 * 1024;

    long size() throws IOException;

    byte[] read(long position, int length) throws IOException;

    default InputStream openStream(long position, long length) throws IOException {
        if (position < 0 || length < 0) {
            throw new IOException("Invalid LCZY byte range");
        }
        return new InputStream() {
            private long remaining = length;
            private long cursor = position;
            private byte[] chunk = new byte[0];
            private int chunkOffset;
            private int chunkLength;

            @Override
            public int read() throws IOException {
                if (!ensureChunk()) {
                    return -1;
                }
                return chunk[chunkOffset++] & 0xff;
            }

            @Override
            public int read(byte[] buffer, int offset, int length) throws IOException {
                if (buffer == null) {
                    throw new NullPointerException("buffer");
                }
                if (offset < 0 || length < 0 || length > buffer.length - offset) {
                    throw new IndexOutOfBoundsException();
                }
                if (length == 0) {
                    return 0;
                }
                int total = 0;
                while (length > 0) {
                    if (!ensureChunk()) {
                        break;
                    }
                    int copied = Math.min(length, chunkLength - chunkOffset);
                    System.arraycopy(chunk, chunkOffset, buffer, offset, copied);
                    chunkOffset += copied;
                    offset += copied;
                    length -= copied;
                    total += copied;
                }
                return total == 0 ? -1 : total;
            }

            private boolean ensureChunk() throws IOException {
                if (chunkOffset < chunkLength) {
                    return true;
                }
                if (remaining == 0) {
                    return false;
                }
                int wanted = (int) Math.min(DEFAULT_RANGE_CHUNK_SIZE, remaining);
                chunk = LczyRangeSource.this.read(cursor, wanted);
                if (chunk.length != wanted) {
                    throw new IOException("Unexpected end of LCZY range");
                }
                cursor += wanted;
                remaining -= wanted;
                chunkOffset = 0;
                chunkLength = wanted;
                return true;
            }
        };
    }
}
