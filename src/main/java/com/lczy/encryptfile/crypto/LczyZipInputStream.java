package com.lczy.encryptfile.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;

final class LczyZipInputStream extends InputStream {

    private static final int LOCAL_FILE_HEADER = 0x04034b50;
    private static final int CENTRAL_DIRECTORY_HEADER = 0x02014b50;
    private static final int END_OF_CENTRAL_DIRECTORY = 0x06054b50;
    private static final int DATA_DESCRIPTOR = 0x08074b50;
    private static final int METHOD_STORED = 0;
    private static final int METHOD_DEFLATED = 8;
    private static final int FLAG_ENCRYPTED = 1;
    private static final int FLAG_DATA_DESCRIPTOR = 1 << 3;
    private static final int FLAG_UTF8 = 1 << 11;
    private static final long ZIP64_MAGIC = 0xffffffffL;

    private final PushbackInputStream input;
    private final Charset charset;
    private CurrentEntryInput current;
    private boolean closed;

    LczyZipInputStream(InputStream input, Charset charset) {
        this.input = new PushbackInputStream(input, LczyFormat.BUFFER_SIZE);
        this.charset = charset;
    }

    ZipEntry getNextEntry() throws IOException {
        ensureOpen();
        closeEntry();
        int signature = readSignature();
        if (signature == -1
                || signature == CENTRAL_DIRECTORY_HEADER
                || signature == END_OF_CENTRAL_DIRECTORY) {
            return null;
        }
        if (signature != LOCAL_FILE_HEADER) {
            throw new IOException("Invalid ZIP local file header");
        }

        byte[] fixed = readFully(26);
        int flags = u16(fixed, 2);
        int method = u16(fixed, 4);
        long compressedSize = u32(fixed, 14);
        long uncompressedSize = u32(fixed, 18);
        boolean zip64Descriptor = compressedSize == ZIP64_MAGIC || uncompressedSize == ZIP64_MAGIC;
        int nameLength = u16(fixed, 22);
        int extraLength = u16(fixed, 24);
        if ((flags & FLAG_ENCRYPTED) != 0) {
            throw new IOException("Encrypted ZIP entries are not supported");
        }

        byte[] nameBytes = readFully(nameLength);
        byte[] extra = readFully(extraLength);
        long[] zip64Sizes = zip64Sizes(extra, compressedSize, uncompressedSize);
        compressedSize = zip64Sizes[0];
        uncompressedSize = zip64Sizes[1];

        Charset entryCharset = (flags & FLAG_UTF8) != 0 ? StandardCharsets.UTF_8 : charset;
        ZipEntry entry = new ZipEntry(new String(nameBytes, entryCharset));
        entry.setMethod(method);
        if (compressedSize >= 0) {
            entry.setCompressedSize(compressedSize);
        }
        if (uncompressedSize >= 0) {
            entry.setSize(uncompressedSize);
        }

        boolean usesDescriptor = (flags & FLAG_DATA_DESCRIPTOR) != 0;
        if (method == METHOD_STORED) {
            if (compressedSize < 0) {
                throw new IOException("Stored ZIP entry is missing compressed size");
            }
            current = new StoredEntryInput(compressedSize, usesDescriptor, zip64Descriptor);
        } else if (method == METHOD_DEFLATED) {
            current = new DeflatedEntryInput(usesDescriptor, zip64Descriptor);
        } else {
            throw new IOException("Unsupported ZIP compression method: " + method);
        }
        return entry;
    }

    private void closeEntry() throws IOException {
        if (current == null) {
            return;
        }
        byte[] buffer = new byte[LczyFormat.BUFFER_SIZE];
        while (current.read(buffer, 0, buffer.length) != -1) {
            // Drain the current entry so the next local header is aligned.
        }
        current = null;
    }

    @Override
    public int read() throws IOException {
        byte[] one = new byte[1];
        int read = read(one, 0, 1);
        return read == -1 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        ensureOpen();
        if (current == null) {
            return -1;
        }
        return current.read(buffer, offset, length);
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        current = null;
        input.close();
    }

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("ZIP stream is closed");
        }
    }

    private int readSignature() throws IOException {
        byte[] bytes = new byte[4];
        int read = readMaybe(bytes, 0, bytes.length);
        if (read == -1) {
            return -1;
        }
        if (read != bytes.length) {
            throw new IOException("Unexpected end of ZIP stream");
        }
        return u32Int(bytes, 0);
    }

    private byte[] readFully(int length) throws IOException {
        byte[] bytes = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(bytes, offset, length - offset);
            if (read == -1) {
                throw new IOException("Unexpected end of ZIP stream");
            }
            offset += read;
        }
        return bytes;
    }

    private int readMaybe(byte[] bytes, int offset, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int read = input.read(bytes, offset + total, length - total);
            if (read == -1) {
                return total == 0 ? -1 : total;
            }
            total += read;
        }
        return total;
    }

    private void consumeDataDescriptor(boolean zip64) throws IOException {
        byte[] first = readFully(4);
        if (u32Int(first, 0) == DATA_DESCRIPTOR) {
            readFully(4);
        }
        int sizeBytes = zip64 ? Long.BYTES : Integer.BYTES;
        readFully(sizeBytes);
        readFully(sizeBytes);
    }

    private long[] zip64Sizes(byte[] extra, long compressedSize, long uncompressedSize) {
        int offset = 0;
        long resolvedCompressedSize = compressedSize == ZIP64_MAGIC ? -1 : compressedSize;
        long resolvedUncompressedSize = uncompressedSize == ZIP64_MAGIC ? -1 : uncompressedSize;
        while (offset + 4 <= extra.length) {
            int headerId = u16(extra, offset);
            int dataSize = u16(extra, offset + 2);
            offset += 4;
            if (offset + dataSize > extra.length) {
                break;
            }
            if (headerId == 0x0001) {
                int zip64Offset = offset;
                if (uncompressedSize == ZIP64_MAGIC && zip64Offset + Long.BYTES <= offset + dataSize) {
                    resolvedUncompressedSize = i64(extra, zip64Offset);
                    zip64Offset += Long.BYTES;
                }
                if (compressedSize == ZIP64_MAGIC && zip64Offset + Long.BYTES <= offset + dataSize) {
                    resolvedCompressedSize = i64(extra, zip64Offset);
                }
                break;
            }
            offset += dataSize;
        }
        return new long[] {resolvedCompressedSize, resolvedUncompressedSize};
    }

    private static int u16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static long u32(byte[] bytes, int offset) {
        return u32Int(bytes, offset) & 0xffffffffL;
    }

    private static int u32Int(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff)
                | ((bytes[offset + 1] & 0xff) << 8)
                | ((bytes[offset + 2] & 0xff) << 16)
                | ((bytes[offset + 3] & 0xff) << 24);
    }

    private static long i64(byte[] bytes, int offset) {
        return (bytes[offset] & 0xffL)
                | ((bytes[offset + 1] & 0xffL) << 8)
                | ((bytes[offset + 2] & 0xffL) << 16)
                | ((bytes[offset + 3] & 0xffL) << 24)
                | ((bytes[offset + 4] & 0xffL) << 32)
                | ((bytes[offset + 5] & 0xffL) << 40)
                | ((bytes[offset + 6] & 0xffL) << 48)
                | ((bytes[offset + 7] & 0xffL) << 56);
    }

    private abstract class CurrentEntryInput extends InputStream {

        private final boolean usesDescriptor;
        private final boolean zip64Descriptor;
        private boolean completed;

        private CurrentEntryInput(boolean usesDescriptor, boolean zip64Descriptor) {
            this.usesDescriptor = usesDescriptor;
            this.zip64Descriptor = zip64Descriptor;
        }

        @Override
        public final int read() throws IOException {
            byte[] one = new byte[1];
            int read = read(one, 0, 1);
            return read == -1 ? -1 : one[0] & 0xff;
        }

        @Override
        public final int read(byte[] buffer, int offset, int length) throws IOException {
            if (completed) {
                return -1;
            }
            if (length == 0) {
                return 0;
            }
            int read = readEntry(buffer, offset, length);
            if (read == -1) {
                complete();
            }
            return read;
        }

        protected abstract int readEntry(byte[] buffer, int offset, int length) throws IOException;

        protected void onComplete() throws IOException {
        }

        private void complete() throws IOException {
            if (completed) {
                return;
            }
            completed = true;
            onComplete();
            if (usesDescriptor) {
                consumeDataDescriptor(zip64Descriptor);
            }
        }
    }

    private final class StoredEntryInput extends CurrentEntryInput {

        private long remaining;

        private StoredEntryInput(long compressedSize, boolean usesDescriptor, boolean zip64Descriptor) {
            super(usesDescriptor, zip64Descriptor);
            this.remaining = compressedSize;
        }

        @Override
        protected int readEntry(byte[] buffer, int offset, int length) throws IOException {
            if (remaining == 0) {
                return -1;
            }
            int wanted = (int) Math.min(length, remaining);
            int read = input.read(buffer, offset, wanted);
            if (read == -1) {
                throw new IOException("Unexpected end of stored ZIP entry");
            }
            remaining -= read;
            return read;
        }
    }

    private final class DeflatedEntryInput extends CurrentEntryInput {

        private final Inflater inflater = new Inflater(true);
        private final byte[] inputBuffer = new byte[LczyFormat.BUFFER_SIZE];
        private int inputLength;

        private DeflatedEntryInput(boolean usesDescriptor, boolean zip64Descriptor) {
            super(usesDescriptor, zip64Descriptor);
        }

        @Override
        protected int readEntry(byte[] buffer, int offset, int length) throws IOException {
            try {
                while (true) {
                    int read = inflater.inflate(buffer, offset, length);
                    if (read > 0) {
                        return read;
                    }
                    if (inflater.finished()) {
                        unreadRemaining();
                        return -1;
                    }
                    if (inflater.needsDictionary()) {
                        throw new IOException("ZIP entry requires a preset dictionary");
                    }
                    if (inflater.needsInput()) {
                        fillInflater();
                    }
                }
            } catch (DataFormatException ex) {
                throw new IOException("Invalid deflated ZIP entry", ex);
            }
        }

        @Override
        protected void onComplete() {
            inflater.end();
        }

        private void fillInflater() throws IOException {
            int read = input.read(inputBuffer, 0, inputBuffer.length);
            if (read == -1) {
                throw new IOException("Unexpected end of deflated ZIP entry");
            }
            inputLength = read;
            inflater.setInput(inputBuffer, 0, read);
        }

        private void unreadRemaining() throws IOException {
            int remaining = inflater.getRemaining();
            if (remaining > 0) {
                input.unread(inputBuffer, inputLength - remaining, remaining);
            }
        }
    }
}
