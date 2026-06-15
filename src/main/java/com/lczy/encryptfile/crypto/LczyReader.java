package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.security.GeneralSecurityException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Random access LCZY reader backed by seekable channels or object-storage ranges.
 */
public class LczyReader {

    private final LczyRangeSource source;
    private final ResourceKeyProvider keyProvider;
    private final ObjectMapper objectMapper;
    private final Header header;
    private final Footer footer;
    private LczyManifest manifest;

    public LczyReader(SeekableByteChannel channel, ResourceKeyProvider keyProvider) {
        this(new SeekableChannelRangeSource(channel), keyProvider);
    }

    public LczyReader(LczyRangeSource source, ResourceKeyProvider keyProvider) {
        this(source, keyProvider, defaultObjectMapper());
    }

    public LczyReader(LczyRangeSource source, ResourceKeyProvider keyProvider, ObjectMapper objectMapper) {
        try {
            this.source = source;
            this.keyProvider = keyProvider;
            this.objectMapper = objectMapper;
            this.header = readHeader();
            if (header.version() != LczyFormat.VERSION_2) {
                throw new LczyException("LczyReader supports LCZY v2 random access packages only");
            }
            this.footer = readFooter();
        } catch (IOException ex) {
            throw new LczyException("Failed to open LCZY reader", ex);
        }
    }

    public LczyMetadata metadata() {
        return header.metadata();
    }

    public LczyManifest manifest() {
        if (manifest == null) {
            manifest = readManifest();
        }
        return manifest;
    }

    public byte[] readFile(String path) {
        return readFile(manifest().requireEntry(normalizePath(path)));
    }

    byte[] readFile(LczyEntry entry) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            readFile(entry, output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to read LCZY entry: " + entry.path(), ex);
        }
    }

    public void readFile(String path, OutputStream output) {
        readFile(manifest().requireEntry(normalizePath(path)), output);
    }

    void readFile(LczyEntry entry, OutputStream output) {
        try {
            // 根据 manifest 中的相对 offset 定位单个加密块，不需要顺序扫描整个 LCZY 文件。
            long blockPosition = header.fileDataStart() + entry.offset();
            SecretKey key = keyProvider.getKey(header.metadata().keyId());
            MessageDigest digest = LczyDigest.sha256();
            DigestOutputStream digestOutput = new DigestOutputStream(output, digest);
            try (InputStream encryptedInput = source.openStream(blockPosition, entry.encryptedSize());
                 InputStream plainInput = new DecryptingInputStream(
                         encryptedInput,
                         LczyCrypto.decryptCipher(key, entry.iv(), header.algorithm())
                 )) {
                if (storedWithoutCompression(entry)) {
                    plainInput.transferTo(digestOutput);
                } else {
                    LczyCompression.inflate(plainInput, digestOutput);
                }
            }
            LczyDigest.verify(entry.sha256(), digest, entry.path());
        } catch (IOException ex) {
            throw new LczyException("Failed to read LCZY entry: " + entry.path(), ex);
        }
    }

    private LczyManifest readManifest() {
        try {
            byte[] indexCipher = source.read(footer.indexOffset(), footer.indexCipherLength());
            SecretKey key = keyProvider.getKey(header.metadata().keyId());
            byte[] indexPlain = LczyCrypto.decrypt(indexCipher, key, header.indexIv(), header.algorithm());
            try (DataInputStream inner = new DataInputStream(new ByteArrayInputStream(indexPlain))) {
                int headerLength = inner.readInt();
                inner.skipNBytes(headerLength);
                int manifestLength = inner.readInt();
                return readJson(inner.readNBytes(manifestLength), LczyManifest.class);
            }
        } catch (IOException ex) {
            throw new LczyException("Failed to read LCZY manifest", ex);
        }
    }

    private Header readHeader() throws IOException {
        byte[] fixed = source.read(0, LczyFormat.MAGIC.length + 3);
        byte[] magic = Arrays.copyOfRange(fixed, 0, LczyFormat.MAGIC.length);
        if (!Arrays.equals(LczyFormat.MAGIC, magic)) {
            throw new LczyException("Invalid LCZY magic");
        }
        int version = fixed[4] & 0xff;
        LczyAlgorithm algorithm = LczyAlgorithm.fromId(fixed[5]);
        int ivLength = fixed[6] & 0xff;
        byte[] rest = source.read(fixed.length, ivLength + Integer.BYTES);
        byte[] indexIv = Arrays.copyOfRange(rest, 0, ivLength);
        int metaLength = ByteBuffer.wrap(rest, ivLength, Integer.BYTES).getInt();
        if (ivLength != algorithm.ivLength() || metaLength < 0) {
            throw new LczyException("Invalid LCZY header");
        }
        byte[] metaJson = source.read(fixed.length + rest.length, metaLength);
        LczyMetadata metadata = readJson(metaJson, LczyMetadata.class);
        long fileDataStart = fixed.length + rest.length + metaLength;
        return new Header(version, algorithm, indexIv, metadata, fileDataStart);
    }

    private Footer readFooter() throws IOException {
        long size = source.size();
        if (size < LczyFormat.V2_FOOTER_LENGTH) {
            throw new LczyException("Invalid LCZY v2 footer");
        }
        // footer 固定长度，适合本地 seek 或对象存储 Range GET 直接从文件尾读取。
        byte[] footerBytes = source.read(size - LczyFormat.V2_FOOTER_LENGTH, LczyFormat.V2_FOOTER_LENGTH);
        ByteBuffer buffer = ByteBuffer.wrap(footerBytes);
        long indexOffset = buffer.getLong();
        int indexCipherLength = buffer.getInt();
        byte[] magic = new byte[LczyFormat.V2_FOOTER_MAGIC.length];
        buffer.get(magic);
        if (!Arrays.equals(LczyFormat.V2_FOOTER_MAGIC, magic) || indexOffset < header.fileDataStart() || indexCipherLength <= 0) {
            throw new LczyException("Invalid LCZY v2 footer");
        }
        return new Footer(indexOffset, indexCipherLength);
    }

    private String normalizePath(String path) {
        String normalized = path.replace('\\', '/');
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isBlank() || normalized.contains("../") || normalized.equals("..") || normalized.startsWith("../")) {
            throw new LczyException("Unsafe resource path: " + path);
        }
        return normalized;
    }

    private boolean storedWithoutCompression(LczyEntry entry) {
        return entry.compressedSize() == entry.originalSize()
                && FAST_STORE_EXTENSIONS.contains(extensionOf(entry.path()));
    }

    private String extensionOf(String path) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot <= slash || dot == path.length() - 1) {
            return "";
        }
        return path.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private <T> T readJson(byte[] value, Class<T> type) {
        try {
            return objectMapper.readValue(value, type);
        } catch (IOException ex) {
            throw new LczyException("Failed to parse LCZY JSON", ex);
        }
    }

    private static ObjectMapper defaultObjectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private record Header(int version, LczyAlgorithm algorithm, byte[] indexIv, LczyMetadata metadata, long fileDataStart) {
    }

    private record Footer(long indexOffset, int indexCipherLength) {
    }

    private static final class DecryptingInputStream extends InputStream {

        private static final byte[] EMPTY = new byte[0];

        private final InputStream input;
        private final Cipher cipher;
        private final byte[] encryptedBuffer = new byte[LczyRangeSource.DEFAULT_RANGE_CHUNK_SIZE];
        private byte[] plainBuffer = EMPTY;
        private int plainOffset;
        private boolean finalBlockRead;

        private DecryptingInputStream(InputStream input, Cipher cipher) {
            this.input = input;
            this.cipher = cipher;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int read = read(one, 0, 1);
            return read == -1 ? -1 : one[0] & 0xff;
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
                if (!ensurePlainBuffer()) {
                    break;
                }
                int copied = Math.min(length, plainBuffer.length - plainOffset);
                System.arraycopy(plainBuffer, plainOffset, buffer, offset, copied);
                plainOffset += copied;
                offset += copied;
                length -= copied;
                total += copied;
            }
            return total == 0 ? -1 : total;
        }

        @Override
        public void close() throws IOException {
            input.close();
        }

        private boolean ensurePlainBuffer() throws IOException {
            while (plainOffset == plainBuffer.length) {
                if (finalBlockRead) {
                    return false;
                }
                int read = input.read(encryptedBuffer);
                try {
                    if (read == -1) {
                        finalBlockRead = true;
                        plainBuffer = bytesOrEmpty(cipher.doFinal());
                    } else {
                        plainBuffer = bytesOrEmpty(cipher.update(encryptedBuffer, 0, read));
                    }
                } catch (GeneralSecurityException ex) {
                    throw new IOException("LCZY AES-GCM decrypt stream failed", ex);
                }
                plainOffset = 0;
            }
            return true;
        }

        private byte[] bytesOrEmpty(byte[] bytes) {
            return bytes == null ? EMPTY : bytes;
        }
    }

    private static final Set<String> FAST_STORE_EXTENSIONS = Set.of(
            "7z",
            "aac",
            "avi",
            "basis",
            "bin",
            "br",
            "bundle",
            "data",
            "dds",
            "fbx",
            "gif",
            "glb",
            "gz",
            "jpeg",
            "jpg",
            "ktx",
            "ktx2",
            "m4a",
            "mesh",
            "mov",
            "mp3",
            "mp4",
            "ogg",
            "png",
            "rar",
            "usdz",
            "unityweb",
            "webm",
            "webp",
            "wasm",
            "zip"
    );

    private static final class SeekableChannelRangeSource implements LczyRangeSource {

        private final SeekableByteChannel channel;

        private SeekableChannelRangeSource(SeekableByteChannel channel) {
            this.channel = channel;
        }

        @Override
        public long size() throws IOException {
            return channel.size();
        }

        @Override
        public byte[] read(long position, int length) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(length);
            channel.position(position);
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) == -1) {
                    throw new IOException("Unexpected end of LCZY channel");
                }
            }
            return buffer.array();
        }
    }
}
