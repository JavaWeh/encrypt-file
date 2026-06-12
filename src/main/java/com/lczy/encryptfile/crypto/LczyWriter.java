package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.ZipEntry;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;

/**
 * Streaming LCZY package writer.
 */
public class LczyWriter {

    private final ResourceKeyProvider keyProvider;
    private final ObjectMapper objectMapper;

    public LczyWriter(ResourceKeyProvider keyProvider) {
        this(keyProvider, defaultObjectMapper());
    }

    public LczyWriter(ResourceKeyProvider keyProvider, ObjectMapper objectMapper) {
        this.keyProvider = keyProvider;
        this.objectMapper = objectMapper;
    }

    public void writeZip(InputStream zipInput, OutputStream lczyOutput) {
        LczyEncryptProfiler profiler = LczyEncryptProfiler.start("writeZip");
        try (LczyZipInputStream zip = new LczyZipInputStream(zipInput, StandardCharsets.UTF_8)) {
            try (Session session = begin(lczyOutput, profiler)) {
                ZipEntry entry;
                while (true) {
                    long nextEntryStart = System.nanoTime();
                    entry = zip.getNextEntry();
                    profiler.addZipEntryScanNanos(System.nanoTime() - nextEntryStart);
                    if (entry == null) {
                        break;
                    }
                    if (!entry.isDirectory()) {
                        session.writeFile(entry.getName(), zip);
                    } else {
                        profiler.addDirectory();
                    }
                }
            }
            profiler.finishSuccess();
        } catch (IOException ex) {
            profiler.finishFailure(ex);
            throw new LczyException("Failed to write LCZY package from ZIP stream", ex);
        } catch (RuntimeException ex) {
            profiler.finishFailure(ex);
            throw ex;
        }
    }

    public void writeResources(List<ZipEntryResource> resources, OutputStream lczyOutput) {
        LczyEncryptProfiler profiler = LczyEncryptProfiler.start("writeResources");
        try {
            try (Session session = begin(lczyOutput, profiler)) {
                for (ZipEntryResource resource : resources) {
                    session.writeFile(resource.path(), new ByteArrayInputStream(resource.content()));
                }
            }
            profiler.finishSuccess();
        } catch (IOException ex) {
            profiler.finishFailure(ex);
            throw new LczyException("Failed to write LCZY package from resources", ex);
        } catch (RuntimeException ex) {
            profiler.finishFailure(ex);
            throw ex;
        }
    }

    public Session begin(OutputStream lczyOutput) throws IOException {
        return new Session(lczyOutput, LczyEncryptProfiler.start("session"), true);
    }

    private Session begin(OutputStream lczyOutput, LczyEncryptProfiler profiler) throws IOException {
        return new Session(lczyOutput, profiler, false);
    }

    public final class Session implements AutoCloseable {

        private final CountingOutputStream output;
        private final SecretKey key;
        private final String keyId;
        private final LczyAlgorithm algorithm;
        private final byte[] indexIv;
        private final long fileDataStart;
        private final LczyEncryptProfiler profiler;
        private final boolean finishProfilerOnClose;
        private final List<LczyEntry> entries = new ArrayList<>();
        private boolean closed;

        private Session(OutputStream lczyOutput, LczyEncryptProfiler profiler, boolean finishProfilerOnClose) throws IOException {
            this.profiler = profiler;
            this.finishProfilerOnClose = finishProfilerOnClose;
            this.output = new CountingOutputStream(lczyOutput);
            this.keyId = keyProvider.currentKeyId();
            this.key = keyProvider.getKey(keyId);
            this.algorithm = LczyAlgorithm.AES_256_GCM;
            this.indexIv = LczyCrypto.randomIv(algorithm);
            long headerStart = System.nanoTime();
            writeHeader();
            profiler.addHeaderNanos(System.nanoTime() - headerStart);
            this.fileDataStart = output.count();
        }

        public void writeFile(String path, InputStream plainInput) throws IOException {
            ensureOpen();
            String normalizedPath = normalizePath(path);
            boolean stored = storeWithoutCompression(normalizedPath);
            LczyEncryptProfiler.FileStats fileStats = profiler.beginFile(normalizedPath, stored);
            byte[] entryIv = LczyCrypto.randomIv(algorithm);
            long offset = output.count() - fileDataStart;
            CountingOutputStream encryptedCounter = new CountingOutputStream(new CloseShieldOutputStream(output));
            CipherOutputStream cipherOutput = new CipherOutputStream(
                    encryptedCounter,
                    LczyCrypto.encryptCipher(key, entryIv, algorithm)
            );
            CountingOutputStream compressedCounter = new CountingOutputStream(cipherOutput);
            MessageDigest digest = LczyDigest.sha256();

            long originalSize = 0;
            if (stored) {
                CountingOutputStream storedOutput = compressedCounter;
                try {
                    byte[] buffer = new byte[LczyFormat.BUFFER_SIZE];
                    int read;
                    while (true) {
                        long readStart = System.nanoTime();
                        read = plainInput.read(buffer);
                        fileStats.addRead(System.nanoTime() - readStart, read);
                        if (read == -1) {
                            break;
                        }
                        long digestStart = System.nanoTime();
                        digest.update(buffer, 0, read);
                        fileStats.addDigest(System.nanoTime() - digestStart);
                        long writeStart = System.nanoTime();
                        storedOutput.write(buffer, 0, read);
                        fileStats.addWrite(System.nanoTime() - writeStart);
                        fileStats.setOutputSizes(compressedCounter.count(), encryptedCounter.count());
                        originalSize += read;
                    }
                } finally {
                    long closeStart = System.nanoTime();
                    storedOutput.close();
                    fileStats.addClose(System.nanoTime() - closeStart);
                }
            } else {
                Deflater compressor = new Deflater(compressionLevel(normalizedPath));
                DeflaterOutputStream deflater = new DeflaterOutputStream(
                        compressedCounter,
                        compressor,
                        LczyFormat.BUFFER_SIZE
                );
                try {
                    byte[] buffer = new byte[LczyFormat.BUFFER_SIZE];
                    int read;
                    while (true) {
                        long readStart = System.nanoTime();
                        read = plainInput.read(buffer);
                        fileStats.addRead(System.nanoTime() - readStart, read);
                        if (read == -1) {
                            break;
                        }
                        long digestStart = System.nanoTime();
                        digest.update(buffer, 0, read);
                        fileStats.addDigest(System.nanoTime() - digestStart);
                        long writeStart = System.nanoTime();
                        deflater.write(buffer, 0, read);
                        fileStats.addWrite(System.nanoTime() - writeStart);
                        fileStats.setOutputSizes(compressedCounter.count(), encryptedCounter.count());
                        originalSize += read;
                    }
                } finally {
                    long closeStart = System.nanoTime();
                    try {
                        deflater.close();
                    } finally {
                        fileStats.addClose(System.nanoTime() - closeStart);
                        compressor.end();
                    }
                }
            }

            fileStats.setOutputSizes(compressedCounter.count(), encryptedCounter.count());
            profiler.finishFile(fileStats, originalSize, compressedCounter.count(), encryptedCounter.count());
            entries.add(new LczyEntry(
                    normalizedPath,
                    offset,
                    Math.toIntExact(encryptedCounter.count()),
                    Math.toIntExact(compressedCounter.count()),
                    originalSize,
                    LczyDigest.hex(digest),
                    entryIv
            ));
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            // v2 将加密索引写在文件尾部，读取端只需 Range 读取 footer 和索引区即可定位目标块。
            long indexOffset = output.count();
            LczyManifest manifest = new LczyManifest(LczyFormat.VERSION_2, algorithm.name(), List.copyOf(entries));
            long indexBuildStart = System.nanoTime();
            byte[] indexPlain = writeIndexBlock(manifest);
            profiler.addIndexBuildNanos(System.nanoTime() - indexBuildStart);
            long indexEncryptStart = System.nanoTime();
            byte[] indexCipher = LczyCrypto.encrypt(indexPlain, key, indexIv, algorithm);
            profiler.addIndexEncryptNanos(System.nanoTime() - indexEncryptStart);
            long indexWriteStart = System.nanoTime();
            output.write(indexCipher);
            profiler.addIndexWriteNanos(System.nanoTime() - indexWriteStart);
            long footerStart = System.nanoTime();
            writeFooter(indexOffset, indexCipher.length);
            profiler.addFooterWriteNanos(System.nanoTime() - footerStart);
            long flushStart = System.nanoTime();
            output.flush();
            profiler.addFlushNanos(System.nanoTime() - flushStart);
            if (finishProfilerOnClose) {
                profiler.finishSuccess();
            }
        }

        private void writeHeader() throws IOException {
            LczyMetadata metadata = new LczyMetadata(
                    "LCZY",
                    LczyFormat.VERSION_2,
                    algorithm.name(),
                    Instant.now(),
                    0,
                    0,
                    keyId
            );
            byte[] metaJson = writeJson(metadata);
            try (DataOutputStream data = new DataOutputStream(new CloseShieldOutputStream(output))) {
                data.write(LczyFormat.MAGIC);
                data.writeByte(LczyFormat.VERSION_2);
                data.writeByte(algorithm.id());
                data.writeByte(indexIv.length);
                data.write(indexIv);
                data.writeInt(metaJson.length);
                data.write(metaJson);
                data.flush();
            }
        }

        private void writeFooter(long indexOffset, int indexCipherLength) throws IOException {
            try (DataOutputStream data = new DataOutputStream(new CloseShieldOutputStream(output))) {
                data.writeLong(indexOffset);
                data.writeInt(indexCipherLength);
                data.write(LczyFormat.V2_FOOTER_MAGIC);
                data.flush();
            }
        }

        private void ensureOpen() {
            if (closed) {
                throw new LczyException("LCZY writer is already closed");
            }
        }
    }

    private byte[] writeIndexBlock(LczyManifest manifest) throws IOException {
        byte[] header = writeJson(new LczyMetadata(
                "LCZY-INDEX",
                LczyFormat.VERSION_2,
                manifest.algorithm(),
                Instant.now(),
                manifest.entries().size(),
                0,
                keyProvider.currentKeyId()
        ));
        byte[] manifestJson = writeJson(manifest);
        try (ByteArrayOutputStream output = new ByteArrayOutputStream();
             DataOutputStream data = new DataOutputStream(output)) {
            data.writeInt(header.length);
            data.write(header);
            data.writeInt(manifestJson.length);
            data.write(manifestJson);
            data.flush();
            return output.toByteArray();
        }
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

    private int compressionLevel(String path) {
        return Deflater.BEST_SPEED;
    }

    private boolean storeWithoutCompression(String path) {
        return FAST_STORE_EXTENSIONS.contains(extensionOf(path));
    }

    private String extensionOf(String path) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot <= slash || dot == path.length() - 1) {
            return "";
        }
        return path.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private byte[] writeJson(Object value) {
        try {
            return objectMapper.writeValueAsBytes(value);
        } catch (JsonProcessingException ex) {
            throw new LczyException("Failed to serialize LCZY JSON", ex);
        }
    }

    private static ObjectMapper defaultObjectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
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
}
