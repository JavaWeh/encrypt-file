package com.lczy.encryptfile.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class LczyResourceServiceTests {

    private final LczyResourceService service = new LczyResourceService(
            () -> new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES")
    );

    @Test
    void encryptZipDecryptsBackToZip() throws Exception {
        byte[] zip = zipOf(Map.of(
                "docs/readme.txt", "hello LCZY".getBytes(StandardCharsets.UTF_8),
                "assets/config.json", "{\"enabled\":true}".getBytes(StandardCharsets.UTF_8)
        ));

        ByteArrayOutputStream lczyOutput = new ByteArrayOutputStream();
        service.encryptZip(new ByteArrayInputStream(zip), lczyOutput);
        byte[] lczy = lczyOutput.toByteArray();
        ByteArrayOutputStream decryptedZipOutput = new ByteArrayOutputStream();
        service.decryptToZip(lczy, decryptedZipOutput);
        byte[] decryptedZip = decryptedZipOutput.toByteArray();

        assertThat(new String(lczy, 0, 4, StandardCharsets.US_ASCII)).isEqualTo("LCZY");
        assertThat(unzip(decryptedZip)).containsAllEntriesOf(unzip(zip));
        assertThat(Arrays.equals(zip, lczy)).isFalse();
    }

    @Test
    void readsSingleFileByManifestOffset() {
        byte[] zip = zipOf(Map.of(
                "docs/readme.txt", "first file".getBytes(StandardCharsets.UTF_8),
                "image/raw.bin", new byte[] {1, 2, 3, 4, 5}
        ));

        byte[] lczy = service.encryptZip(zip);
        LczyManifest manifest = service.readManifest(lczy);

        assertThat(manifest.entries()).hasSize(2);
        assertThat(manifest.version()).isEqualTo(2);
        assertThat(manifest.entries())
                .allSatisfy(entry -> {
                    assertThat(entry.offset()).isGreaterThanOrEqualTo(0);
                    assertThat(entry.encryptedSize()).isPositive();
                    assertThat(entry.sha256()).hasSize(64);
                    assertThat(entry.iv()).hasSize(12);
                });
        assertThat(manifest.requireEntry("image/raw.bin").sha256())
                .isEqualTo(LczyDigest.sha256Hex(new byte[] {1, 2, 3, 4, 5}));
        assertThat(service.readFile(lczy, "image/raw.bin")).containsExactly(1, 2, 3, 4, 5);
    }

    @Test
    void storesPreviewAssetsWithoutDeflater() {
        byte[] data = randomBytes(32 * 1024, 10);
        byte[] unityweb = randomBytes(32 * 1024, 11);
        byte[] wasm = randomBytes(32 * 1024, 12);
        byte[] bundle = randomBytes(32 * 1024, 13);
        byte[] bin = randomBytes(32 * 1024, 14);
        byte[] png = randomBytes(32 * 1024, 15);
        byte[] ktx2 = randomBytes(32 * 1024, 16);
        byte[] lczy = service.encryptZip(zipOf(Map.of(
                "Build/app.data", data,
                "Build/app.unityweb", unityweb,
                "Build/app.wasm", wasm,
                "Build/app.bundle", bundle,
                "Build/app.bin", bin,
                "Textures/albedo.png", png,
                "Textures/albedo.ktx2", ktx2
        )));

        LczyManifest manifest = service.readManifest(lczy);

        assertThat(manifest.entries())
                .allSatisfy(entry -> {
                    assertThat(entry.compressedSize()).isEqualTo(entry.originalSize());
                    assertThat(entry.encryptedSize()).isEqualTo(entry.compressedSize() + 16);
                });
        assertThat(service.readFile(lczy, "Build/app.data")).isEqualTo(data);
        assertThat(service.readFile(lczy, "Build/app.unityweb")).isEqualTo(unityweb);
        assertThat(service.readFile(lczy, "Build/app.wasm")).isEqualTo(wasm);
        assertThat(service.readFile(lczy, "Build/app.bundle")).isEqualTo(bundle);
        assertThat(service.readFile(lczy, "Build/app.bin")).isEqualTo(bin);
        assertThat(service.readFile(lczy, "Textures/albedo.png")).isEqualTo(png);
        assertThat(service.readFile(lczy, "Textures/albedo.ktx2")).isEqualTo(ktx2);
    }

    @Test
    void compressesTextResourcesForPreviewSpeed() {
        byte[] text = "position,rotation,scale\n".repeat(4096).getBytes(StandardCharsets.UTF_8);
        byte[] lczy = service.encryptZip(zipOf(Map.of(
                "Build/catalog.json", text
        )));

        LczyEntry entry = service.readManifest(lczy).requireEntry("Build/catalog.json");

        assertThat(entry.compressedSize()).isLessThan((int) entry.originalSize());
        assertThat(service.readFile(lczy, "Build/catalog.json")).isEqualTo(text);
    }

    @Test
    void rejectsDigestMismatchAfterDecrypting() {
        MessageDigest digest = LczyDigest.sha256();
        digest.update("actual".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> LczyDigest.verify(
                LczyDigest.sha256Hex("expected".getBytes(StandardCharsets.UTF_8)),
                digest,
                "docs/readme.txt"
        ))
                .isInstanceOf(LczyException.class)
                .hasMessageContaining("SHA-256 mismatch")
                .hasMessageContaining("docs/readme.txt");
    }

    @Test
    void dispatchesParsingToFormatReaderByVersion() {
        byte[] futurePackage = new byte[] {'L', 'C', 'Z', 'Y', 99};
        LczyResourceService futureService = new LczyResourceService(
                serviceKeyProvider(),
                new com.fasterxml.jackson.databind.ObjectMapper(),
                List.of(new FutureFormatReader())
        );

        LczyManifest manifest = futureService.readManifest(futurePackage);

        assertThat(manifest.version()).isEqualTo(99);
    }

    @Test
    void writesKeyIdAndReadsWithHistoricalKey() {
        byte[] oldKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".getBytes(StandardCharsets.UTF_8);
        byte[] newKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".getBytes(StandardCharsets.UTF_8);
        RotatingKeyProvider encryptKeys = new RotatingKeyProvider("new-key", Map.of(
                "old-key", new SecretKeySpec(oldKey, "AES"),
                "new-key", new SecretKeySpec(newKey, "AES")
        ));
        LczyResourceService rotatingService = new LczyResourceService(encryptKeys);

        byte[] lczy = rotatingService.encryptZip(zipOf(Map.of(
                "docs/readme.txt", "new package".getBytes(StandardCharsets.UTF_8)
        )));
        LczyResourcePackage resourcePackage = rotatingService.decryptPackage(lczy);

        assertThat(resourcePackage.metadata().keyId()).isEqualTo("new-key");
        assertThat(rotatingService.readFile(lczy, "docs/readme.txt"))
                .isEqualTo("new package".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void rangeReaderReadsOnlyIndexAndTargetBlock() {
        byte[] first = randomBytes(128 * 1024, 1);
        byte[] second = randomBytes(128 * 1024, 2);
        byte[] lczy = service.encryptZip(zipOf(Map.of(
                "first.bin", first,
                "second.bin", second
        )));
        LczyEntry target = service.readManifest(lczy).requireEntry("second.bin");
        CountingRangeSource rangeSource = new CountingRangeSource(lczy);
        LczyReader reader = new LczyReader(rangeSource, serviceKeyProvider());

        assertThat(reader.readFile("second.bin")).isEqualTo(second);
        assertThat(rangeSource.requests()).isGreaterThanOrEqualTo(6);
        assertThat(rangeSource.maxReadLength()).isLessThan(target.encryptedSize());
        assertThat(rangeSource.bytesRead()).isLessThan(lczy.length);
    }

    @Test
    void rejectsWrongKeyDuringAuthentication() {
        byte[] lczy = service.encryptZip(zipOf(Map.of(
                "secret.txt", "sensitive".getBytes(StandardCharsets.UTF_8)
        )));
        LczyResourceService wrongKeyService = new LczyResourceService(
                () -> new SecretKeySpec("abcdef0123456789abcdef0123456789".getBytes(StandardCharsets.UTF_8), "AES")
        );

        assertThatThrownBy(() -> wrongKeyService.decryptPackage(lczy))
                .isInstanceOf(LczyException.class)
                .hasMessageContaining("AES-GCM");
    }

    private ResourceKeyProvider serviceKeyProvider() {
        return () -> new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES");
    }

    private byte[] randomBytes(int size, int seed) {
        byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    private byte[] zipOf(Map<String, byte[]> files) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream();
             ZipOutputStream zip = new ZipOutputStream(output, StandardCharsets.UTF_8)) {
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                zip.putNextEntry(new ZipEntry(file.getKey()));
                zip.write(file.getValue());
                zip.closeEntry();
            }
            zip.finish();
            return output.toByteArray();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Map<String, byte[]> unzip(byte[] zipBytes) throws Exception {
        Map<String, byte[]> files = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(zipBytes), StandardCharsets.UTF_8)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                files.put(entry.getName(), zip.readAllBytes());
            }
        }
        return files;
    }

    private static final class CountingRangeSource implements LczyRangeSource {

        private final byte[] bytes;
        private int requests;
        private long bytesRead;
        private int maxReadLength;

        private CountingRangeSource(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public long size() {
            return bytes.length;
        }

        @Override
        public byte[] read(long position, int length) throws IOException {
            requests++;
            bytesRead += length;
            maxReadLength = Math.max(maxReadLength, length);
            return Arrays.copyOfRange(bytes, Math.toIntExact(position), Math.toIntExact(position) + length);
        }

        int requests() {
            return requests;
        }

        long bytesRead() {
            return bytesRead;
        }

        int maxReadLength() {
            return maxReadLength;
        }
    }

    private record RotatingKeyProvider(String currentKeyId, Map<String, SecretKey> keys) implements ResourceKeyProvider {

        @Override
        public SecretKey getKey() {
            return getKey(currentKeyId);
        }

        @Override
        public String currentKeyId() {
            return currentKeyId;
        }

        @Override
        public SecretKey getKey(String keyId) {
            SecretKey key = keys.get(keyId);
            if (key == null) {
                throw new LczyException("Missing test key: " + keyId);
            }
            return key;
        }
    }

    private static final class FutureFormatReader implements LczyFormatReader {

        @Override
        public int version() {
            return 99;
        }

        @Override
        public LczyMetadata readMetadata(
                LczyRangeSource source,
                ResourceKeyProvider keyProvider,
                com.fasterxml.jackson.databind.ObjectMapper objectMapper
        ) {
            return null;
        }

        @Override
        public LczyManifest readManifest(
                LczyRangeSource source,
                ResourceKeyProvider keyProvider,
                com.fasterxml.jackson.databind.ObjectMapper objectMapper
        ) {
            return new LczyManifest(99, "future", List.of());
        }

        @Override
        public void readFile(
                LczyRangeSource source,
                String path,
                java.io.OutputStream output,
                ResourceKeyProvider keyProvider,
                com.fasterxml.jackson.databind.ObjectMapper objectMapper
        ) {
            throw new UnsupportedOperationException();
        }

        @Override
        public LczyResourcePackage decryptPackage(
                LczyRangeSource source,
                ResourceKeyProvider keyProvider,
                com.fasterxml.jackson.databind.ObjectMapper objectMapper
        ) {
            throw new UnsupportedOperationException();
        }
    }
}
