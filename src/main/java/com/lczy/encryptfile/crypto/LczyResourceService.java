package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Public service for creating and reading LCZY resource packages.
 *
 * <p>New packages are written as LCZY v2: file blocks are compressed and
 * encrypted while they are copied to the target stream, then the encrypted
 * manifest is appended at the tail for random range reads. LCZY v1 packages are
 * still accepted for backward-compatible decryption.</p>
 *
 * @author JavaWeh
 */
public class LczyResourceService {

    private final ResourceKeyProvider keyProvider;
    private final ObjectMapper objectMapper;
    private final Map<Integer, LczyFormatReader> formatReaders;

    public LczyResourceService(ResourceKeyProvider keyProvider) {
        this(keyProvider, defaultObjectMapper());
    }

    public LczyResourceService(ResourceKeyProvider keyProvider, ObjectMapper objectMapper) {
        this(keyProvider, objectMapper, defaultFormatReaders());
    }

    public LczyResourceService(
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper,
            List<LczyFormatReader> formatReaders
    ) {
        this.keyProvider = keyProvider;
        this.objectMapper = objectMapper;
        this.formatReaders = formatReaders.stream()
                .collect(Collectors.toMap(LczyFormatReader::version, Function.identity(), (first, second) -> second));
    }

    public byte[] encryptZip(byte[] zipBytes) {
        return encryptZip(new ByteArrayInputStream(zipBytes));
    }

    public byte[] encryptZip(java.io.InputStream zipInput) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            encryptZip(zipInput, output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to write LCZY bytes", ex);
        }
    }

    public void encryptZip(java.io.InputStream zipInput, OutputStream lczyOutput) {
        new LczyWriter(keyProvider, objectMapper).writeZip(zipInput, lczyOutput);
    }

    public byte[] encryptResources(List<ZipEntryResource> resources) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            new LczyWriter(keyProvider, objectMapper).writeResources(resources, output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to build LCZY package", ex);
        }
    }

    public LczyResourcePackage decryptPackage(byte[] lczyBytes) {
        return readerFor(lczyBytes).decryptPackage(source(lczyBytes), keyProvider, objectMapper);
    }

    public void decryptToZip(byte[] lczyBytes, OutputStream zipOutput) {
        if (versionOf(lczyBytes) == LczyFormat.VERSION_2) {
            decryptV2ToZip(lczyBytes, zipOutput);
            return;
        }
        LczyFormatReader reader = readerFor(lczyBytes);
        LczyManifest manifest = reader.readManifest(source(lczyBytes), keyProvider, objectMapper);
        try (ZipOutputStream zip = new ZipOutputStream(new CloseShieldOutputStream(zipOutput), StandardCharsets.UTF_8)) {
            for (LczyEntry entry : manifest.entries()) {
                zip.setLevel(zipCompressionLevel(entry.path()));
                zip.putNextEntry(new ZipEntry(entry.path()));
                reader.readFile(source(lczyBytes), entry.path(), zip, keyProvider, objectMapper);
                zip.closeEntry();
            }
            zip.finish();
        } catch (IOException ex) {
            throw new LczyException("Failed to write ZIP from LCZY package", ex);
        }
    }

    private void decryptV2ToZip(byte[] lczyBytes, OutputStream zipOutput) {
        LczyReader reader = new LczyReader(source(lczyBytes), keyProvider, objectMapper);
        LczyManifest manifest = reader.manifest();
        try (ZipOutputStream zip = new ZipOutputStream(new CloseShieldOutputStream(zipOutput), StandardCharsets.UTF_8)) {
            for (LczyEntry entry : manifest.entries()) {
                zip.setLevel(zipCompressionLevel(entry.path()));
                zip.putNextEntry(new ZipEntry(entry.path()));
                reader.readFile(entry, zip);
                zip.closeEntry();
            }
            zip.finish();
        } catch (IOException ex) {
            throw new LczyException("Failed to write ZIP from LCZY package", ex);
        }
    }

    public byte[] decryptToZip(byte[] lczyBytes) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            decryptToZip(lczyBytes, output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to write ZIP bytes", ex);
        }
    }

    public byte[] readFile(byte[] lczyBytes, String path) {
        return readerFor(lczyBytes).readFile(source(lczyBytes), path, keyProvider, objectMapper);
    }

    public LczyManifest readManifest(byte[] lczyBytes) {
        return readerFor(lczyBytes).readManifest(source(lczyBytes), keyProvider, objectMapper);
    }

    private LczyFormatReader readerFor(byte[] lczyBytes) {
        // 只在服务层识别魔数和版本号，具体格式细节交给对应的 LczyFormatReader。
        int version = versionOf(lczyBytes);
        LczyFormatReader reader = formatReaders.get(version);
        if (reader == null) {
            throw new LczyException("Unsupported LCZY version: " + version);
        }
        return reader;
    }

    private int versionOf(byte[] lczyBytes) {
        if (lczyBytes.length <= LczyFormat.MAGIC.length
                || !Arrays.equals(LczyFormat.MAGIC, Arrays.copyOfRange(lczyBytes, 0, LczyFormat.MAGIC.length))) {
            throw new LczyException("Invalid LCZY magic");
        }
        return lczyBytes[LczyFormat.MAGIC.length] & 0xff;
    }

    private LczyRangeSource source(byte[] lczyBytes) {
        return new LczyByteArrayRangeSource(lczyBytes);
    }

    private int zipCompressionLevel(String path) {
        if (FAST_STORE_EXTENSIONS.contains(extensionOf(path))) {
            return Deflater.NO_COMPRESSION;
        }
        return Deflater.BEST_SPEED;
    }

    private String extensionOf(String path) {
        int slash = path.lastIndexOf('/');
        int dot = path.lastIndexOf('.');
        if (dot <= slash || dot == path.length() - 1) {
            return "";
        }
        return path.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static List<LczyFormatReader> defaultFormatReaders() {
        List<LczyFormatReader> readers = new java.util.ArrayList<>();
        readers.add(new LczyV1FormatReader());
        readers.add(new LczyV2FormatReader());
        // 允许后续版本通过 Java SPI 注册读取器，不需要改动当前服务门面。
        ServiceLoader.load(LczyFormatReader.class).forEach(readers::add);
        return readers;
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
