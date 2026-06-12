package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

final class LczyV1FormatReader implements LczyFormatReader {

    @Override
    public int version() {
        return LczyFormat.VERSION_1;
    }

    @Override
    public LczyMetadata readMetadata(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        return readBlock(source, keyProvider, objectMapper).metadata();
    }

    @Override
    public LczyManifest readManifest(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        return readBlock(source, keyProvider, objectMapper).manifest();
    }

    @Override
    public void readFile(
            LczyRangeSource source,
            String path,
            OutputStream output,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        try {
            output.write(readFile(source, path, keyProvider, objectMapper));
        } catch (IOException ex) {
            throw new LczyException("Failed to write LCZY entry: " + path, ex);
        }
    }

    @Override
    public byte[] readFile(
            LczyRangeSource source,
            String path,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        LegacyBlock legacyBlock = readBlock(source, keyProvider, objectMapper);
        LczyEntry entry = legacyBlock.manifest().requireEntry(LczyPaths.normalize(path));
        return decryptEntry(legacyBlock, entry, keyProvider);
    }

    @Override
    public LczyResourcePackage decryptPackage(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        LegacyBlock legacyBlock = readBlock(source, keyProvider, objectMapper);
        Map<String, byte[]> files = new LinkedHashMap<>();
        for (LczyEntry entry : legacyBlock.manifest().entries()) {
            files.put(entry.path(), decryptEntry(legacyBlock, entry, keyProvider));
        }
        return new LczyResourcePackage(legacyBlock.metadata(), legacyBlock.manifest(), files);
    }

    private byte[] decryptEntry(LegacyBlock legacyBlock, LczyEntry entry, ResourceKeyProvider keyProvider) {
        int offset = Math.toIntExact(entry.offset());
        int end = offset + entry.encryptedSize();
        if (offset < 0 || end > legacyBlock.fileData().length) {
            throw new LczyException("Invalid LCZY entry range: " + entry.path());
        }
        byte[] encrypted = Arrays.copyOfRange(legacyBlock.fileData(), offset, end);
        byte[] compressed = LczyCrypto.decrypt(
                encrypted,
                keyProvider.getKey(legacyBlock.metadata().keyId()),
                entry.iv(),
                LczyAlgorithm.AES_256_GCM
        );
        byte[] plain = LczyCompression.inflate(compressed);
        MessageDigest digest = LczyDigest.sha256();
        digest.update(plain);
        LczyDigest.verify(entry.sha256(), digest, entry.path());
        return plain;
    }

    private LegacyBlock readBlock(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        // v1 的索引位于文件头部后的密文数据前段，旧格式读取时仍需载入完整包体。
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(
                source.read(0, Math.toIntExact(source.size()))
        ))) {
            byte[] magic = input.readNBytes(LczyFormat.MAGIC.length);
            if (!Arrays.equals(LczyFormat.MAGIC, magic)) {
                throw new LczyException("Invalid LCZY magic");
            }
            int version = input.readUnsignedByte();
            if (version != LczyFormat.VERSION_1) {
                throw new LczyException("Unsupported LCZY version: " + version);
            }
            LczyAlgorithm algorithm = LczyAlgorithm.fromId(input.readByte());
            int ivLength = input.readUnsignedByte();
            if (ivLength != algorithm.ivLength()) {
                throw new LczyException("Invalid LCZY IV length: " + ivLength);
            }
            byte[] iv = input.readNBytes(ivLength);
            int metaLength = input.readInt();
            if (metaLength < 0) {
                throw new LczyException("Invalid LCZY metadata length");
            }
            LczyMetadata metadata = LczyJson.read(objectMapper, input.readNBytes(metaLength), LczyMetadata.class);
            if (metadata.indexCipherLength() <= 0) {
                throw new LczyException("Invalid LCZY encrypted index length");
            }
            byte[] cipherData = input.readAllBytes();
            if (metadata.indexCipherLength() > cipherData.length) {
                throw new LczyException("LCZY encrypted index exceeds cipher data length");
            }
            byte[] indexCipher = Arrays.copyOfRange(cipherData, 0, metadata.indexCipherLength());
            byte[] fileData = Arrays.copyOfRange(cipherData, metadata.indexCipherLength(), cipherData.length);
            byte[] indexPlain = LczyCrypto.decrypt(indexCipher, keyProvider.getKey(metadata.keyId()), iv, algorithm);
            try (DataInputStream inner = new DataInputStream(new ByteArrayInputStream(indexPlain))) {
                int headerLength = inner.readInt();
                inner.skipNBytes(headerLength);
                int manifestLength = inner.readInt();
                LczyManifest manifest = LczyJson.read(objectMapper, inner.readNBytes(manifestLength), LczyManifest.class);
                return new LegacyBlock(metadata, manifest, fileData);
            }
        } catch (IOException ex) {
            throw new LczyException("Failed to parse LCZY package", ex);
        }
    }

    private record LegacyBlock(LczyMetadata metadata, LczyManifest manifest, byte[] fileData) {
    }
}
