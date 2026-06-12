package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

final class LczyV2FormatReader implements LczyFormatReader {

    @Override
    public int version() {
        return LczyFormat.VERSION_2;
    }

    @Override
    public LczyMetadata readMetadata(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        return reader(source, keyProvider, objectMapper).metadata();
    }

    @Override
    public LczyManifest readManifest(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        return reader(source, keyProvider, objectMapper).manifest();
    }

    @Override
    public void readFile(
            LczyRangeSource source,
            String path,
            OutputStream output,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        reader(source, keyProvider, objectMapper).readFile(path, output);
    }

    @Override
    public LczyResourcePackage decryptPackage(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        LczyReader reader = reader(source, keyProvider, objectMapper);
        LczyManifest manifest = reader.manifest();
        Map<String, byte[]> files = new LinkedHashMap<>();
        for (LczyEntry entry : manifest.entries()) {
            files.put(entry.path(), reader.readFile(entry));
        }
        return new LczyResourcePackage(reader.metadata(), manifest, files);
    }

    private LczyReader reader(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        return new LczyReader(source, keyProvider, objectMapper);
    }
}
