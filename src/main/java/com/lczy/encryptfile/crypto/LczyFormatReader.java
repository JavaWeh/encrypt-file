package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Version-specific LCZY parser SPI.
 *
 * <p>Implementations can be registered with {@link java.util.ServiceLoader} to
 * support future container versions without changing the public service API.</p>
 */
public interface LczyFormatReader {

    int version();

    // SPI 方法保持无状态：同一个 reader 实例可以被多个服务复用，状态放在 source/objectMapper/keyProvider 中。
    LczyMetadata readMetadata(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    );

    LczyManifest readManifest(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    );

    void readFile(
            LczyRangeSource source,
            String path,
            OutputStream output,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    );

    LczyResourcePackage decryptPackage(
            LczyRangeSource source,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    );

    default byte[] readFile(
            LczyRangeSource source,
            String path,
            ResourceKeyProvider keyProvider,
            ObjectMapper objectMapper
    ) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            readFile(source, path, output, keyProvider, objectMapper);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to read LCZY entry: " + path, ex);
        }
    }
}
