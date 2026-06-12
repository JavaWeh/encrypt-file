package com.lczy.encryptfile.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class LczyRealZipPerformanceTests {

    private final LczyResourceService service = new LczyResourceService(
            () -> new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES")
    );

    @Test
    void encryptRealBatteryCellZip() throws Exception {
        Path input = Path.of("C:\\WorkSpace", "\u7535\u82af.zip");
        assumeTrue(Files.isRegularFile(input), "Performance fixture not found: " + input);

        Path output = Path.of("target", "perf", "\u7535\u82af.lczy");
        Files.createDirectories(output.getParent());
        Files.deleteIfExists(output);

        long startedNanos = System.nanoTime();
        try (InputStream zipInput = Files.newInputStream(input);
             OutputStream lczyOutput = Files.newOutputStream(output)) {
            service.encryptZip(zipInput, lczyOutput);
        }
        long elapsedNanos = System.nanoTime() - startedNanos;

        assertThat(Files.size(output)).isPositive();
        System.out.printf(
                "LCZY real zip encryption finished input=%s output=%s elapsed=%.3fms inputSize=%d outputSize=%d%n",
                input,
                output,
                elapsedNanos / 1_000_000.0,
                Files.size(input),
                Files.size(output)
        );
    }

    @Test
    void readRealBatteryCellPreviewFiles() throws Exception {
        Path lczy = Path.of("target", "perf", "\u7535\u82af.lczy");
        assumeTrue(Files.isRegularFile(lczy), "Encrypted performance fixture not found: " + lczy);

        byte[] bytes = Files.readAllBytes(lczy);
        long dataStart = System.nanoTime();
        byte[] data = service.readFile(bytes, "Build/DX2.data");
        long dataNanos = System.nanoTime() - dataStart;

        long wasmStart = System.nanoTime();
        byte[] wasm = service.readFile(bytes, "Build/DX2.wasm");
        long wasmNanos = System.nanoTime() - wasmStart;

        assertThat(data).isNotEmpty();
        assertThat(wasm).isNotEmpty();
        System.out.printf(
                "LCZY real preview reads data=%.3fms(%d bytes) wasm=%.3fms(%d bytes)%n",
                dataNanos / 1_000_000.0,
                data.length,
                wasmNanos / 1_000_000.0,
                wasm.length
        );
    }

    @Test
    void decryptRealBatteryCellPackageToZip() throws Exception {
        Path lczy = Path.of("target", "perf", "\u7535\u82af.lczy");
        assumeTrue(Files.isRegularFile(lczy), "Encrypted performance fixture not found: " + lczy);

        Path output = Path.of("target", "perf", "\u7535\u82af-decrypted.zip");
        Files.deleteIfExists(output);

        byte[] bytes = Files.readAllBytes(lczy);
        long startedNanos = System.nanoTime();
        try (OutputStream zipOutput = Files.newOutputStream(output)) {
            service.decryptToZip(bytes, zipOutput);
        }
        long elapsedNanos = System.nanoTime() - startedNanos;

        assertThat(Files.size(output)).isPositive();
        System.out.printf(
                "LCZY real decryptToZip finished output=%s elapsed=%.3fms inputSize=%d outputSize=%d%n",
                output,
                elapsedNanos / 1_000_000.0,
                Files.size(lczy),
                Files.size(output)
        );
    }
}
