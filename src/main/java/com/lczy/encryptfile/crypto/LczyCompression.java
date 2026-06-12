package com.lczy.encryptfile.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

final class LczyCompression {

    private static final int BUFFER_SIZE = 16 * 1024;

    private LczyCompression() {
    }

    static byte[] deflate(byte[] input) {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream();
             DeflaterOutputStream deflater = new DeflaterOutputStream(output)) {
            deflater.write(input);
            deflater.finish();
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to compress LCZY entry", ex);
        }
    }

    static byte[] inflate(byte[] input) {
        try (InflaterInputStream inflater = new InflaterInputStream(new ByteArrayInputStream(input));
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            inflater.transferTo(output);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new LczyException("Failed to decompress LCZY entry", ex);
        }
    }

    static void inflate(InputStream input, OutputStream output) {
        try (InflaterInputStream inflater = new InflaterInputStream(input)) {
            inflater.transferTo(output);
        } catch (IOException ex) {
            throw new LczyException("Failed to decompress LCZY entry", ex);
        }
    }
}
