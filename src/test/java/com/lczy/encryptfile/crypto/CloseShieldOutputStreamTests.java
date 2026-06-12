package com.lczy.encryptfile.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import org.junit.jupiter.api.Test;

class CloseShieldOutputStreamTests {

    @Test
    void delegatesBulkWritesWithoutFallingBackToSingleByteWrites() throws Exception {
        BulkCountingOutputStream target = new BulkCountingOutputStream();
        CloseShieldOutputStream output = new CloseShieldOutputStream(target);

        output.write(new byte[8192], 0, 8192);

        assertThat(target.bulkWrites).isEqualTo(1);
        assertThat(target.singleByteWrites).isZero();
        assertThat(target.bytes).isEqualTo(8192);
    }

    private static final class BulkCountingOutputStream extends OutputStream {

        private int bulkWrites;
        private int singleByteWrites;
        private long bytes;

        @Override
        public void write(int b) {
            singleByteWrites++;
            bytes++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            bulkWrites++;
            bytes += len;
        }
    }
}
