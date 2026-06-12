package com.lczy.encryptfile.crypto;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

final class CloseShieldOutputStream extends FilterOutputStream {

    CloseShieldOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        out.write(b, off, len);
    }

    @Override
    public void close() throws IOException {
        flush();
    }
}
