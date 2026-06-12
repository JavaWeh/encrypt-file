package com.lczy.encryptfile.crypto;

import java.util.Arrays;

record LczyByteArrayRangeSource(byte[] bytes) implements LczyRangeSource {

    @Override
    public long size() {
        return bytes.length;
    }

    @Override
    public byte[] read(long position, int length) {
        int start = Math.toIntExact(position);
        int end = start + length;
        if (start < 0 || length < 0 || end > bytes.length) {
            throw new LczyException("Invalid LCZY byte range");
        }
        return Arrays.copyOfRange(bytes, start, end);
    }
}
