package com.lczy.encryptfile.crypto;

final class LczyFormat {

    static final byte[] MAGIC = {'L', 'C', 'Z', 'Y'};
    static final int VERSION_1 = 1;
    static final int VERSION_2 = 2;
    static final int BUFFER_SIZE = 4 * 1024 * 1024;
    static final byte[] V2_FOOTER_MAGIC = {'L', 'C', 'Z', 'Y', 'I', 'D', 'X', '2'};
    static final int V2_FOOTER_LENGTH = Long.BYTES + Integer.BYTES + V2_FOOTER_MAGIC.length;

    private LczyFormat() {
    }
}
