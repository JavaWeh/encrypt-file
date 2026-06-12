package com.lczy.encryptfile.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class LczyDigest {

    private static final String SHA_256 = "SHA-256";

    private LczyDigest() {
    }

    static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance(SHA_256);
        } catch (NoSuchAlgorithmException ex) {
            throw new LczyException("SHA-256 digest is not available", ex);
        }
    }

    static String hex(MessageDigest digest) {
        return HexFormat.of().formatHex(digest.digest());
    }

    static String sha256Hex(byte[] bytes) {
        MessageDigest digest = sha256();
        digest.update(bytes);
        return hex(digest);
    }

    static void verify(String expectedSha256, MessageDigest actualDigest, String path) {
        if (expectedSha256 == null || expectedSha256.isBlank()) {
            return;
        }
        String actualSha256 = hex(actualDigest);
        if (!expectedSha256.equalsIgnoreCase(actualSha256)) {
            throw new LczyException("LCZY SHA-256 mismatch for " + path
                    + ": expected " + expectedSha256 + ", actual " + actualSha256);
        }
    }
}
