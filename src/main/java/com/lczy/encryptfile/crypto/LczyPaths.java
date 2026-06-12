package com.lczy.encryptfile.crypto;

final class LczyPaths {

    private LczyPaths() {
    }

    static String normalize(String path) {
        String normalized = path.replace('\\', '/');
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isBlank() || normalized.contains("../") || normalized.equals("..") || normalized.startsWith("../")) {
            throw new LczyException("Unsafe resource path: " + path);
        }
        return normalized;
    }
}
