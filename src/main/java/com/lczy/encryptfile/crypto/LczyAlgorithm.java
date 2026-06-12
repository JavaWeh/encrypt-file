package com.lczy.encryptfile.crypto;

/**
 * Supported LCZY encryption algorithms.
 *
 * @author JavaWeh
 */
public enum LczyAlgorithm {
    AES_256_GCM((byte) 1, "AES/GCM/NoPadding", 12, 16, 256);

    private final byte id;
    private final String transformation;
    private final int ivLength;
    private final int tagLength;
    private final int keyBits;

    LczyAlgorithm(byte id, String transformation, int ivLength, int tagLength, int keyBits) {
        this.id = id;
        this.transformation = transformation;
        this.ivLength = ivLength;
        this.tagLength = tagLength;
        this.keyBits = keyBits;
    }

    public byte id() {
        return id;
    }

    public String transformation() {
        return transformation;
    }

    public int ivLength() {
        return ivLength;
    }

    public int tagLength() {
        return tagLength;
    }

    public int keyBits() {
        return keyBits;
    }

    public static LczyAlgorithm fromId(byte id) {
        for (LczyAlgorithm algorithm : values()) {
            if (algorithm.id == id) {
                return algorithm;
            }
        }
        throw new LczyException("Unsupported LCZY algorithm id: " + id);
    }
}
