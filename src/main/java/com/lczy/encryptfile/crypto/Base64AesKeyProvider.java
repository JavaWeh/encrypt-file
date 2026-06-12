package com.lczy.encryptfile.crypto;

import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads an AES-256 key from a Base64 string, usually bound from Spring
 * configuration or an environment variable.
 *
 * @author JavaWeh
 */
public class Base64AesKeyProvider implements ResourceKeyProvider {

    private final String base64Key;
    private final String keyId;

    public Base64AesKeyProvider(String base64Key) {
        this(base64Key, null);
    }

    public Base64AesKeyProvider(String base64Key, String keyId) {
        this.base64Key = base64Key;
        this.keyId = keyId;
    }

    @Override
    public SecretKey getKey() {
        if (base64Key == null || base64Key.isBlank()) {
            throw new LczyException("LCZY AES key is not configured");
        }
        byte[] key = Base64.getDecoder().decode(base64Key);
        if (key.length != 32) {
            throw new LczyException("LCZY AES-256-GCM requires a 32-byte key");
        }
        return new SecretKeySpec(key, "AES");
    }

    @Override
    public String currentKeyId() {
        return keyId;
    }
}
