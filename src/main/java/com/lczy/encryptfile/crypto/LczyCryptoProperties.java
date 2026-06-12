package com.lczy.encryptfile.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * LCZY Spring configuration properties.
 *
 * @author JavaWeh
 */
@ConfigurationProperties(prefix = "lczy.crypto")
public class LczyCryptoProperties {

    /**
     * Base64 encoded 32-byte AES key. Prefer environment variables or a custom
     * ResourceKeyProvider backed by database/KMS in production.
     */
    private String keyBase64;
    private String keyId;

    public String getKeyBase64() {
        return keyBase64;
    }

    public void setKeyBase64(String keyBase64) {
        this.keyBase64 = keyBase64;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
