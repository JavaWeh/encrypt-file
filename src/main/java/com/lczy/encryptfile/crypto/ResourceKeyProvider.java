package com.lczy.encryptfile.crypto;

import javax.crypto.SecretKey;

/**
 * Provides encryption keys from external configuration, environment variables,
 * KMS, database, or any project-specific secret storage.
 *
 * @author JavaWeh
 */
public interface ResourceKeyProvider {

    SecretKey getKey();

    default String currentKeyId() {
        return null;
    }

    default SecretKey getKey(String keyId) {
        // 默认兼容单密钥项目；需要轮换时重写该方法，按 keyId 返回历史密钥。
        return getKey();
    }
}
