package com.lczy.encryptfile.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class LczyCrypto {

    private static final SecureRandom RANDOM = new SecureRandom();

    private LczyCrypto() {
    }

    static byte[] randomIv(LczyAlgorithm algorithm) {
        byte[] iv = new byte[algorithm.ivLength()];
        RANDOM.nextBytes(iv);
        return iv;
    }

    static byte[] encrypt(byte[] plain, SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        return doFinal(Cipher.ENCRYPT_MODE, plain, key, iv, algorithm);
    }

    static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        return doFinal(Cipher.DECRYPT_MODE, cipherText, key, iv, algorithm);
    }

    static Cipher encryptCipher(SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        return initCipher(Cipher.ENCRYPT_MODE, key, iv, algorithm);
    }

    static Cipher decryptCipher(SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        return initCipher(Cipher.DECRYPT_MODE, key, iv, algorithm);
    }

    private static byte[] doFinal(int mode, byte[] input, SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        try {
            return initCipher(mode, key, iv, algorithm).doFinal(input);
        } catch (GeneralSecurityException ex) {
            throw new LczyException("LCZY AES-GCM operation failed", ex);
        }
    }

    private static Cipher initCipher(int mode, SecretKey key, byte[] iv, LczyAlgorithm algorithm) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.transformation());
            cipher.init(mode, key, new GCMParameterSpec(algorithm.tagLength() * Byte.SIZE, iv));
            return cipher;
        } catch (GeneralSecurityException ex) {
            throw new LczyException("LCZY AES-GCM operation failed", ex);
        }
    }
}
