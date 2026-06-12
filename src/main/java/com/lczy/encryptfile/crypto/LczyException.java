package com.lczy.encryptfile.crypto;

/**
 * Runtime exception used for malformed LCZY packages and crypto failures.
 *
 * @author JavaWeh
 */
public class LczyException extends RuntimeException {

    public LczyException(String message) {
        super(message);
    }

    public LczyException(String message, Throwable cause) {
        super(message, cause);
    }
}
