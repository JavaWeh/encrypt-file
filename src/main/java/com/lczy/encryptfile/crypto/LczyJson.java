package com.lczy.encryptfile.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

final class LczyJson {

    private LczyJson() {
    }

    static <T> T read(ObjectMapper objectMapper, byte[] value, Class<T> type) {
        try {
            return objectMapper.readValue(value, type);
        } catch (IOException ex) {
            throw new LczyException("Failed to parse LCZY JSON", ex);
        }
    }
}
