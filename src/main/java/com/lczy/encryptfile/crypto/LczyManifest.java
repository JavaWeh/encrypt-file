package com.lczy.encryptfile.crypto;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Encrypted index manifest. It records all independently encrypted file blocks
 * so callers can locate and decrypt a single resource without expanding the
 * whole package to ZIP.
 *
 * @author JavaWeh
 */
public record LczyManifest(
        int version,
        String algorithm,
        List<LczyEntry> entries
) {

    public LczyManifest {
        entries = List.copyOf(entries);
    }

    public LczyEntry requireEntry(String path) {
        LczyEntry entry = entryIndex().get(path);
        if (entry == null) {
            throw new LczyException("Resource not found in LCZY package: " + path);
        }
        return entry;
    }

    private Map<String, LczyEntry> entryIndex() {
        synchronized (ENTRY_INDEXES) {
            return ENTRY_INDEXES.computeIfAbsent(this, LczyManifest::buildEntryIndex);
        }
    }

    private static Map<String, LczyEntry> buildEntryIndex(LczyManifest manifest) {
        Map<String, LczyEntry> index = new LinkedHashMap<>();
        for (LczyEntry entry : manifest.entries()) {
            index.putIfAbsent(entry.path(), entry);
        }
        return index;
    }

    private static final Map<LczyManifest, Map<String, LczyEntry>> ENTRY_INDEXES =
            Collections.synchronizedMap(new WeakHashMap<>());
}
