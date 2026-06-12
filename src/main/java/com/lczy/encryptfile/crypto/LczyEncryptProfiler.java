package com.lczy.encryptfile.crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

final class LczyEncryptProfiler {

    private static final Logger LOGGER = Logger.getLogger(LczyEncryptProfiler.class.getName());
    private static final boolean ENABLED = enabled();
    private static final int TOP_ENTRIES = Integer.getInteger("lczy.profile.top", 20);
    private static final long PROGRESS_INTERVAL_NANOS = progressIntervalNanos();

    private final String operation;
    private final long startedNanos;
    private final List<FileStats> files = new ArrayList<>();
    private long zipEntryScanNanos;
    private long headerNanos;
    private long indexBuildNanos;
    private long indexEncryptNanos;
    private long indexWriteNanos;
    private long footerWriteNanos;
    private long flushNanos;
    private long totalPlainBytes;
    private long totalCompressedBytes;
    private long totalEncryptedBytes;
    private int directories;
    private int storedEntries;
    private int deflatedEntries;
    private boolean finished;

    private LczyEncryptProfiler(String operation) {
        this.operation = operation;
        this.startedNanos = System.nanoTime();
    }

    static LczyEncryptProfiler start(String operation) {
        return new LczyEncryptProfiler(operation);
    }

    static boolean isEnabled() {
        return ENABLED && LOGGER.isLoggable(Level.INFO);
    }

    void addZipEntryScanNanos(long nanos) {
        if (isEnabled()) {
            zipEntryScanNanos += nanos;
        }
    }

    void addDirectory() {
        if (isEnabled()) {
            directories++;
        }
    }

    void addHeaderNanos(long nanos) {
        if (isEnabled()) {
            headerNanos += nanos;
        }
    }

    FileStats beginFile(String path, boolean stored) {
        if (!isEnabled()) {
            return FileStats.disabled(path, stored);
        }
        FileStats stats = new FileStats(path, stored);
        files.add(stats);
        if (stored) {
            storedEntries++;
        } else {
            deflatedEntries++;
        }
        return stats;
    }

    void finishFile(FileStats stats, long plainBytes, long compressedBytes, long encryptedBytes) {
        if (!isEnabled()) {
            return;
        }
        stats.finish();
        totalPlainBytes += plainBytes;
        totalCompressedBytes += compressedBytes;
        totalEncryptedBytes += encryptedBytes;
    }

    void addIndexBuildNanos(long nanos) {
        if (isEnabled()) {
            indexBuildNanos += nanos;
        }
    }

    void addIndexEncryptNanos(long nanos) {
        if (isEnabled()) {
            indexEncryptNanos += nanos;
        }
    }

    void addIndexWriteNanos(long nanos) {
        if (isEnabled()) {
            indexWriteNanos += nanos;
        }
    }

    void addFooterWriteNanos(long nanos) {
        if (isEnabled()) {
            footerWriteNanos += nanos;
        }
    }

    void addFlushNanos(long nanos) {
        if (isEnabled()) {
            flushNanos += nanos;
        }
    }

    void finishSuccess() {
        if (isEnabled()) {
            if (finished) {
                return;
            }
            finished = true;
            log("SUCCESS", null);
        }
    }

    void finishFailure(Throwable failure) {
        if (isEnabled()) {
            if (finished) {
                return;
            }
            finished = true;
            log("FAILED", failure);
        }
    }

    private void log(String status, Throwable failure) {
        long totalNanos = System.nanoTime() - startedNanos;
        long fileReadNanos = files.stream().mapToLong(FileStats::readNanos).sum();
        long fileDigestNanos = files.stream().mapToLong(FileStats::digestNanos).sum();
        long fileWriteNanos = files.stream().mapToLong(FileStats::writeNanos).sum();
        long fileCloseNanos = files.stream().mapToLong(FileStats::closeNanos).sum();
        long fileTotalNanos = files.stream().mapToLong(FileStats::totalNanos).sum();

        StringBuilder message = new StringBuilder(2048);
        message.append("LCZY encrypt profile ")
                .append(status)
                .append(" operation=").append(operation)
                .append(" total=").append(ms(totalNanos)).append("ms")
                .append(" entries=").append(files.size())
                .append(" dirs=").append(directories)
                .append(" stored=").append(storedEntries)
                .append(" deflated=").append(deflatedEntries)
                .append(" plain=").append(bytes(totalPlainBytes))
                .append(" compressed=").append(bytes(totalCompressedBytes))
                .append(" encrypted=").append(bytes(totalEncryptedBytes))
                .append('\n')
                .append("  stages: zipEntryScan=").append(ms(zipEntryScanNanos)).append("ms")
                .append(", header=").append(ms(headerNanos)).append("ms")
                .append(", fileTotal=").append(ms(fileTotalNanos)).append("ms")
                .append(", fileRead(zip/source)=").append(ms(fileReadNanos)).append("ms")
                .append(", digest=").append(ms(fileDigestNanos)).append("ms")
                .append(", write(compress/encrypt/output)=").append(ms(fileWriteNanos)).append("ms")
                .append(", fileFinalize=").append(ms(fileCloseNanos)).append("ms")
                .append(", indexBuild=").append(ms(indexBuildNanos)).append("ms")
                .append(", indexEncrypt=").append(ms(indexEncryptNanos)).append("ms")
                .append(", indexWrite=").append(ms(indexWriteNanos)).append("ms")
                .append(", footer=").append(ms(footerWriteNanos)).append("ms")
                .append(", flush=").append(ms(flushNanos)).append("ms");

        files.stream()
                .sorted(Comparator.comparingLong(FileStats::totalNanos).reversed())
                .limit(Math.max(0, TOP_ENTRIES))
                .forEach(stats -> appendFile(message, stats));

        if (failure != null) {
            message.append('\n').append("  failure=").append(failure.getClass().getName())
                    .append(": ").append(failure.getMessage());
        }
        LOGGER.info(message.toString());
    }

    private static void appendFile(StringBuilder message, FileStats stats) {
        message.append('\n')
                .append("  file path=").append(stats.path())
                .append(", mode=").append(stats.stored() ? "store" : "deflate")
                .append(", total=").append(ms(stats.totalNanos())).append("ms")
                .append(", read(zip/source)=").append(ms(stats.readNanos())).append("ms")
                .append(", digest=").append(ms(stats.digestNanos())).append("ms")
                .append(", write(compress/encrypt/output)=").append(ms(stats.writeNanos())).append("ms")
                .append(", finalize=").append(ms(stats.closeNanos())).append("ms")
                .append(", reads=").append(stats.readCalls())
                .append(", writes=").append(stats.writeCalls())
                .append(", plain=").append(bytes(stats.plainBytes()))
                .append(", compressed=").append(bytes(stats.compressedBytes()))
                .append(", encrypted=").append(bytes(stats.encryptedBytes()));
    }

    private static boolean enabled() {
        String property = System.getProperty("lczy.profile.enabled");
        if (property != null) {
            return Boolean.parseBoolean(property);
        }
        String env = System.getenv("LCZY_PROFILE_ENABLED");
        return env == null || Boolean.parseBoolean(env);
    }

    private static String ms(long nanos) {
        return String.format(Locale.ROOT, "%.3f", nanos / 1_000_000.0);
    }

    private static String bytes(long count) {
        if (count < 1024) {
            return count + "B";
        }
        double kib = count / 1024.0;
        if (kib < 1024) {
            return String.format(Locale.ROOT, "%.2fKiB", kib);
        }
        double mib = kib / 1024.0;
        if (mib < 1024) {
            return String.format(Locale.ROOT, "%.2fMiB", mib);
        }
        return String.format(Locale.ROOT, "%.2fGiB", mib / 1024.0);
    }

    static final class FileStats {

        private final String path;
        private final boolean stored;
        private final boolean enabled;
        private final long startedNanos;
        private long nextProgressNanos;
        private long finishedNanos;
        private long readNanos;
        private long digestNanos;
        private long writeNanos;
        private long closeNanos;
        private long plainBytes;
        private long compressedBytes;
        private long encryptedBytes;
        private int readCalls;
        private int writeCalls;

        private FileStats(String path, boolean stored) {
            this(path, stored, true);
        }

        private FileStats(String path, boolean stored, boolean enabled) {
            this.path = path;
            this.stored = stored;
            this.enabled = enabled;
            this.startedNanos = System.nanoTime();
            this.nextProgressNanos = this.startedNanos + PROGRESS_INTERVAL_NANOS;
        }

        private static FileStats disabled(String path, boolean stored) {
            return new FileStats(path, stored, false);
        }

        void addRead(long nanos, int bytes) {
            if (!enabled) {
                return;
            }
            readNanos += nanos;
            if (bytes > 0) {
                plainBytes += bytes;
                readCalls++;
                logProgressIfDue("read");
            }
        }

        void addDigest(long nanos) {
            if (enabled) {
                digestNanos += nanos;
            }
        }

        void addWrite(long nanos) {
            if (enabled) {
                writeNanos += nanos;
                writeCalls++;
                logProgressIfDue("write");
            }
        }

        void addClose(long nanos) {
            if (enabled) {
                closeNanos += nanos;
            }
        }

        void setOutputSizes(long compressedBytes, long encryptedBytes) {
            if (enabled) {
                this.compressedBytes = compressedBytes;
                this.encryptedBytes = encryptedBytes;
            }
        }

        private void finish() {
            if (enabled) {
                finishedNanos = System.nanoTime();
            }
        }

        private String path() {
            return path;
        }

        private boolean stored() {
            return stored;
        }

        private long totalNanos() {
            return finishedNanos == 0 ? 0 : finishedNanos - startedNanos;
        }

        private long readNanos() {
            return readNanos;
        }

        private long digestNanos() {
            return digestNanos;
        }

        private long writeNanos() {
            return writeNanos;
        }

        private long closeNanos() {
            return closeNanos;
        }

        private long plainBytes() {
            return plainBytes;
        }

        private long compressedBytes() {
            return compressedBytes;
        }

        private long encryptedBytes() {
            return encryptedBytes;
        }

        private int readCalls() {
            return readCalls;
        }

        private int writeCalls() {
            return writeCalls;
        }

        private void logProgressIfDue(String phase) {
            long now = System.nanoTime();
            if (PROGRESS_INTERVAL_NANOS <= 0 || now < nextProgressNanos) {
                return;
            }
            nextProgressNanos = now + PROGRESS_INTERVAL_NANOS;
            LOGGER.info("LCZY encrypt progress file path=" + path
                    + ", mode=" + (stored ? "store" : "deflate")
                    + ", phase=" + phase
                    + ", elapsed=" + ms(now - startedNanos) + "ms"
                    + ", read(zip/source)=" + ms(readNanos) + "ms"
                    + ", digest=" + ms(digestNanos) + "ms"
                    + ", write(compress/encrypt/output)=" + ms(writeNanos) + "ms"
                    + ", reads=" + readCalls
                    + ", writes=" + writeCalls
                    + ", plain=" + bytes(plainBytes)
                    + ", compressedSoFar=" + bytes(compressedBytes)
                    + ", encryptedSoFar=" + bytes(encryptedBytes));
        }
    }

    private static long progressIntervalNanos() {
        int seconds = Integer.getInteger("lczy.profile.progressSeconds", 10);
        if (seconds <= 0) {
            return 0;
        }
        return seconds * 1_000_000_000L;
    }
}
