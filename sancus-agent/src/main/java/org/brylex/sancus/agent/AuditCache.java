package org.brylex.sancus.agent;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class AuditCache {

    public static final AuditCache INSTANCE = new AuditCache();

    private final ConcurrentHashMap<String, Instant> cache = new ConcurrentHashMap<>();
    private final AtomicLong callCount = new AtomicLong(0);
    private volatile Duration ttl = Duration.ofMinutes(AgentConfig.current().cacheTtlMinutes());

    private AuditCache() {
    }

    public static String fingerprint(X509Certificate cert) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] der = cert.getEncoded();
            byte[] hash = digest.digest(der);
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute certificate fingerprint", e);
        }
    }

    /**
     * Returns true if the fingerprint was recently audited (within TTL).
     * Registers the fingerprint if not present, returning false on first call.
     * Evicts stale entries every 100 calls.
     */
    public boolean recentlyAudited(String fingerprint) {
        long count = callCount.incrementAndGet();
        if (count % 100 == 0) {
            evictStale();
        }

        Instant now = Instant.now();
        Instant registered = cache.get(fingerprint);
        if (registered != null && now.isBefore(registered.plus(getTtl()))) {
            return true;
        }
        cache.put(fingerprint, now);
        return false;
    }

    /** Visible for testing. */
    public void clear() {
        cache.clear();
        callCount.set(0);
    }

    private Duration getTtl() {
        return Duration.ofMinutes(AgentConfig.current().cacheTtlMinutes());
    }

    private void evictStale() {
        Instant cutoff = Instant.now().minus(getTtl());
        cache.entrySet().removeIf(e -> e.getValue().isBefore(cutoff));
    }
}
