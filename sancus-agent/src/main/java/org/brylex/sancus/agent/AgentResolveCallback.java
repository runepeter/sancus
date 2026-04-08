package org.brylex.sancus.agent;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.resolver.RemoteResolver;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.logging.Logger;

public class AgentResolveCallback implements Function<X509Certificate[], X509Certificate[]> {

    private static final Logger LOG = Logger.getLogger("sancus");

    private record CachedChain(X509Certificate[] chain, Instant resolvedAt) {}

    private final ConcurrentHashMap<String, CachedChain> cache = new ConcurrentHashMap<>();
    private final AtomicLong callCount = new AtomicLong(0);

    public AgentResolveCallback() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public X509Certificate[] apply(X509Certificate[] chain) {
        try {
            if (chain == null || chain.length == 0) return chain;
            String fingerprint = AuditCache.fingerprint(chain[0]);

            CachedChain cached = cache.get(fingerprint);
            int ttlMinutes = AgentConfig.current().cacheTtlMinutes();
            if (cached != null && Instant.now().isBefore(cached.resolvedAt().plusSeconds(ttlMinutes * 60L))) {
                return cached.chain();
            }

            long count = callCount.incrementAndGet();
            if (count % 100 == 0) {
                Instant cutoff = Instant.now().minusSeconds(ttlMinutes * 60L);
                cache.entrySet().removeIf(e -> e.getValue().resolvedAt().isBefore(cutoff));
            }

            CertificateChain certChain = CertificateChain.create(chain);
            if (certChain.isComplete()) {
                cache.put(fingerprint, new CachedChain(chain, Instant.now()));
                return chain;
            }

            new RemoteResolver().resolve(certChain);
            X509Certificate[] resolved = certChain.toList().toArray(new X509Certificate[0]);
            cache.put(fingerprint, new CachedChain(resolved, Instant.now()));

            if (resolved.length > chain.length) {
                LOG.info("[sancus] AIA resolved " + (resolved.length - chain.length) + " additional certificate(s)");
            }
            return resolved;
        } catch (Exception e) {
            LOG.fine("[sancus] AIA resolve failed, using original chain: " + e.getMessage());
            return chain;
        }
    }

    void clearCache() {
        cache.clear();
        callCount.set(0);
    }
}
