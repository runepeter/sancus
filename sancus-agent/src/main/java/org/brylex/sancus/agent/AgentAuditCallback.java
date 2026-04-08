package org.brylex.sancus.agent;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AgentAuditCallback implements BiConsumer<X509Certificate[], Boolean> {

    private static final Logger LOG = Logger.getLogger("sancus");

    @Override
    public void accept(X509Certificate[] chain, Boolean rejected) {
        if (chain == null || chain.length == 0) return;

        // Dedup: use fingerprint of leaf certificate
        X509Certificate leaf = chain[0];
        String fingerprint = AuditCache.fingerprint(leaf);
        if (AuditCache.INSTANCE.recentlyAudited(fingerprint)) {
            return; // already audited within TTL
        }

        AgentConfig config = AgentConfig.current();
        if (!config.enabled()) return;

        String prefix = Boolean.TRUE.equals(rejected) ? "[REJECTED] " : "";
        List<AuditCheck> checks = config.checks();
        Severity minLevel = config.logLevel();

        // Use empty protocol/cipherSuite since we only have the chain
        X509Certificate[] resolvedChain = readResolvedChainFromBootstrap();
        HandshakeInfo handshakeInfo = new HandshakeInfo("unknown", "unknown", chain, resolvedChain);

        for (AuditCheck check : checks) {
            try {
                List<Finding> findings = check.check(handshakeInfo, chain);
                for (Finding finding : findings) {
                    if (finding.severity().compareTo(minLevel) >= 0) {
                        Level julLevel = toJulLevel(finding.severity());
                        String message = "[sancus] " + finding.severity() + " \u2014 " + prefix + finding.summary();
                        LOG.log(julLevel, message);
                    }
                }
            } catch (Exception ignored) {
                // A failing check must not propagate — keep auditing remaining checks
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static final ThreadLocal<X509Certificate[]> BOOTSTRAP_THREAD_LOCAL;
    static {
        ThreadLocal<X509Certificate[]> tl = null;
        try {
            Class<?> bootstrapCopy = Class.forName(
                    "org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager", true, null);
            java.lang.reflect.Field field = bootstrapCopy.getField("lastResolvedChain");
            tl = (ThreadLocal<X509Certificate[]>) field.get(null);
        } catch (Exception ignored) {
            // Bootstrap copy not available — will fall back to agent-loader copy
        }
        BOOTSTRAP_THREAD_LOCAL = tl;
    }

    private static X509Certificate[] readResolvedChainFromBootstrap() {
        ThreadLocal<X509Certificate[]> tl = BOOTSTRAP_THREAD_LOCAL;
        if (tl != null) {
            return tl.get();
        }
        // Fallback: agent-loader copy (unit test scenario)
        return SancusAgentTrustManager.lastResolvedChain.get();
    }

    private static Level toJulLevel(Severity severity) {
        return switch (severity) {
            case OK -> Level.INFO;
            case WARNING, CRITICAL -> Level.WARNING;
        };
    }
}
