package org.brylex.sancus.agent;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Severity;
import org.brylex.sancus.audit.check.ChainCompletenessCheck;
import org.brylex.sancus.audit.check.ExpiryCheck;
import org.brylex.sancus.audit.check.OcspCheck;
import org.brylex.sancus.audit.check.TransparencyCheck;
import org.brylex.sancus.audit.check.WeakAlgorithmCheck;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public record AgentConfig(
        boolean enabled,
        boolean ocspEnabled,
        boolean chainEnabled,
        boolean aiaResolveEnabled,
        Severity logLevel,
        int cacheTtlMinutes
) {

    private static final AtomicReference<AgentConfig> INSTANCE = new AtomicReference<>();

    public static AgentConfig current() {
        return INSTANCE.updateAndGet(existing -> existing != null ? existing : fromSystemProperties());
    }

    public static void reset() {
        INSTANCE.set(null);
    }

    public static AgentConfig fromSystemProperties() {
        boolean enabled = Boolean.parseBoolean(System.getProperty("sancus.enabled", "true"));
        boolean ocsp = Boolean.parseBoolean(System.getProperty("sancus.checks.ocsp", "false"));
        boolean chain = Boolean.parseBoolean(System.getProperty("sancus.checks.chain", "false"));
        boolean aiaResolve = Boolean.parseBoolean(System.getProperty("sancus.aia.resolve", "true"));
        String levelName = System.getProperty("sancus.log.level", "WARNING");
        Severity logLevel = Severity.valueOf(levelName);
        int ttl = Integer.parseInt(System.getProperty("sancus.cache.ttl.minutes", "5"));
        return new AgentConfig(enabled, ocsp, chain, aiaResolve, logLevel, ttl);
    }

    public List<AuditCheck> checks() {
        List<AuditCheck> list = new ArrayList<>();
        list.add(new ExpiryCheck());
        list.add(new WeakAlgorithmCheck());
        list.add(new TransparencyCheck());
        if (ocspEnabled) {
            list.add(new OcspCheck());
        }
        if (chainEnabled) {
            list.add(new ChainCompletenessCheck());
        }
        return list;
    }
}
