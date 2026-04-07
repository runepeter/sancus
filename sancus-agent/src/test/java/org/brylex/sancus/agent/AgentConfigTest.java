package org.brylex.sancus.agent;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AgentConfigTest {

    @AfterEach
    void cleanup() {
        AgentConfig.reset();
        System.clearProperty("sancus.enabled");
        System.clearProperty("sancus.checks.ocsp");
        System.clearProperty("sancus.checks.chain");
        System.clearProperty("sancus.log.level");
        System.clearProperty("sancus.cache.ttl.minutes");
    }

    @Test
    void defaultValues() {
        AgentConfig config = AgentConfig.fromSystemProperties();
        assertTrue(config.enabled());
        assertFalse(config.ocspEnabled());
        assertFalse(config.chainEnabled());
        assertEquals(Severity.WARNING, config.logLevel());
        assertEquals(5, config.cacheTtlMinutes());
    }

    @Test
    void customValues() {
        System.setProperty("sancus.enabled", "false");
        System.setProperty("sancus.checks.ocsp", "true");
        System.setProperty("sancus.checks.chain", "true");
        System.setProperty("sancus.log.level", "CRITICAL");
        System.setProperty("sancus.cache.ttl.minutes", "10");

        AgentConfig config = AgentConfig.fromSystemProperties();
        assertFalse(config.enabled());
        assertTrue(config.ocspEnabled());
        assertTrue(config.chainEnabled());
        assertEquals(Severity.CRITICAL, config.logLevel());
        assertEquals(10, config.cacheTtlMinutes());
    }

    @Test
    void defaultChecksCount() {
        AgentConfig config = AgentConfig.fromSystemProperties();
        List<AuditCheck> checks = config.checks();
        // ExpiryCheck, WeakAlgorithmCheck, TransparencyCheck
        assertEquals(3, checks.size());
    }

    @Test
    void allChecksWithOptIns() {
        System.setProperty("sancus.checks.ocsp", "true");
        System.setProperty("sancus.checks.chain", "true");

        AgentConfig config = AgentConfig.fromSystemProperties();
        List<AuditCheck> checks = config.checks();
        // ExpiryCheck, WeakAlgorithmCheck, TransparencyCheck, OcspCheck, ChainCompletenessCheck
        assertEquals(5, checks.size());
    }

    @Test
    void currentReturnsSameInstance() {
        AgentConfig first = AgentConfig.current();
        AgentConfig second = AgentConfig.current();
        assertSame(first, second);
    }
}
