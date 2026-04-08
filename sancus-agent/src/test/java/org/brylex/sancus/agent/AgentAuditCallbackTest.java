package org.brylex.sancus.agent;

import org.brylex.sancus.audit.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import static org.junit.jupiter.api.Assertions.*;

class AgentAuditCallbackTest {

    private X509Certificate cert;
    private CapturingHandler logHandler;
    private Logger sancusLogger;

    @BeforeEach
    void setUp() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/ca/intermediate/certs/127.0.0.1.cert.pem")) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) factory.generateCertificate(is);
        }
        AuditCache.INSTANCE.clear();
        AgentConfig.reset();

        // Attach capturing handler to sancus logger
        sancusLogger = Logger.getLogger("sancus");
        sancusLogger.setUseParentHandlers(false);
        logHandler = new CapturingHandler();
        sancusLogger.addHandler(logHandler);
    }

    @AfterEach
    void tearDown() {
        sancusLogger.removeHandler(logHandler);
        sancusLogger.setUseParentHandlers(true);
        System.clearProperty("sancus.checks.chain");
        AgentConfig.reset();
        AuditCache.INSTANCE.clear();
        SancusAgentTrustManager.lastResolvedChain.remove();
    }

    @Test
    void logsFindings() {
        System.setProperty("sancus.log.level", "OK"); // log everything
        AgentConfig.reset();

        AgentAuditCallback callback = new AgentAuditCallback();
        callback.accept(new X509Certificate[]{cert}, false);

        assertFalse(logHandler.records.isEmpty(), "Expected at least one log record");
        // All log messages should contain [sancus]
        for (LogRecord record : logHandler.records) {
            assertTrue(record.getMessage().contains("[sancus]"), "Missing [sancus] prefix: " + record.getMessage());
        }
    }

    @Test
    void rejectedPrefixOnRejectedHandshake() {
        System.setProperty("sancus.log.level", "OK");
        AgentConfig.reset();

        AgentAuditCallback callback = new AgentAuditCallback();
        callback.accept(new X509Certificate[]{cert}, true);

        boolean foundRejected = logHandler.records.stream()
                .anyMatch(r -> r.getMessage().contains("[REJECTED]"));
        assertTrue(foundRejected, "Expected at least one [REJECTED] prefixed log record");
    }

    @Test
    void deduplicationWithinTtl() {
        System.setProperty("sancus.log.level", "OK");
        AgentConfig.reset();

        AgentAuditCallback callback = new AgentAuditCallback();
        X509Certificate[] chain = new X509Certificate[]{cert};

        callback.accept(chain, false); // first call — should audit
        int firstCount = logHandler.records.size();
        assertTrue(firstCount > 0, "Expected findings on first call");

        logHandler.records.clear();
        callback.accept(chain, false); // second call — should be deduped
        assertEquals(0, logHandler.records.size(), "Expected no logs on second call (deduped)");
    }

    @Test
    void readsResolvedChainFromThreadLocal() {
        System.setProperty("sancus.log.level", "OK");
        System.setProperty("sancus.checks.chain", "true");
        AgentConfig.reset();

        X509Certificate[] resolvedChain = new X509Certificate[]{cert};
        SancusAgentTrustManager.lastResolvedChain.set(resolvedChain);

        AgentAuditCallback callback = new AgentAuditCallback();
        // Should not throw — resolvedChain is read from ThreadLocal fallback
        callback.accept(new X509Certificate[]{cert}, false);

        assertFalse(logHandler.records.isEmpty(), "Expected findings when chain check is enabled with resolved chain");
    }

    @Test
    void worksWithoutResolvedChain() {
        System.setProperty("sancus.log.level", "OK");
        System.setProperty("sancus.checks.chain", "true");
        AgentConfig.reset();

        // No ThreadLocal set — resolvedChain should be null
        AgentAuditCallback callback = new AgentAuditCallback();
        // Should not throw even without resolved chain
        callback.accept(new X509Certificate[]{cert}, false);

        // Still runs other checks
        assertFalse(logHandler.records.isEmpty());
    }

    // --- Custom JUL handler ---

    static class CapturingHandler extends Handler {
        final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
    }
}
