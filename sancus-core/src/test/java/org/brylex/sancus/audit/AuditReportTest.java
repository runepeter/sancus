package org.brylex.sancus.audit;

import org.brylex.sancus.audit.Finding.*;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AuditReportTest {

    @Test
    void overallSeverityReturnsCriticalWhenAtLeastOneCritical() {
        var report = new AuditReport("host", 443, Instant.now(), List.of(
                new ExpiryFinding("CN=test", Severity.OK, 90, Instant.now()),
                new ProtocolFinding(Severity.WARNING, "TLSv1.2", "AES"),
                new WeakAlgorithmFinding("CN=test", Severity.CRITICAL, "SHA1WithRSA", 1024)
        ));
        assertEquals(Severity.CRITICAL, report.overallSeverity());
    }

    @Test
    void overallSeverityReturnsWarningWhenWorstIsWarning() {
        var report = new AuditReport("host", 443, Instant.now(), List.of(
                new ExpiryFinding("CN=test", Severity.OK, 90, Instant.now()),
                new ProtocolFinding(Severity.WARNING, "TLSv1.2", "AES")
        ));
        assertEquals(Severity.WARNING, report.overallSeverity());
    }

    @Test
    void overallSeverityReturnsOkForEmptyList() {
        var report = new AuditReport("host", 443, Instant.now(), List.of());
        assertEquals(Severity.OK, report.overallSeverity());
    }

    @Test
    void overallSeverityReturnsOkWhenAllOk() {
        var report = new AuditReport("host", 443, Instant.now(), List.of(
                new ExpiryFinding("CN=test", Severity.OK, 90, Instant.now()),
                new ProtocolFinding(Severity.OK, "TLSv1.3", "AES")
        ));
        assertEquals(Severity.OK, report.overallSeverity());
    }

    @Test
    void exitCodeMapsCorrectly() {
        assertEquals(0, new AuditReport("h", 443, Instant.now(), List.of()).exitCode());
        assertEquals(1, new AuditReport("h", 443, Instant.now(), List.of(
                new ProtocolFinding(Severity.WARNING, "TLSv1.2", "AES"))).exitCode());
        assertEquals(2, new AuditReport("h", 443, Instant.now(), List.of(
                new ProtocolFinding(Severity.CRITICAL, "SSLv3", "RC4"))).exitCode());
    }

    @Test
    void allFindingRecordsCanBeInstantiatedWithNonEmptySummary() {
        List<Finding> findings = List.of(
                new ExpiryFinding("CN=test", Severity.OK, 90, Instant.now()),
                new RevocationFinding("CN=test", Severity.OK, "good", "http://ocsp.example.com"),
                new WeakAlgorithmFinding("CN=test", Severity.OK, "SHA256WithRSA", 4096),
                new ChainFinding(Severity.OK, 3, true, List.of()),
                new ProtocolFinding(Severity.OK, "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
                new TransparencyFinding("CN=test", Severity.OK, 3)
        );

        for (Finding f : findings) {
            assertNotNull(f.summary(), "summary() should not be null");
            assertFalse(f.summary().isEmpty(), "summary() should not be empty for " + f.getClass().getSimpleName());
            assertNotNull(f.severity(), "severity() should not be null");
        }
    }
}
