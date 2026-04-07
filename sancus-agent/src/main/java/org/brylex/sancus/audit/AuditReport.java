package org.brylex.sancus.audit;

import java.time.Instant;
import java.util.List;

public record AuditReport(String host, int port, Instant timestamp, List<Finding> findings) {

    public Severity overallSeverity() {
        return findings.stream()
                .map(Finding::severity)
                .max(Enum::compareTo)
                .orElse(Severity.OK);
    }

    public int exitCode() {
        return overallSeverity().exitCode();
    }
}
