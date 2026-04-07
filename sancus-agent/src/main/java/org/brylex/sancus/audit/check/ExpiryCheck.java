package org.brylex.sancus.audit.check;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.ExpiryFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ExpiryCheck implements AuditCheck {

    private static final Duration CRITICAL_THRESHOLD = Duration.ofDays(7);
    private static final Duration WARN_THRESHOLD = Duration.ofDays(30);

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        List<Finding> findings = new ArrayList<>();
        Instant now = Instant.now();

        for (X509Certificate cert : chain) {
            String cn = cert.getSubjectX500Principal().getName();
            Instant notAfter = cert.getNotAfter().toInstant();
            Instant notBefore = cert.getNotBefore().toInstant();

            if (now.isAfter(notAfter)) {
                long daysExpired = Duration.between(notAfter, now).toDays();
                findings.add(new ExpiryFinding(cn, Severity.CRITICAL, -daysExpired, notAfter));
            } else if (now.isBefore(notBefore)) {
                findings.add(new ExpiryFinding(cn, Severity.CRITICAL, 0, notAfter));
            } else {
                long daysLeft = Duration.between(now, notAfter).toDays();
                Severity severity;
                if (daysLeft <= CRITICAL_THRESHOLD.toDays()) {
                    severity = Severity.CRITICAL;
                } else if (daysLeft <= WARN_THRESHOLD.toDays()) {
                    severity = Severity.WARNING;
                } else {
                    severity = Severity.OK;
                }
                findings.add(new ExpiryFinding(cn, severity, daysLeft, notAfter));
            }
        }

        return findings;
    }
}
