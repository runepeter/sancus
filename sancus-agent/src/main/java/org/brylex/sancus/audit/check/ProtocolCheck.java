package org.brylex.sancus.audit.check;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.ProtocolFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ProtocolCheck implements AuditCheck {

    private static final Set<String> CRITICAL_PROTOCOLS = Set.of("SSLv2", "SSLv3", "TLSv1", "TLSv1.1");
    private static final Set<String> CRITICAL_CIPHER_KEYWORDS = Set.of("RC4", "DES", "NULL", "EXPORT");

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        List<Finding> findings = new ArrayList<>();

        String protocol = handshakeInfo.protocol();
        String cipher = handshakeInfo.cipherSuite();

        Severity protocolSeverity = CRITICAL_PROTOCOLS.contains(protocol) ? Severity.CRITICAL : Severity.OK;
        String cipherUpper = cipher.toUpperCase();
        boolean weakCipher = CRITICAL_CIPHER_KEYWORDS.stream().anyMatch(cipherUpper::contains);
        Severity cipherSeverity = weakCipher ? Severity.CRITICAL : Severity.OK;

        Severity worst = protocolSeverity.compareTo(cipherSeverity) >= 0 ? protocolSeverity : cipherSeverity;
        findings.add(new ProtocolFinding(worst, protocol, cipher));

        return findings;
    }
}
