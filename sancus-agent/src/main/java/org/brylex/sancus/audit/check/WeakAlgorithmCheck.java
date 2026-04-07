package org.brylex.sancus.audit.check;

import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.WeakAlgorithmFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

public class WeakAlgorithmCheck implements AuditCheck {

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        List<Finding> findings = new ArrayList<>();

        for (X509Certificate cert : chain) {
            String cn = cert.getSubjectX500Principal().getName();
            String sigAlg = cert.getSigAlgName();
            String sigAlgUpper = sigAlg.toUpperCase();

            if (sigAlgUpper.contains("SHA1") || sigAlgUpper.contains("SHA-1")) {
                findings.add(new WeakAlgorithmFinding(cn, Severity.CRITICAL, sigAlg, 0));
            }

            var publicKey = cert.getPublicKey();
            if (publicKey instanceof RSAPublicKey rsa) {
                int bitLength = rsa.getModulus().bitLength();
                Severity severity;
                if (bitLength < 2048) {
                    severity = Severity.CRITICAL;
                } else if (bitLength < 4096) {
                    severity = Severity.WARNING;
                } else {
                    severity = Severity.OK;
                }
                findings.add(new WeakAlgorithmFinding(cn, severity, sigAlg, bitLength));
            } else if (publicKey instanceof ECPublicKey ec) {
                int bitLength = ec.getParams().getOrder().bitLength();
                Severity severity = bitLength < 256 ? Severity.CRITICAL : Severity.OK;
                findings.add(new WeakAlgorithmFinding(cn, severity, sigAlg, bitLength));
            }
        }

        if (findings.isEmpty()) {
            findings.add(new WeakAlgorithmFinding("all", Severity.OK, "acceptable", 0));
        }

        return findings;
    }
}
