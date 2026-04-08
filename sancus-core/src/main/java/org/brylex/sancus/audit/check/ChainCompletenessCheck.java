package org.brylex.sancus.audit.check;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.ChainFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;
import org.brylex.sancus.resolver.RemoteResolver;

import java.io.OutputStream;
import java.io.PrintStream;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class ChainCompletenessCheck implements AuditCheck {

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        if (chain.length == 0) {
            return List.of(new ChainFinding(Severity.CRITICAL, 0, false, List.of("no certificates")));
        }

        CertificateChain certChain = CertificateChain.create(chain);

        if (certChain.isComplete()) {
            return List.of(new ChainFinding(Severity.OK, chain.length, true, List.of()));
        }

        X509Certificate[] resolvedChain = handshakeInfo.resolvedChain();
        if (resolvedChain != null && resolvedChain.length > chain.length) {
            X509Certificate last = resolvedChain[resolvedChain.length - 1];
            X500Principal issuer = last.getIssuerX500Principal();
            boolean complete = last.getSubjectX500Principal().equals(issuer);
            if (complete) {
                int extra = resolvedChain.length - chain.length;
                return List.of(new ChainFinding(Severity.WARNING, chain.length, false,
                        List.of(extra + " certificate(s) resolved via AIA")));
            } else {
                return List.of(new ChainFinding(Severity.CRITICAL, chain.length, false, List.of(issuer.getName())));
            }
        }

        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(OutputStream.nullOutputStream()));
            new RemoteResolver().resolve(certChain);
        } catch (Exception ignored) {
        } finally {
            System.setOut(originalOut);
        }

        if (certChain.isComplete()) {
            int resolved = certChain.toList().size() - chain.length;
            return List.of(new ChainFinding(Severity.WARNING, chain.length, false,
                    List.of(resolved + " certificate(s) resolved via AIA")));
        }

        X509Certificate last = chain[chain.length - 1];
        String missingIssuer = last.getIssuerX500Principal().getName();
        return List.of(new ChainFinding(Severity.CRITICAL, chain.length, false, List.of(missingIssuer)));
    }
}
