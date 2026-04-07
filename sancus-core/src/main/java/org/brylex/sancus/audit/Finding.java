package org.brylex.sancus.audit;

import java.time.Instant;
import java.util.List;

public sealed interface Finding {

    Severity severity();

    String summary();

    record ExpiryFinding(String subject, Severity severity, long daysRemaining, Instant notAfter) implements Finding {
        @Override
        public String summary() {
            if (daysRemaining < 0) {
                return "Certificate expired: " + subject + " (expired " + notAfter + ")";
            }
            return "Certificate expires in " + daysRemaining + " days: " + subject;
        }
    }

    record RevocationFinding(String subject, Severity severity, String ocspStatus, String responderUrl) implements Finding {
        @Override
        public String summary() {
            return "OCSP " + ocspStatus + " for " + subject + " via " + responderUrl;
        }
    }

    record WeakAlgorithmFinding(String subject, Severity severity, String algorithm, int keySize) implements Finding {
        @Override
        public String summary() {
            return algorithm + " with " + keySize + "-bit key for " + subject;
        }
    }

    record ChainFinding(Severity severity, int chainLength, boolean complete, List<String> missingIssuers) implements Finding {
        @Override
        public String summary() {
            if (complete) {
                return "Chain complete (" + chainLength + " certificates)";
            }
            return "Chain incomplete (" + chainLength + " certificates), missing: " + String.join(", ", missingIssuers);
        }
    }

    record ProtocolFinding(Severity severity, String protocol, String cipherSuite) implements Finding {
        @Override
        public String summary() {
            return protocol + " / " + cipherSuite;
        }
    }

    record TransparencyFinding(String subject, Severity severity, int sctCount) implements Finding {
        @Override
        public String summary() {
            if (sctCount == 0) {
                return "No SCTs found for " + subject;
            }
            return sctCount + " SCT(s) embedded in " + subject;
        }
    }
}
