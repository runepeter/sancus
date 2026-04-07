package org.brylex.sancus.agent;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class AuditCacheTest {

    private X509Certificate cert;

    @BeforeEach
    void setUp() throws Exception {
        try (InputStream is = getClass().getResourceAsStream("/ca/intermediate/certs/127.0.0.1.cert.pem")) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) factory.generateCertificate(is);
        }
        // Reset cache state between tests
        AuditCache.INSTANCE.clear();
    }

    @Test
    void fingerprintIs64HexChars() {
        String fingerprint = AuditCache.fingerprint(cert);
        assertNotNull(fingerprint);
        assertEquals(64, fingerprint.length());
        assertTrue(fingerprint.matches("[0-9a-f]{64}"), "Should be lowercase hex: " + fingerprint);
    }

    @Test
    void fingerprintIsDeterministic() {
        String fp1 = AuditCache.fingerprint(cert);
        String fp2 = AuditCache.fingerprint(cert);
        assertEquals(fp1, fp2);
    }

    @Test
    void firstCallReturnsFalse() {
        String fingerprint = AuditCache.fingerprint(cert);
        assertFalse(AuditCache.INSTANCE.recentlyAudited(fingerprint));
    }

    @Test
    void secondCallReturnsTrue() {
        String fingerprint = AuditCache.fingerprint(cert);
        AuditCache.INSTANCE.recentlyAudited(fingerprint); // first — registers
        assertTrue(AuditCache.INSTANCE.recentlyAudited(fingerprint)); // second — within TTL
    }
}
