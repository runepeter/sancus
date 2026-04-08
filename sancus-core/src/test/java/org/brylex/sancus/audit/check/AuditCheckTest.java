package org.brylex.sancus.audit.check;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;
import org.brylex.sancus.util.Certificates;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class AuditCheckTest {

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static HandshakeInfo handshake(String protocol, String cipher, X509Certificate... chain) {
        return new HandshakeInfo(protocol, cipher, chain);
    }

    private static HandshakeInfo defaultHandshake(X509Certificate... chain) {
        return handshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", chain);
    }

    private static X509Certificate generateCert(int validDays, int keySize, String sigAlgorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(Duration.ofDays(1)));
        Date notAfter = Date.from(now.plus(Duration.ofDays(validDays)));

        X500Principal subject = new X500Principal("CN=Test, O=Test");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, kp.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(sigAlgorithm)
                .setProvider("BC").build(kp.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));
    }

    @Nested
    class ExpiryCheckTest {

        private final ExpiryCheck check = new ExpiryCheck();

        @Test
        void criticalWhenExpiresIn5Days() throws Exception {
            X509Certificate cert = generateCert(5, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "Expected CRITICAL for cert expiring in 5 days");
        }

        @Test
        void warningWhenExpiresIn20Days() throws Exception {
            X509Certificate cert = generateCert(20, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.WARNING),
                    "Expected WARNING for cert expiring in 20 days");
        }

        @Test
        void okWhenExpiresIn60Days() throws Exception {
            X509Certificate cert = generateCert(60, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.OK),
                    "Expected OK for cert expiring in 60 days");
        }
    }

    @Nested
    class WeakAlgorithmCheckTest {

        private final WeakAlgorithmCheck check = new WeakAlgorithmCheck();

        @Test
        void okWithSha256Rsa2048() throws Exception {
            X509Certificate cert = generateCert(365, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertFalse(findings.stream().anyMatch(f ->
                            f.severity() == Severity.CRITICAL && f.summary().contains("SHA-1")),
                    "Should not flag SHA-256 as weak algorithm");
        }

        @Test
        void criticalWithSha1() throws Exception {
            X509Certificate cert = generateCert(365, 2048, "SHA1WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "Expected CRITICAL for SHA-1 signature algorithm");
        }

        @Test
        void warningForRsa2048() throws Exception {
            X509Certificate cert = generateCert(365, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f ->
                            f.severity() == Severity.WARNING && f.summary().contains("2048")),
                    "Expected WARNING for RSA 2048 (< 4096)");
        }

        @Test
        void criticalForWeakRsa1024() throws Exception {
            X509Certificate cert = generateCert(365, 1024, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f ->
                            f.severity() == Severity.CRITICAL && f.summary().contains("1024")),
                    "Expected CRITICAL for RSA 1024");
        }
    }

    @Nested
    class ProtocolCheckTest {

        private final ProtocolCheck check = new ProtocolCheck();

        @Test
        void okWithTls13() {
            List<Finding> findings = check.check(
                    handshake("TLSv1.3", "TLS_AES_256_GCM_SHA384"), new X509Certificate[0]);
            assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.OK),
                    "Expected OK for TLSv1.3");
        }

        @Test
        void criticalWithTls11() {
            List<Finding> findings = check.check(
                    handshake("TLSv1.1", "TLS_AES_256_GCM_SHA384"), new X509Certificate[0]);
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "Expected CRITICAL for TLSv1.1");
        }

        @Test
        void criticalWithWeakCipher() {
            List<Finding> findings = check.check(
                    handshake("TLSv1.2", "TLS_RSA_WITH_RC4_128_SHA"), new X509Certificate[0]);
            assertTrue(findings.stream().anyMatch(f ->
                            f.severity() == Severity.CRITICAL && f.summary().contains("RC4")),
                    "Expected CRITICAL for RC4 cipher");
        }

        @Test
        void okWithTls12AndStrongCipher() {
            List<Finding> findings = check.check(
                    handshake("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), new X509Certificate[0]);
            assertTrue(findings.stream().allMatch(f -> f.severity() == Severity.OK),
                    "Expected OK for TLSv1.2 with strong cipher");
        }
    }

    @Nested
    class ChainCompletenessCheckTest {

        private final ChainCompletenessCheck check = new ChainCompletenessCheck();

        @Test
        void okWithCompleteChain() throws Exception {
            X509Certificate selfSigned = generateCert(365, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(selfSigned), new X509Certificate[]{selfSigned});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.OK),
                    "Expected OK for complete chain");
        }

        @Test
        void criticalWithIncompleteChain() {
            X509Certificate leaf = Certificates.LOCALHOST;
            List<Finding> findings = check.check(defaultHandshake(leaf), new X509Certificate[]{leaf});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL),
                    "Expected CRITICAL for incomplete chain without resolvable AIA");
        }

        @Test
        void usesResolvedChainWhenPresent() throws Exception {
            X509Certificate leaf = Certificates.LOCALHOST;
            X509Certificate fakeRoot = generateCert(365, 2048, "SHA256WithRSA");
            X509Certificate[] resolvedChain = new X509Certificate[]{leaf, fakeRoot};
            HandshakeInfo info = new HandshakeInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384",
                    new X509Certificate[]{leaf}, resolvedChain);
            List<Finding> findings = check.check(info, new X509Certificate[]{leaf});
            assertFalse(findings.isEmpty());
            Finding.ChainFinding cf = (Finding.ChainFinding) findings.getFirst();
            assertEquals(Severity.WARNING, cf.severity());
            assertTrue(cf.summary().contains("resolved via AIA"));
        }

        @Test
        void criticalWhenResolvedChainIsIncomplete() {
            X509Certificate leaf = Certificates.LOCALHOST;
            X509Certificate intermediate = Certificates.AMAZON_CA;
            X509Certificate[] resolvedChain = new X509Certificate[]{leaf, intermediate};
            HandshakeInfo info = new HandshakeInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384",
                    new X509Certificate[]{leaf}, resolvedChain);
            List<Finding> findings = check.check(info, new X509Certificate[]{leaf});
            assertFalse(findings.isEmpty());
            Finding.ChainFinding cf = (Finding.ChainFinding) findings.getFirst();
            assertEquals(Severity.CRITICAL, cf.severity());
        }
    }

    @Nested
    class OcspCheckTest {

        private final OcspCheck check = new OcspCheck();

        @Test
        void okWhenChainTooSmall() throws Exception {
            X509Certificate selfSigned = generateCert(365, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(selfSigned), new X509Certificate[]{selfSigned});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.OK),
                    "Expected OK when chain has only one cert");
        }

        @Test
        void checksRealCertWithOcsp() {
            X509Certificate leaf = Certificates.AWS_AMAZON;
            X509Certificate issuer = Certificates.AMAZON_CA;
            X509Certificate[] chain = {leaf, issuer};
            List<Finding> findings = check.check(defaultHandshake(leaf, issuer), chain);
            assertFalse(findings.isEmpty(), "Expected at least one finding");
        }
    }

    @Nested
    class TransparencyCheckTest {

        private final TransparencyCheck check = new TransparencyCheck();

        @Test
        void warningWhenNoSctExtension() throws Exception {
            X509Certificate cert = generateCert(365, 2048, "SHA256WithRSA");
            List<Finding> findings = check.check(defaultHandshake(cert), new X509Certificate[]{cert});
            assertTrue(findings.stream().anyMatch(f -> f.severity() == Severity.WARNING),
                    "Expected WARNING for cert without SCT extension");
        }

        @Test
        void okWithRealCertContainingScts() {
            X509Certificate leaf = Certificates.AWS_AMAZON;
            List<Finding> findings = check.check(defaultHandshake(leaf), new X509Certificate[]{leaf});
            boolean hasSctInfo = findings.stream().anyMatch(f ->
                    f.summary().contains("SCT"));
            assertTrue(hasSctInfo, "Expected SCT-related finding for real cert");
        }
    }
}
