package org.brylex.sancus.resolver;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.CertificateChainTest;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.TestServer;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class RemoteResolverTest {

    public static final X509Certificate DIGGERDETTE = loadCertificate("/diggerdette.no.pem");
    public static final X509Certificate LETSENCRYPT = loadCertificate("/letsencrypt.org.pem");
    public static final X509Certificate LOCALHOST = loadCertificate("/ca/intermediate/certs/127.0.0.1.cert.pem");

    @BeforeAll
    static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static X509Certificate loadCertificate(String path) {
        try (InputStream is = CertificateChainTest.class.getResourceAsStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
        }
    }

    @Test
    public void resolveIntermediateViaAccessInfoExtension() throws Exception {

        try (TestServer server = new TestServer()) {

            RemoteResolver resolver = new RemoteResolver();

            final CertificateChain chain = resolver.resolve(CertificateChain.create(LOCALHOST));
            assertNotNull(chain);
            assertFalse(chain.isComplete());
            assertTrue(chain.last().dn().getName().contains("Brylex Development Root CA"));
            assertEquals("MISSING", chain.last().resolvedBy());
            assertNull(chain.last().certificate());
        }

    }

    @Test
    public void diggerDettePkcs7Issuer() throws Exception {

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE, LETSENCRYPT);

        final RemoteResolver resolver = new RemoteResolver() {
            @Override
            byte[] downloadX509CertificateBytes(URL url) {
                return downloadBytes("/dstrootcax3.p7c");
            }
        };


        CertificateChain resolved = resolver.resolve(chain);
        assertNotNull(resolved);
        assertTrue(resolved.isComplete());
        assertTrue(resolved.last().dn().getName().contains("CN=DST Root CA X3"));
    }

    @Test
    public void AWSx509IssuerAndMissingRoot() throws Exception {

        final CertificateChain chain = CertificateChain.create(Certificates.AWS_AMAZON, Certificates.AMAZON_CA, Certificates.AMAZON_ROOT, Certificates.STARFIELD_G2);

        RemoteResolver resolver = new RemoteResolver() {
            @Override
            byte[] downloadX509CertificateBytes(URL url) {
                return downloadBytes("/starfield.class.2.pem");
            }
        };

        CertificateChain resolved = resolver.resolve(chain);
        Util.printChain(resolved);

        assertNotNull(resolved);
        assertFalse(resolved.isComplete());
        assertTrue(resolved.last().dn().getName().contains("OU=ValiCert Class 2 Policy Validation Authority,"));
        assertEquals("MISSING", resolved.last().resolvedBy()); // is not remotely resolvable
    }

    private byte[] downloadBytes(String path) {
        try (InputStream is = CertificateChainTest.class.getResourceAsStream(path)) {
            return is.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException("Test failure - unable to load PEM from filesystem.", e);
        }
    }

    public static class JksBuilder {

        private final Path jksPath;

        public JksBuilder(Path jksPath) {
            this.jksPath = jksPath;
        }

        public void build(CertificateChain chain) {

            KeyStore jks;
            X509TrustManager tm;
            try {

                jks = KeyStore.getInstance("JKS");

                if (jksPath.toFile().isFile()) {

                    try (InputStream is = Files.newInputStream(jksPath, StandardOpenOption.READ)) {
                        jks.load(is, "changeit".toCharArray());
                        System.out.println("Existing keystore loaded...");
                    }

                } else {
                    jks.load(null);
                    System.out.println("Specified KeyStore does not exist. Creating new one.");
                }


                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(jks);

                tm = (X509TrustManager) tmf.getTrustManagers()[0];

            } catch (Exception e) {
                throw new RuntimeException("Unable to initialize keystore");
            }

            chain.visit(new ChainEntry.Visitor() {
                @Override
                public void visit(ChainEntry entry) {
                    if (!"SERVER".equals(entry.resolvedBy())) {
                        System.out.println(" --> " + entry);
                        try {

                            String existingAlias = jks.getCertificateAlias(entry.certificate());
                            if (existingAlias != null) {
                                System.out.println("Certificate allready contained in KeyStore. Ignoring.");
                            } else {

                                String alias = UUID.randomUUID().toString();
                                jks.setCertificateEntry(alias, entry.certificate());
                                System.out.println("Added certificate to keystore [" + alias + "].");
                            }

                        } catch (KeyStoreException e) {
                            e.printStackTrace();
                        }
                    }
                }
            });

            try (OutputStream os = Files.newOutputStream(jksPath, StandardOpenOption.APPEND)) {
                jks.store(os, "changeit".toCharArray());
                System.out.println("Keystore written to [" + jksPath.toAbsolutePath() + "].");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
