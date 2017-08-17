package org.brylex.sancus.resolver;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.CertificateChainTest;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.util.Certificates;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class RemoteResolverTest {

    public static final X509Certificate DIGGERDETTE = loadCertificate("/diggerdette.no.pem");
    public static final X509Certificate LETSENCRYPT = loadCertificate("/letsencrypt.org.pem");


    @BeforeClass
    public static void setUpClass() throws Exception {
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
    public void name() throws Exception {

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE, LETSENCRYPT);

        CertificateChain resolved = new RemoteResolver().resolve(chain);
        System.out.println(resolved);

        new JksBuilder(Paths.get("target/jalla.jks")).build(resolved);

    }

    @Test
    public void aws() throws Exception {

        /*
        [SERVER ][U] CN=aws.amazon.com
[SERVER ][U] CN=Amazon, OU=Server CA 1B, O=Amazon, C=US
[SERVER ][U] CN=Amazon Root CA 1, O=Amazon, C=US
[SERVER ][U] CN=Starfield Services Root Certificate Authority - G2, O="Starfield Technologies, Inc.", L=Scottsdale, ST=Arizona, C=US
[MISSING][U] OU=Starfield Class 2 Certification Authority, O="Starfield Technologies, Inc.", C=US
         */

        final CertificateChain chain = CertificateChain.create(Certificates.AWS_AMAZON, Certificates.AMAZON_CA, Certificates.AMAZON_ROOT, Certificates.STARFIELD_G2);

        CertificateChain resolved = new RemoteResolver().resolve(chain);
        System.out.println(resolved);

        new JksBuilder(Paths.get("target/jalla.jks")).build(resolved);

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
