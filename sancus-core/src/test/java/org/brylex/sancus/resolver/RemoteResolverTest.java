package org.brylex.sancus.resolver;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ResolverSource;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.TestServer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.brylex.sancus.util.Certificates.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class RemoteResolverTest {

    @BeforeAll
    static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void resolveIntermediateViaAccessInfoExtension() throws Exception {

        try (TestServer server = new TestServer()) {

            RemoteResolver resolver = new RemoteResolver();

            final CertificateChain chain = resolver.resolve(CertificateChain.create(LOCALHOST));
            assertNotNull(chain);
            assertFalse(chain.isComplete());
            assertTrue(chain.last().dn().getName().contains("Brylex Development Root CA"));
            assertEquals(ResolverSource.MISSING, chain.last().resolvedBy());
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

        assertNotNull(resolved);
        assertFalse(resolved.isComplete());
        assertTrue(resolved.last().dn().getName().contains("OU=ValiCert Class 2 Policy Validation Authority,"));
        assertEquals(ResolverSource.MISSING, resolved.last().resolvedBy());
    }

    private byte[] downloadBytes(String path) {
        try (InputStream is = Certificates.class.getResourceAsStream(path)) {
            return is.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException("Test failure - unable to load PEM from filesystem.", e);
        }
    }

}
