package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.ResolverSource;
import org.brylex.sancus.util.TestServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class HandshakeResolverTest {

    @Test
    public void serverReturnsFullChain() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/full-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertNotNull(chain);
            assertTrue(chain.isComplete());
            assertEquals(ResolverSource.SERVER, chain.last().resolvedBy());
        }
    }

    @Test
    void serverReturnsPartialChain() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/partial-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertNotNull(chain);
            assertFalse(chain.isComplete());
            assertTrue(chain.last().dn().getName().contains("Brylex Development Root CA"));
            assertEquals(ResolverSource.MISSING, chain.last().resolvedBy());
            assertNull(chain.last().certificate());
        }
    }

    @Test
    void serverReturnsOnlyServerCertificate() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/onlyserver-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertNotNull(chain);
            assertFalse(chain.isComplete());
            assertTrue(chain.last().dn().getName().contains("Brylex Development Intermediate CA"));
            assertEquals(ResolverSource.MISSING, chain.last().resolvedBy());
            assertNull(chain.last().certificate());
        }
    }

    private KeyStore empty() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore emptyJks = KeyStore.getInstance("JKS");
        emptyJks.load(null);
        return emptyJks;
    }

}
