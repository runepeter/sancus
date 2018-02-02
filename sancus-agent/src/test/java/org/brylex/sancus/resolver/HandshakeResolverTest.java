package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.util.TestServer;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class HandshakeResolverTest {

    @Test
    public void serverReturnsFullChain() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/full-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertThat(chain, notNullValue());
            assertTrue(chain.isComplete());
            assertThat(chain.last().resolvedBy(), equalTo("SERVER"));
        }
    }

    @Test
    public void serverReturnsPartialChain() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/partial-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertThat(chain, notNullValue());
            assertFalse(chain.isComplete());
            assertThat(chain.last().dn().getName(), containsString("Brylex Development Root CA"));
            assertThat(chain.last().resolvedBy(), equalTo("MISSING"));
            assertThat(chain.last().certificate(), nullValue());
        }
    }

    @Test
    public void serverReturnsOnlyServerCertificate() throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/onlyserver-openssl.jks")) {

            HandshakeResolver resolver = new HandshakeResolver("127.0.0.1", 8443);

            final CertificateChain chain = resolver.resolve(CertificateChain.create(empty()));
            assertThat(chain, notNullValue());
            assertFalse(chain.isComplete());
            assertThat(chain.last().dn().getName(), containsString("Brylex Development Intermediate CA"));
            assertThat(chain.last().resolvedBy(), equalTo("MISSING"));
            assertThat(chain.last().certificate(), nullValue());
        }
    }

    private KeyStore empty() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore emptyJks = KeyStore.getInstance("JKS");
        emptyJks.load(null);
        return emptyJks;
    }

}
