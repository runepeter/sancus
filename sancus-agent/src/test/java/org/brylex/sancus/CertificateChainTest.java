package org.brylex.sancus;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.resolver.KeyStoreResolver;
import static org.brylex.sancus.ResolverSource.JKS;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.brylex.sancus.util.Certificates.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class CertificateChainTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static KeyStore jks(String path, String password) {
        return Util.loadKeyStore(Paths.get(path), password);
    }

    @Test
    void emptyCertificateChain() {
        assertThrows(IllegalArgumentException.class, () -> CertificateChain.create());
    }

    @Test
    void emptyNullCertificateChain() {
        assertThrows(IllegalArgumentException.class, () -> CertificateChain.create((X509Certificate[]) null));
    }

    @Test
    void name() throws Exception {

        final CertificateChain chain = CertificateChain.create(CERT_GMAIL);
        assertNotNull(chain);
        assertNotNull(chain.issuedBy());
        assertFalse(chain.isComplete());

        var issuerDn = CERT_GOOGLE_G2.getSubjectX500Principal();
        assertEquals(issuerDn, chain.issuedBy().dn());
        assertNull(chain.issuedBy().certificate());
    }

    @Test
    public void resolveFromDefaultTrustManager() throws Exception {

        final KeyStore jks = jks("src/test/resources/geotrust.jks", "changeit");

        final CertificateChain chain = CertificateChain.create(CERT_AFTENPOSTEN, CERT_GODADDY_G2, CERT_GODADDY_G2_ROOT, CERT_GODADDY_CA);
        //assertFalse(chain.isComplete());
        //assertEquals(3, chain.toList().size());

        resolver().resolve(chain);
        resolver(jks).resolve(chain);
        //chain.visit(new CertificateAbsorbingVisitor(jks));
        chain.visit(new TrustMarkerVisitor(jks));

        System.out.println("Complete? " + chain.isComplete());
        System.out.println(chain);

        //assertEquals(4, chain.toList().size());
        //assertTrue(chain.isComplete());
        //assertThat(chain.last().resolvedBy(), equalTo("JALLA"));
    }

    private KeyStoreResolver resolver() throws Exception {
        return resolver(null);
    }

    private KeyStoreResolver resolver(KeyStore jks) throws Exception {
        return new KeyStoreResolver(JKS, jks);
    }

}