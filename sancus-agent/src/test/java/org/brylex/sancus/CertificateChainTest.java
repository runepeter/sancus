package org.brylex.sancus;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class CertificateChainTest {

    public static final X509Certificate CERT_GMAIL = loadCertificate("/mail.google.com.pem");
    public static final X509Certificate CERT_AWS = loadCertificate("/aws.amazon.com.pem");
    public static final X509Certificate CERT_AMAZON = loadCertificate("/amazon.pem");
    public static final X509Certificate CERT_AMAZON_CA = loadCertificate("/amazon.ca.pem");
    public static final X509Certificate CERT_STARFIELD_G2 = loadCertificate("/starfield.g2.pem");
    public static final X509Certificate CERT_HEROKU = loadCertificate("/heroku.com.pem");
    public static final X509Certificate CERT_DIGICERT_CA = loadCertificate("/digicert.ca.pem");
    public static final X509Certificate CERT_DIGICERT_ROOT = loadCertificate("/digicert.root.pem");
    public static final X509Certificate CERT_GOOGLE_G2 = loadCertificate("/google.g2.pem");
    public static final X509Certificate CERT_AFTENPOSTEN = loadCertificate("/aftenposten.no.pem");
    public static final X509Certificate CERT_GODADDY_G2 = loadCertificate("/godaddy.g2.pem");
    public static final X509Certificate CERT_GODADDY_G2_ROOT = loadCertificate("/godaddy.g2.root.pem");
    public static final X509Certificate CERT_GODADDY_CA = loadCertificate("/godaddy.ca.pem");
    public static final X509Certificate GEOTRUST = loadCertificate("/geotrust.global.pem");
    public static final X509Certificate DIGGERDETTE = loadCertificate("/diggerdette.no.pem");
    public static final X509Certificate LETSENCRYPT = loadCertificate("/letsencrypt.org.pem");
    public static final X509Certificate VERISIGN_COM = loadCertificate("/verisign.com.pem");
    public static final X509Certificate SYMANTEC_G3 = loadCertificate("/symantec.g3.pem");

    static {
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

    private static KeyStore jks(String path, String password) {

        try {

            KeyStore jks = KeyStore.getInstance("JKS");

            try (InputStream is = new FileInputStream(path)) {
                jks.load(is, password.toCharArray());
            }

            return jks;

        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize JKS.", e);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyCertificateChain() throws Exception {
        CertificateChain.create();
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyNullCertificateChain() throws Exception {
        CertificateChain.create(null);
    }

    @Test
    public void name() throws Exception {

        final CertificateChain chain = CertificateChain.create(CERT_GMAIL);
        assertNotNull(chain);
        assertNotNull(chain.issuedBy());
        assertFalse(chain.isComplete());

        Principal issuerDn = CERT_GOOGLE_G2.getSubjectDN();
        assertThat(chain.issuedBy().dn(), equalTo(issuerDn));
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

    @Test
    public void jalla() throws Exception {

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE, LETSENCRYPT);
        System.out.println(chain);
        System.out.println("===================================================================================================");

        new RemoteResolver().resolve(chain);

        System.out.println(chain);
    }

    private KeyStoreResolver resolver() throws Exception {
        return resolver(null);
    }

    private KeyStoreResolver resolver(KeyStore jks) throws Exception {
        return new KeyStoreResolver("JKS", jks);
    }

}