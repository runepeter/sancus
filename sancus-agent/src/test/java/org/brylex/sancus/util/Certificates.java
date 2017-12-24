package org.brylex.sancus.util;

import org.brylex.sancus.CertificateChainTest;
import org.brylex.sancus.resolver.DirResolverTest;
import org.brylex.sancus.resolver.RemoteResolverTest;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 17/08/2017.
 */
public class Certificates {

    public static final X509Certificate AWS_AMAZON = loadCertificate("/aws.amazon.com.pem");
    public static final X509Certificate AMAZON_CA = loadCertificate("/amazon.ca.pem");
    public static final X509Certificate AMAZON_ROOT = loadCertificate("/amazon.root.pem");
    public static final X509Certificate STARFIELD_G2 = loadCertificate("/starfield.g2.pem");
    public static final X509Certificate STARFIELD_CLASS2 = loadCertificate("/starfield.class.2.pem");
    public static final X509Certificate VALICERT_CLASS2 = loadCertificate("/valicert.class.2.pem");
    public static final X509Certificate DIGGERDETTE = loadCertificate("/diggerdette.no.pem");
    public static final X509Certificate LETSENCRYPT = loadCertificate("/letsencrypt.org.pem");
    public static final X509Certificate DST_ROOT = loadCertificate("/dst.root.x3.pem");

    private Certificates() {
    }

    private static X509Certificate loadCertificate(String path) {
        try (InputStream is = CertificateChainTest.class.getResourceAsStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
        }
    }
}
