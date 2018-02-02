package org.brylex.sancus;

import org.brylex.sancus.resolver.KeyStoreResolver;
import org.brylex.sancus.util.Util;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class SancusTrustManager implements X509TrustManager {

    private final CertificateChain certificateChain;
    private final X509TrustManager tm;

    public SancusTrustManager(CertificateChain certificateChain, X509TrustManager tm) {
        this.certificateChain = certificateChain;
        this.tm = tm;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return tm.getAcceptedIssuers();
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        tm.checkClientTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        certificateChain.apply(chain);

        new KeyStoreResolver("JKS", certificateChain.jks()).resolve(certificateChain);

        certificateChain.visit(new TrustMarkerVisitor(certificateChain.jks()));

        Util.printChain(certificateChain);

        tm.checkServerTrusted(chain, authType);
    }

}
