package org.brylex.sancus;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class TrustMarkerVisitor implements ChainEntry.Visitor {

    private final X509TrustManager tm;

    public TrustMarkerVisitor(KeyStore jks) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(jks);

            this.tm = (X509TrustManager) tmf.getTrustManagers()[0];

        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize TrustManagerFactory.", e);
        }
    }

    @Override
    public void visit(ChainEntry entry) {

        for (X509Certificate issuer : tm.getAcceptedIssuers()) {
            if (issuer.getSubjectX500Principal().equals(entry.dn())) {
                entry.trustedBy(TrustStatus.JKS);
                break;
            }
        }
    }

}
