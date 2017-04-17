package org.brylex.sancus;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class JksTruster implements CertificateChain.Truster {

    private final X509TrustManager trustManager;

    public JksTruster(X509TrustManager trustManager) {
        this.trustManager = trustManager;
    }

    @Override
    public CertificateChain check(CertificateChain chain) {

        List<X509Certificate> certificates = chain.toList();

        try {
            trustManager.checkServerTrusted(toArray(certificates), "ECDHE_ECDSA");
        } catch (CertificateException e) {
            System.out.println("NOT TRUSTED!!");
            e.printStackTrace();
        }

        check(chain.head());

        return chain;
    }

    private ChainEntry check(ChainEntry entry) {

        for (X509Certificate issuer : trustManager.getAcceptedIssuers()) {
            if (issuer.getSubjectDN().equals(entry.dn())) {
                System.out.println("TRUSTED >> " + entry.dn());
            }
        }

        if (entry.issuedBy() != null) {
            check(entry.issuedBy());
        }

        return entry;
    }

    private X509Certificate[] toArray(List<X509Certificate> list) {
        X509Certificate[] array = new X509Certificate[list.size()];
        return list.toArray(array);

    }
}
