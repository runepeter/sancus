package org.brylex.sancus;

import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class SancusTrustManager implements X509TrustManager {

    private final KeyStore keyStore;
    private final X509TrustManager tm;
    private final CertificateChain.Callback callback;

    public SancusTrustManager(KeyStore keyStore, X509TrustManager tm, CertificateChain.Callback callback) {
        this.keyStore = keyStore;
        this.tm = tm;
        this.callback = callback;
    }

    public X509Certificate[] getAcceptedIssuers() {
        return tm.getAcceptedIssuers();
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        tm.checkClientTrusted(chain, authType);
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        final CertificateChain certificateChain = CertificateChain.create(chain);

        new KeyStoreResolver("JKS", keyStore).resolve(certificateChain);
        //new KeyStoreResolver("DEFAULT", null).resolve(certificateChain);

        certificateChain.visit(new TrustMarkerVisitor(keyStore));
        callback.onCertificateChain(certificateChain);

        tm.checkServerTrusted(chain, authType);
    }

}
