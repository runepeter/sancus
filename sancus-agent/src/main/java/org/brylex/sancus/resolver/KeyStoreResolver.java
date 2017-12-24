package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.util.Util;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class KeyStoreResolver implements CertificateChain.Resolver {

    private final X509TrustManager[] trustManagers;
    private final String name;

    public KeyStoreResolver(final String name, final KeyStore keyStore) {

        this.name = name;

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            this.trustManagers = toX509(tmf.getTrustManagers());

        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize TrustManagers.", e);
        }
    }

    private static X509TrustManager[] toX509(TrustManager[] trustManagers) {
        X509TrustManager[] array = new X509TrustManager[trustManagers.length];
        for (int i = 0; i < trustManagers.length; i++) {
            array[i] = (X509TrustManager) trustManagers[i];
        }
        return array;
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {

        if (chain.issuedBy() != null) {
            resolve(chain.issuedBy());
        }

        return chain;
    }

    private ChainEntry resolve(ChainEntry entry) {

        if (entry.certificate() == null) {

            boolean applied = false;

            for (X509TrustManager trustManager : trustManagers) {
                for (X509Certificate certificate : trustManager.getAcceptedIssuers()) {
                    if (Util.equals(entry.dn(), certificate.getSubjectDN())) {
                        entry.apply(certificate, name);
                        applied = true;
                        break;
                    }
                }
            }

            if (!applied) {
                return entry;
            }
        }

        if (Util.equals(entry.certificate().getSubjectDN(), entry.certificate().getIssuerDN())) {

            if (entry.resolvedBy() == null) {
                entry.resolvedBy(name);
            }

            return entry;
        }

        resolve(entry.issuedBy());

        return entry;
    }

}
