package org.brylex.sancus;

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 14/04/2017.
 */
public class SancusTrustManagerFactory extends TrustManagerFactory {

    SancusTrustManagerFactory(final KeyStore keyStore, final TrustManagerFactory delegate, final CertificateChain.Callback callback) {
        super(new TrustManagerFactorySpi() {
            @Override
            protected void engineInit(KeyStore keyStore) throws KeyStoreException {
            }

            @Override
            protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
            }

            @Override
            protected TrustManager[] engineGetTrustManagers() {

                TrustManager[] appTrustManagers = delegate.getTrustManagers();
                SancusTrustManager[] wrapped = new SancusTrustManager[appTrustManagers.length];

                for (int i = 0; i < appTrustManagers.length; i++) {
                    wrapped[i] = new SancusTrustManager(keyStore, (X509TrustManager) appTrustManagers[i], callback);
                }

                return wrapped;
            }
        }, new Provider("sancus_" + delegate.getProvider().getName(), 0.0, "") {
        }, "");
    }

}
