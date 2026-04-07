package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.SancusTrustManager;

import javax.net.ssl.*;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 14/07/2017.
 */
public class HandshakeResolver implements CertificateChain.Resolver {

    private final String host;
    private final int port;

    public HandshakeResolver(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {
        return resolveCertificateChain(chain);
    }

    private CertificateChain resolveCertificateChain(CertificateChain chain) {

        System.out.println("\nPerforming SSL Handshake with [" + host + ":" + port + "] ...\n");

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(chain.jks());

            TrustManager[] defaultTrustManagers = tmf.getTrustManagers();

            SancusTrustManager[] trustManagers = new SancusTrustManager[defaultTrustManagers.length];
            for (int i = 0; i < defaultTrustManagers.length; i++) {
                trustManagers[i] = new SancusTrustManager(chain, (X509TrustManager) defaultTrustManagers[i]);
            }

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustManagers, null);

            SSLSocketFactory factory = context.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(5000);
                socket.startHandshake();
            }

            System.out.println("Status: SUCCESS");

        } catch (Exception e) {

            if (e instanceof UnknownHostException) {
                System.out.println("Status: UNKNOWN_HOST_EXCEPTION");
            } else if (e instanceof SocketTimeoutException) {
                System.out.println("Status: TIMEOUT_EXCEPTION");
            } else if (e instanceof SSLHandshakeException) {
                System.out.println("Status: SSL_HANDSHAKE_EXCEPTION");
                System.out.println(" Cause: " + e.getCause());
            } else {
                throw new RuntimeException(e);
            }
        }

        System.out.println();

        return chain;
    }

}
