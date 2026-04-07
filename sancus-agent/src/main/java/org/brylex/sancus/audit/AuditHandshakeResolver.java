package org.brylex.sancus.audit;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class AuditHandshakeResolver {

    private AuditHandshakeResolver() {
    }

    public static HandshakeInfo connect(String host, int port) throws AuditConnectionException {
        try {
            TrustManager[] acceptAll = {new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, acceptAll, null);

            SSLSocketFactory factory = context.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(5000);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                String protocol = session.getProtocol();
                String cipherSuite = session.getCipherSuite();
                X509Certificate[] serverChain = Arrays.stream(session.getPeerCertificates())
                        .filter(X509Certificate.class::isInstance)
                        .map(X509Certificate.class::cast)
                        .toArray(X509Certificate[]::new);

                return new HandshakeInfo(protocol, cipherSuite, serverChain);
            }
        } catch (UnknownHostException e) {
            throw new AuditConnectionException("Unknown host: " + host, e);
        } catch (SocketTimeoutException e) {
            throw new AuditConnectionException("Connection timed out connecting to " + host + ":" + port, e);
        } catch (SSLException e) {
            throw new AuditConnectionException("SSL error connecting to " + host + ":" + port + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuditConnectionException("I/O error connecting to " + host + ":" + port + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new AuditConnectionException("Failed to connect to " + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    public static class AuditConnectionException extends Exception {
        public AuditConnectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
