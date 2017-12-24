package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.SancusTrustManager;
import org.fusesource.jansi.Ansi;

import javax.net.ssl.*;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.util.concurrent.TimeoutException;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.ansi;

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

        System.out.println("\nPerforming SSL Handshake with [" + host + ":" + port + "] ...");

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(chain.jks());

            TrustManager[] defaultTrustManagers = tmf.getTrustManagers();

            SancusTrustManager[] trustManagers = new SancusTrustManager[defaultTrustManagers.length];
            for (int i=0;i<defaultTrustManagers.length;i++) {
                trustManagers[i] = new SancusTrustManager(chain, (X509TrustManager) defaultTrustManagers[i]);
            }

            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, trustManagers, null);

            SSLSocketFactory factory = context.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(5000);
            socket.startHandshake();
            socket.close();

            System.out.println(ansi().a("Status: ").fg(Ansi.Color.GREEN).a("SUCCESS").reset());

        } catch (Exception e) {

            if (e instanceof UnknownHostException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("UNKNOWN_HOST_EXCEPTION").reset());
            } else if (e instanceof TimeoutException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("TIMEOUT_EXCEPTION").reset());
            } else if (e instanceof SSLHandshakeException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("SSL_HANDSHAKE_EXCEPTION").reset());
                System.out.println(ansi().a(" Cause: ").fg(Ansi.Color.YELLOW).a(e.getCause()).reset());
            } else {
                throw new RuntimeException(e);
            }
        }

        System.out.println();

        return chain;
    }

    private Path resolveJksPath() {

        return Paths.get("target/jalla.jks");

        /*if (trustStore == null) {
            return resolveDefaultJksPath();
        }

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("JKS").reset().a(" [").bold().a(trustStore.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return trustStore;*/
    }

    private Path resolveDefaultJksPath() {

        Path path = getEffectiveDefaultJksPath();

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("DEFAULT").reset().a(" [").bold().a(path.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return path;
    }

    private Path getEffectiveDefaultJksPath() {
        String javaHome = System.getProperty("java.home");

        Path path = Paths.get(javaHome, "lib/security/jssecacerts");
        if (!path.toFile().exists()) {
            path = Paths.get(javaHome, "lib/security/cacerts");
        }
        return path;
    }

}
