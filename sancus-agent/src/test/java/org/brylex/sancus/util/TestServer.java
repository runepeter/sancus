package org.brylex.sancus.util;

import com.google.common.io.ByteStreams;
import com.sun.net.httpserver.*;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 25/12/2017.
 */
public class TestServer implements AutoCloseable {

    private final HttpsServer https;
    private final HttpServer http;

    public TestServer() {
        this("src/test/resources/jks/full-openssl.jks");
    }

    public TestServer(final String jksPath) {
        try {
            this.https = createHttpsServer(jksPath);
            this.http = createIssuerCertificateEndpoint();
        } catch (Exception e) {
            throw new RuntimeException("Unable to create/start HTTPS https.", e);
        }
    }

    public static void main(String[] args) throws Exception {

        try (TestServer server = new TestServer("src/test/resources/jks/full-openssl.jks")) {
            System.out.println("RUNNING...");
            Thread.sleep(Long.MAX_VALUE);
        }
    }

    private HttpsServer createHttpsServer(String jksPath) throws Exception {

        final char[] password = "changeit".toCharArray();

        final KeyStore jks = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(jksPath)) {
            jks.load(is, password);
        }

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(jks, password);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(jks);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(8443), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(final HttpsParameters parameters) {

                try {
                    SSLContext context = SSLContext.getDefault();
                    SSLEngine engine = context.createSSLEngine();
                    parameters.setNeedClientAuth(false);
                    parameters.setCipherSuites(engine.getEnabledCipherSuites());
                    parameters.setProtocols(engine.getEnabledProtocols());

                    SSLParameters defaultSSLParameters = context.getDefaultSSLParameters();
                    parameters.setSSLParameters(defaultSSLParameters);

                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });

        server.createContext("/test", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                System.out.println("JALLA");
            }
        });

        server.start();

        return server;
    }

    private HttpServer createIssuerCertificateEndpoint() throws Exception {

        HttpServer s = HttpServer.create(new InetSocketAddress(8880), 0);
        s.createContext("/brylex.cer", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {

                byte[] bytes = ByteStreams.toByteArray(TestServer.class.getResourceAsStream("/ca/certs/ca.cert.pem"));
                exchange.sendResponseHeaders(200, bytes.length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        });

        s.createContext("/brylex-intermediate.cer", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {

                byte[] bytes = ByteStreams.toByteArray(TestServer.class.getResourceAsStream("/ca/intermediate/certs/intermediate.cert.pem"));
                exchange.sendResponseHeaders(200, bytes.length);

                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            }
        });

        s.start();

        return s;
    }

    @Override
    public void close() throws Exception {
        this.https.stop(0);
        this.http.stop(0);
    }

}
