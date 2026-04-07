package org.brylex.sancus.agent;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentIT {

    private HttpsServer httpsServer;
    private int serverPort;
    private final List<String> capturedMessages = Collections.synchronizedList(new ArrayList<>());
    private Handler testHandler;

    @BeforeEach
    void setUp() throws Exception {
        // Clear caches and config to avoid test interference
        AuditCache.INSTANCE.clear();
        AgentConfig.reset();

        // Set log level to OK so all findings are visible
        System.setProperty("sancus.log.level", "OK");
        AgentConfig.reset(); // Reset again so config picks up new property

        // Install JUL handler to capture log messages
        testHandler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                String msg = record.getMessage();
                if (record.getParameters() != null && record.getParameters().length > 0) {
                    msg = MessageFormat.format(msg, record.getParameters());
                }
                capturedMessages.add(msg);
            }

            @Override
            public void flush() {}

            @Override
            public void close() {}
        };
        Logger.getLogger("sancus").addHandler(testHandler);

        // Load the self-signed keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = getClass().getResourceAsStream("/jks/selfsigned.jks")) {
            assertNotNull(is, "selfsigned.jks not found on classpath");
            ks.load(is, "changeit".toCharArray());
        }

        // Set up KeyManagerFactory for the server
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());

        // Create server SSL context (not intercepted by agent — we init it with KeyManagers only)
        SSLContext serverSslContext = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        serverSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Start HTTPS server
        httpsServer = HttpsServer.create(new InetSocketAddress(0), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverSslContext));
        httpsServer.createContext("/test", exchange -> {
            byte[] response = "OK".getBytes();
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        httpsServer.start();
        serverPort = httpsServer.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (httpsServer != null) {
            httpsServer.stop(0);
        }
        Logger.getLogger("sancus").removeHandler(testHandler);
        System.clearProperty("sancus.log.level");
        AgentConfig.reset();
    }

    @Test
    void agentInterceptsTlsHandshakeAndLogsFinding() throws Exception {
        // Create client SSLContext that TRUSTS the self-signed cert
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (InputStream is = getClass().getResourceAsStream("/jks/selfsigned.jks")) {
            trustStore.load(is, "changeit".toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(null, tmf.getTrustManagers(), null);

        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .build()) {

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://localhost:" + serverPort + "/test"))
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
        }

        // Verify that at least one log message contains [sancus]
        boolean hasSancusLog = capturedMessages.stream()
                .anyMatch(msg -> msg.contains("[sancus]"));
        assertTrue(hasSancusLog,
                "Expected log output containing '[sancus]' but got: " + capturedMessages);
    }

    @Test
    void agentLogsRejectedHandshake() throws Exception {
        // Clear caches again for isolation
        AuditCache.INSTANCE.clear();

        // Create client SSLContext with default truststore (won't trust self-signed cert)
        // Must explicitly pass TrustManagers so the agent can wrap them (null TMs are a known limitation)
        TrustManagerFactory defaultTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        defaultTmf.init((KeyStore) null); // initializes with default cacerts
        SSLContext clientSslContext = SSLContext.getInstance("TLS");
        clientSslContext.init(null, defaultTmf.getTrustManagers(), null);

        try (HttpClient client = HttpClient.newBuilder()
                .sslContext(clientSslContext)
                .build()) {

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://localhost:" + serverPort + "/test"))
                    .GET()
                    .build();

            assertThrows(IOException.class, () ->
                    client.send(request, HttpResponse.BodyHandlers.ofString()));
        }

        // Verify that log output contains [REJECTED]
        boolean hasRejectedLog = capturedMessages.stream()
                .anyMatch(msg -> msg.contains("[REJECTED]"));
        assertTrue(hasRejectedLog,
                "Expected log output containing '[REJECTED]' but got: " + capturedMessages);
    }
}
