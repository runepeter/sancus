package org.brylex.sancus.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class AgentResolveCallbackTest {

    private X509Certificate selfSignedCert;

    @BeforeEach
    void setUp() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = getClass().getResourceAsStream("/jks/selfsigned.jks")) {
            assertNotNull(is, "selfsigned.jks not found on classpath");
            ks.load(is, "changeit".toCharArray());
        }
        selfSignedCert = (X509Certificate) ks.getCertificate("test");
        assertNotNull(selfSignedCert, "Expected 'test' alias in selfsigned.jks");

        AgentConfig.reset();
    }

    @AfterEach
    void tearDown() {
        AgentConfig.reset();
    }

    @Test
    void returnsOriginalChainWhenAlreadyComplete() {
        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] chain = new X509Certificate[]{selfSignedCert};

        X509Certificate[] result = callback.apply(chain);

        assertArrayEquals(chain, result, "Self-signed cert chain should be returned unchanged");
    }

    @Test
    void cachesResolvedChainByLeafFingerprint() {
        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] chain = new X509Certificate[]{selfSignedCert};

        X509Certificate[] first = callback.apply(chain);
        X509Certificate[] second = callback.apply(chain);

        assertSame(first, second, "Second call should return cached result");
    }

    @Test
    void returnsOriginalChainOnError() {
        AgentResolveCallback callback = new AgentResolveCallback();

        X509Certificate[] nullResult = callback.apply(null);
        assertNull(nullResult, "null input should return null");

        X509Certificate[] emptyChain = new X509Certificate[0];
        X509Certificate[] emptyResult = callback.apply(emptyChain);
        assertSame(emptyChain, emptyResult, "Empty chain should be returned as-is");
    }
}
