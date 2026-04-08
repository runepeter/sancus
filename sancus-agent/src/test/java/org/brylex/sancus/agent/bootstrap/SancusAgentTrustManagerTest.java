package org.brylex.sancus.agent.bootstrap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentTrustManagerTest {

    private static final X509Certificate SELF_SIGNED_CERT;

    static {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            try (InputStream is = SancusAgentTrustManagerTest.class.getResourceAsStream("/jks/selfsigned.jks")) {
                ks.load(is, "changeit".toCharArray());
            }
            SELF_SIGNED_CERT = (X509Certificate) ks.getCertificate("test");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private X509Certificate[] chain;
    private List<Object[]> callbackInvocations;

    @BeforeEach
    void setUp() {
        chain = new X509Certificate[0];
        callbackInvocations = new ArrayList<>();
        // Reset callbacks before each test
        SancusAgentTrustManager.auditCallback = null;
        SancusAgentTrustManager.resolveCallback = null;
    }

    private BiConsumer<X509Certificate[], Boolean> captureCallback() {
        BiConsumer<X509Certificate[], Boolean> cb = (certs, rejected) ->
                callbackInvocations.add(new Object[]{certs, rejected});
        SancusAgentTrustManager.auditCallback = cb;
        return cb;
    }

    // --- Extended delegate ---

    @Test
    void delegatesToOriginal_extended() throws Exception {
        AtomicBoolean delegateCalled = new AtomicBoolean(false);
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> delegateCalled.set(true), false);
        captureCallback();

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(chain, "RSA");

        assertTrue(delegateCalled.get());
    }

    @Test
    void callbackOnSuccess_rejected_false() throws Exception {
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> {}, false);
        captureCallback();

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(chain, "RSA");

        assertEquals(1, callbackInvocations.size());
        assertFalse((Boolean) callbackInvocations.get(0)[1]);
    }

    @Test
    void callbackOnRejection_rejected_true() {
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> {
            throw new CertificateException("untrusted");
        }, false);
        captureCallback();

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        assertThrows(CertificateException.class, () -> tm.checkServerTrusted(chain, "RSA"));

        assertEquals(1, callbackInvocations.size());
        assertTrue((Boolean) callbackInvocations.get(0)[1]);
    }

    @Test
    void propagatesException() {
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> {
            throw new CertificateException("propagated");
        }, false);
        captureCallback();

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        CertificateException ex = assertThrows(CertificateException.class,
                () -> tm.checkServerTrusted(chain, "RSA"));
        assertEquals("propagated", ex.getMessage());
    }

    // --- Non-extended delegate ---

    @Test
    void nonExtendedDelegateFallsBackTo2Arg() throws Exception {
        AtomicBoolean delegateCalled = new AtomicBoolean(false);
        X509TrustManager simpleDelegate = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegateCalled.set(true);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        captureCallback();

        SancusAgentTrustManager tm = new SancusAgentTrustManager(simpleDelegate);
        tm.checkServerTrusted(chain, "RSA");

        assertTrue(delegateCalled.get());
        assertEquals(1, callbackInvocations.size());
        assertFalse((Boolean) callbackInvocations.get(0)[1]);
    }

    // --- Callback exception safety ---

    @Test
    void callbackExceptionDoesNotAffectDelegation() throws Exception {
        AtomicBoolean delegateCalled = new AtomicBoolean(false);
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> delegateCalled.set(true), false);
        SancusAgentTrustManager.auditCallback = (certs, rejected) -> {
            throw new RuntimeException("callback explosion");
        };

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        // Should NOT throw despite callback failing
        assertDoesNotThrow(() -> tm.checkServerTrusted(chain, "RSA"));
        assertTrue(delegateCalled.get());
    }

    // --- Resolve callback tests ---

    @Test
    void delegatesResolvedChainWhenCallbackSet() throws Exception {
        X509Certificate cert = SELF_SIGNED_CERT;
        X509Certificate[] original = { cert };
        X509Certificate[] extended = { cert, cert };

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = c -> extended;

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertArrayEquals(extended, delegate.capturedChain);
    }

    @Test
    void usesOriginalChainWhenCallbackNull() throws Exception {
        X509Certificate cert = SELF_SIGNED_CERT;
        X509Certificate[] original = { cert };

        CapturingDelegate delegate = new CapturingDelegate();
        // resolveCallback is already null from setUp

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertArrayEquals(original, delegate.capturedChain);
    }

    @Test
    void failOpenWhenCallbackThrows() throws Exception {
        X509Certificate cert = SELF_SIGNED_CERT;
        X509Certificate[] original = { cert };

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = c -> { throw new RuntimeException("boom"); };

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertArrayEquals(original, delegate.capturedChain);
    }

    @Test
    void auditsWithOriginalChain() throws Exception {
        X509Certificate cert = SELF_SIGNED_CERT;
        X509Certificate[] original = { cert };
        X509Certificate[] extended = { cert, cert };

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = c -> extended;

        AtomicReference<X509Certificate[]> auditedChain = new AtomicReference<>();
        SancusAgentTrustManager.auditCallback = (certs, rejected) -> auditedChain.set(certs);

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertSame(original, auditedChain.get(), "fireAudit must receive original chain, not resolved");
    }

    @Test
    void setsThreadLocalWithResolvedChain() throws Exception {
        X509Certificate cert = SELF_SIGNED_CERT;
        X509Certificate[] original = { cert };
        X509Certificate[] extended = { cert, cert };

        CapturingDelegate delegate = new CapturingDelegate();
        SancusAgentTrustManager.resolveCallback = c -> extended;

        AtomicReference<X509Certificate[]> threadLocalDuringAudit = new AtomicReference<>();
        SancusAgentTrustManager.auditCallback = (certs, rejected) ->
                threadLocalDuringAudit.set(SancusAgentTrustManager.lastResolvedChain.get());

        SancusAgentTrustManager tm = new SancusAgentTrustManager(delegate);
        tm.checkServerTrusted(original, "RSA");

        assertArrayEquals(extended, threadLocalDuringAudit.get(), "ThreadLocal must be set during audit");
        assertNull(SancusAgentTrustManager.lastResolvedChain.get(), "ThreadLocal must be cleared after");
    }

    // --- CapturingDelegate ---

    private static class CapturingDelegate extends X509ExtendedTrustManager {
        volatile X509Certificate[] capturedChain;

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            capturedChain = chain;
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            capturedChain = chain;
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            capturedChain = chain;
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    // --- Helper ---

    private X509ExtendedTrustManager newExtendedDelegate(ThrowingRunnable serverCheck, boolean fail) {
        return new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                runCheck();
            }
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                runCheck();
            }
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                runCheck();
            }
            @Override
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }

            private void runCheck() throws CertificateException {
                try {
                    serverCheck.run();
                } catch (CertificateException e) {
                    throw e;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
