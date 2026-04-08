package org.brylex.sancus.agent.bootstrap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class SancusAgentTrustManagerTest {

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

    // --- Resolve callback ---

    @Test
    void resolveCallbackFieldExists() throws Exception {
        // resolveCallback should be a public static volatile field of the correct type
        assertNull(SancusAgentTrustManager.resolveCallback);

        Function<X509Certificate[], X509Certificate[]> resolve = c -> c;
        SancusAgentTrustManager.resolveCallback = resolve;
        assertSame(resolve, SancusAgentTrustManager.resolveCallback);

        // Also verify the field is accessible via reflection (needed for bootstrap copy wiring)
        java.lang.reflect.Field field = SancusAgentTrustManager.class.getField("resolveCallback");
        assertNotNull(field);
        assertTrue(java.lang.reflect.Modifier.isPublic(field.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isStatic(field.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isVolatile(field.getModifiers()));
    }

    @Test
    void resolveCallbackTransformsChainBeforeDelegation() throws Exception {
        X509Certificate[] originalChain = new X509Certificate[0];
        X509Certificate[] resolvedChain = new X509Certificate[]{null}; // different instance

        AtomicReference<X509Certificate[]> chainSeenByDelegate = new AtomicReference<>();
        X509ExtendedTrustManager delegate = newExtendedDelegate(() -> {}, false);

        // Override delegate to capture the chain it receives
        X509TrustManager capturingDelegate = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) {
                chainSeenByDelegate.set(chain);
            }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };

        SancusAgentTrustManager.resolveCallback = c -> resolvedChain;

        SancusAgentTrustManager tm = new SancusAgentTrustManager(capturingDelegate);
        tm.checkServerTrusted(originalChain, "RSA");

        assertSame(resolvedChain, chainSeenByDelegate.get(),
                "Delegate should receive the resolved chain, not the original");
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
