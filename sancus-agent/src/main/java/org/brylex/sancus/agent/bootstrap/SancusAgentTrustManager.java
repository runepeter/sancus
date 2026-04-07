package org.brylex.sancus.agent.bootstrap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;

/**
 * Bootstrap shim — lives in the bootstrap classloader. NO references to sancus-core allowed.
 * Only JDK types + the BiConsumer callback that is injected by premain().
 */
public class SancusAgentTrustManager extends X509ExtendedTrustManager {

    /** Set by premain() from agent classloader. Volatile for visibility across threads. */
    public static volatile BiConsumer<X509Certificate[], Boolean> auditCallback = null;

    private final X509ExtendedTrustManager extendedDelegate;
    private final X509TrustManager simpleDelegate;
    private final boolean delegateIsExtended;

    public SancusAgentTrustManager(X509ExtendedTrustManager delegate) {
        this.extendedDelegate = delegate;
        this.simpleDelegate = delegate;
        this.delegateIsExtended = true;
    }

    public SancusAgentTrustManager(X509TrustManager delegate) {
        this.extendedDelegate = null;
        this.simpleDelegate = delegate;
        this.delegateIsExtended = false;
    }

    // ---- checkServerTrusted (3 overloads) ----

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException thrown = null;
        try {
            simpleDelegate.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                extendedDelegate.checkServerTrusted(chain, authType, socket);
            } else {
                simpleDelegate.checkServerTrusted(chain, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        CertificateException thrown = null;
        try {
            if (delegateIsExtended) {
                extendedDelegate.checkServerTrusted(chain, authType, engine);
            } else {
                simpleDelegate.checkServerTrusted(chain, authType);
            }
        } catch (CertificateException e) {
            thrown = e;
        } finally {
            fireAudit(chain, thrown != null);
        }
        if (thrown != null) throw thrown;
    }

    // ---- checkClientTrusted (3 overloads) — pure delegation ----

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        simpleDelegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        if (delegateIsExtended) {
            extendedDelegate.checkClientTrusted(chain, authType, socket);
        } else {
            simpleDelegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        if (delegateIsExtended) {
            extendedDelegate.checkClientTrusted(chain, authType, engine);
        } else {
            simpleDelegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return simpleDelegate.getAcceptedIssuers();
    }

    // ---- Internal ----

    private void fireAudit(X509Certificate[] chain, boolean rejected) {
        try {
            BiConsumer<X509Certificate[], Boolean> cb = auditCallback;
            if (cb != null) {
                cb.accept(chain, rejected);
            }
        } catch (Exception ignored) {
            // Callback must never affect SSL handshake outcome
        }
    }
}
