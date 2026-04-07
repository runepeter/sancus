package org.brylex.sancus.agent;

import net.bytebuddy.asm.Advice;
import org.brylex.sancus.agent.bootstrap.SancusAgentTrustManager;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

public class SslContextAdvice {

    @Advice.OnMethodEnter
    static void onInit(@Advice.Argument(value = 1, readOnly = false) TrustManager[] tms) {
        if (tms == null) return;

        TrustManager[] wrapped = new TrustManager[tms.length];
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof SancusAgentTrustManager) {
                wrapped[i] = tms[i];
            } else if (tms[i] instanceof X509ExtendedTrustManager ext) {
                wrapped[i] = new SancusAgentTrustManager(ext);
            } else if (tms[i] instanceof X509TrustManager x509) {
                wrapped[i] = new SancusAgentTrustManager(x509);
            } else {
                wrapped[i] = tms[i];
            }
        }
        tms = wrapped;
    }
}
