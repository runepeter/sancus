package org.brylex.sancus.agent;

import java.security.cert.X509Certificate;
import java.util.function.Function;

public class AgentResolveCallback implements Function<X509Certificate[], X509Certificate[]> {

    @Override
    public X509Certificate[] apply(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return chain;
        }
        return chain;
    }
}
