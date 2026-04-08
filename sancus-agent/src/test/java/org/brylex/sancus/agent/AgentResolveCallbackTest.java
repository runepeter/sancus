package org.brylex.sancus.agent;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class AgentResolveCallbackTest {

    @Test
    void implementsFunctionInterface() {
        AgentResolveCallback callback = new AgentResolveCallback();
        assertInstanceOf(Function.class, callback);
    }

    @Test
    void returnsInputChainWhenNoResolutionNeeded() {
        AgentResolveCallback callback = new AgentResolveCallback();
        X509Certificate[] chain = new X509Certificate[0];

        X509Certificate[] result = callback.apply(chain);

        assertSame(chain, result, "Should return original chain when no resolution is needed");
    }

    @Test
    void returnsOriginalChainOnNullInput() {
        AgentResolveCallback callback = new AgentResolveCallback();

        X509Certificate[] result = callback.apply(null);

        assertNull(result, "Should return null when input is null");
    }
}
