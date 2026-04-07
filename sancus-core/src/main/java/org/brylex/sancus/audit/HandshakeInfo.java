package org.brylex.sancus.audit;

import java.security.cert.X509Certificate;

public record HandshakeInfo(String protocol, String cipherSuite, X509Certificate[] serverChain) {
}
