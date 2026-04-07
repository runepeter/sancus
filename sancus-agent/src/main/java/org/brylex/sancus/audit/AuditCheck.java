package org.brylex.sancus.audit;

import java.security.cert.X509Certificate;
import java.util.List;

public interface AuditCheck {

    List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain);
}
