package org.brylex.sancus.audit.check;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.TransparencyFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.List;

public class TransparencyCheck implements AuditCheck {

    private static final String SCT_EXTENSION_OID = "1.3.6.1.4.1.11129.2.4.2";

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        if (chain.length == 0) {
            return List.of(new TransparencyFinding("unknown", Severity.WARNING, 0));
        }

        X509Certificate leaf = chain[0];
        String cn = leaf.getSubjectX500Principal().getName();
        byte[] extensionValue = leaf.getExtensionValue(SCT_EXTENSION_OID);

        if (extensionValue == null) {
            return List.of(new TransparencyFinding(cn, Severity.WARNING, 0));
        }

        try {
            ASN1OctetString outerOcts = ASN1OctetString.getInstance(extensionValue);
            ASN1Primitive inner = ASN1Primitive.fromByteArray(outerOcts.getOctets());
            byte[] sctListBytes = ASN1OctetString.getInstance(inner).getOctets();

            int sctCount = countScts(sctListBytes);

            if (sctCount == 0) {
                return List.of(new TransparencyFinding(cn, Severity.WARNING, 0));
            }

            return List.of(new TransparencyFinding(cn, Severity.OK, sctCount));

        } catch (Exception e) {
            return List.of(new TransparencyFinding(cn, Severity.WARNING, 0));
        }
    }

    private static int countScts(byte[] sctListBytes) {
        ByteBuffer buf = ByteBuffer.wrap(sctListBytes);
        int totalLength = Short.toUnsignedInt(buf.getShort());
        int count = 0;
        int bytesRead = 0;

        while (bytesRead < totalLength && buf.hasRemaining()) {
            int sctLength = Short.toUnsignedInt(buf.getShort());
            buf.position(buf.position() + sctLength);
            bytesRead += 2 + sctLength;
            count++;
        }

        return count;
    }
}
