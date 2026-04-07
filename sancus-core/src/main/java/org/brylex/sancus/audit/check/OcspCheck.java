package org.brylex.sancus.audit.check;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.brylex.sancus.audit.AuditCheck;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.RevocationFinding;
import org.brylex.sancus.audit.HandshakeInfo;
import org.brylex.sancus.audit.Severity;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class OcspCheck implements AuditCheck {

    @Override
    public List<Finding> check(HandshakeInfo handshakeInfo, X509Certificate[] chain) {
        if (chain.length < 2) {
            return List.of(new RevocationFinding(
                    chain.length > 0 ? chain[0].getSubjectX500Principal().getName() : "unknown",
                    Severity.OK, "skipped", "n/a"));
        }

        X509Certificate leaf = chain[0];
        X509Certificate issuer = chain[1];
        String cn = leaf.getSubjectX500Principal().getName();

        String ocspUrl = getOcspResponderUrl(leaf);
        if (ocspUrl == null) {
            return List.of(new RevocationFinding(cn, Severity.OK, "no-responder", "n/a"));
        }

        try {
            OCSPReq request = buildOcspRequest(leaf, issuer);
            OCSPResp response = sendOcspRequest(ocspUrl, request);

            if (response.getStatus() != OCSPResp.SUCCESSFUL) {
                return List.of(new RevocationFinding(cn, Severity.WARNING,
                        "error-" + response.getStatus(), ocspUrl));
            }

            BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
            List<Finding> findings = new ArrayList<>();

            for (SingleResp singleResp : basicResp.getResponses()) {
                var certStatus = singleResp.getCertStatus();
                if (certStatus == null) {
                    findings.add(new RevocationFinding(cn, Severity.OK, "good", ocspUrl));
                } else if (certStatus instanceof RevokedStatus) {
                    findings.add(new RevocationFinding(cn, Severity.CRITICAL, "revoked", ocspUrl));
                } else if (certStatus instanceof UnknownStatus) {
                    findings.add(new RevocationFinding(cn, Severity.WARNING, "unknown", ocspUrl));
                }
            }

            return findings.isEmpty()
                    ? List.of(new RevocationFinding(cn, Severity.WARNING, "no-response", ocspUrl))
                    : findings;

        } catch (Exception e) {
            return List.of(new RevocationFinding(cn, Severity.OK, "skipped", ocspUrl));
        }
    }

    private static String getOcspResponderUrl(X509Certificate certificate) {
        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octetBytes == null) {
            return null;
        }

        try {
            ASN1OctetString octs = ASN1OctetString.getInstance(octetBytes);
            ASN1Primitive fromExtensionValue = ASN1Primitive.fromByteArray(octs.getOctets());
            if (!(fromExtensionValue instanceof DLSequence dlSequence)) {
                return null;
            }

            for (int i = 0; i < dlSequence.size(); i++) {
                ASN1Encodable asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DLSequence keyValue) {
                    if (keyValue.getObjectAt(0).equals(X509ObjectIdentifiers.id_ad_ocsp)) {
                        ASN1Encodable value = keyValue.getObjectAt(1);
                        ASN1TaggedObject taggedObject = (ASN1TaggedObject) value;
                        byte[] encoded = taggedObject.getEncoded();
                        if (taggedObject.getTagNo() == 6) {
                            int len = encoded[1];
                            return new String(encoded, 2, len);
                        }
                    }
                }
            }

            return null;
        } catch (IOException e) {
            return null;
        }
    }

    private static OCSPReq buildOcspRequest(X509Certificate leaf, X509Certificate issuer) throws Exception {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        CertificateID certId = new CertificateID(
                digCalcProv.get(CertificateID.HASH_SHA1),
                new X509CertificateHolder(issuer.getEncoded()),
                leaf.getSerialNumber());

        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        return builder.build();
    }

    private static OCSPResp sendOcspRequest(String urlString, OCSPReq request) throws Exception {
        byte[] requestBytes = request.getEncoded();
        URL url = URI.create(urlString).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/ocsp-request");
        connection.setRequestProperty("Accept", "application/ocsp-response");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(10000);
        connection.setDoOutput(true);

        try (OutputStream out = connection.getOutputStream()) {
            out.write(requestBytes);
        }

        try (InputStream in = connection.getInputStream()) {
            return new OCSPResp(in.readAllBytes());
        } finally {
            connection.disconnect();
        }
    }
}
