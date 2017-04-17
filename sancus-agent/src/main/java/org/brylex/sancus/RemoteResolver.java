package org.brylex.sancus;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
class RemoteResolver implements CertificateChain.Resolver {

    private static X509Certificate downloadX509Certificate(URL url) {

        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

        try (InputStream is = url.openStream()) {

            CMSSignedData sd = new CMSSignedData(is);
            Store certificates = sd.getCertificates();

            Collection matches = certificates.getMatches(null);
            for (Object match : matches) {
                X509CertificateHolder holder = (X509CertificateHolder) match;
                return converter.getCertificate(holder);
            }

        } catch (Exception e) {
            throw new RuntimeException("Certificate could not be downloaded.", e);
        }

        throw new RuntimeException("Certificate not found.");
    }

    private static URL getIssuerCaUrl(X509Certificate certificate) {

        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        DLSequence dlSequence = null;
        ASN1Encodable asn1Encodable = null;

        try {
            ASN1Primitive fromExtensionValue = X509ExtensionUtil.fromExtensionValue(octetBytes);
            if (!(fromExtensionValue instanceof DLSequence)) {
                return null;
            }

            dlSequence = (DLSequence) fromExtensionValue;
            for (int i = 0; i < dlSequence.size(); i++) {
                asn1Encodable = dlSequence.getObjectAt(i);
                if (asn1Encodable instanceof DLSequence) {

                    DLSequence keyValue = (DLSequence) asn1Encodable;
                    if (keyValue.getObjectAt(0).equals(X509ObjectIdentifiers.id_ad_caIssuers)) {

                        ASN1Encodable value = keyValue.getObjectAt(1);
                        DERTaggedObject derTaggedObject = (DERTaggedObject) value;

                        byte[] encoded = derTaggedObject.getEncoded();
                        if (derTaggedObject.getTagNo() == 6) {
                            int len = encoded[1];
                            return new URL(new String(encoded, 2, len));
                        }
                    }
                }
            }

            return null;

        } catch (IOException e) {
            throw new RuntimeException("Unable to resolve Issuing CA certificate.", e);
        }
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {

        ChainEntry issuer = chain.issuedBy();
        if (issuer.certificate() == null) {
            URL url = getIssuerCaUrl(chain.head().certificate());
            System.out.println("URL 1: " + url);
        }

        resolve(issuer);

        return chain;
    }

    private ChainEntry resolve(ChainEntry entry) {

        if (entry.certificate() == null) {
            System.out.println("UNRESOLVABLE? " + entry.dn());
        }

        if (entry.certificate().getSubjectDN().equals(entry.certificate().getIssuerDN())) {
            return entry;
        }

        ChainEntry issuer = entry.issuedBy();
        if (issuer.certificate() == null) {
            URL url = getIssuerCaUrl(entry.certificate());
            System.out.println("URL 2: " + url);
            X509Certificate certificate = downloadX509Certificate(url);
            issuer.apply(certificate, "REMOTE");
        }

        resolve(issuer);

        return entry;
    }
}
