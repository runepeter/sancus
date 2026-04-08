package org.brylex.sancus.resolver;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.ResolverSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.logging.Logger;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class RemoteResolver implements CertificateChain.Resolver {

    private static final Logger LOG = Logger.getLogger("sancus");

    final JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

    private static X509Certificate loadCertificate(byte[] bytes) {
        try (InputStream is = new ByteArrayInputStream(bytes)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load DER-encoded certificate.", e);
        }
    }

    private static URL getIssuerCaUrl(X509Certificate certificate) {

        byte[] octetBytes = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octetBytes == null) {
            return null;
        }

        DLSequence dlSequence = null;
        ASN1Encodable asn1Encodable = null;

        try {
            ASN1OctetString octs = ASN1OctetString.getInstance(octetBytes);
            ASN1Primitive fromExtensionValue = ASN1Primitive.fromByteArray(octs.getOctets());
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
                        ASN1TaggedObject taggedObject = (ASN1TaggedObject) value;

                        byte[] encoded = taggedObject.getEncoded();
                        if (taggedObject.getTagNo() == 6) {
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

    byte[] downloadX509CertificateBytes(URL url) {
        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(10000);
            try (InputStream is = connection.getInputStream()) {
                return is.readAllBytes();
            } finally {
                connection.disconnect();
            }
        } catch (IOException e) {
            throw new RuntimeException("Unable to download remote certificate bytes.", e);
        }
    }

    X509Certificate downloadX509Certificate(URL url) {

        byte[] bytes = downloadX509CertificateBytes(url);

        try (InputStream is = new ByteArrayInputStream(bytes)) {

            CMSSignedData sd = new CMSSignedData(is);
            Store<X509CertificateHolder> certificates = sd.getCertificates();

            Collection<X509CertificateHolder> matches = certificates.getMatches(null);
            for (X509CertificateHolder holder : matches) {
                return converter.getCertificate(holder);
            }

        } catch (CMSException e) {

            return loadCertificate(bytes);

        } catch (Exception e) {
            throw new RuntimeException("Certificate could not be downloaded.", e);
        }

        throw new RuntimeException("Certificate not found.");
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {

        ChainEntry issuer = chain.issuedBy();
        if (issuer.certificate() == null) {
            URL url = getIssuerCaUrl(chain.head().certificate());

            if (url != null) {
                LOG.info("Downloading issuer [" + issuer.dn() + "] certificate from [" + url + "]");
                X509Certificate certificate = downloadX509Certificate(url);
                issuer.apply(certificate, ResolverSource.REMOTE);
            }

        }

        resolve(issuer);

        return chain;
    }

    private ChainEntry resolve(ChainEntry entry) {

        if (entry.certificate() == null) {
            return entry;
        } else if (entry.certificate().getSubjectX500Principal().equals(entry.certificate().getIssuerX500Principal())) {
            return entry;
        }

        ChainEntry issuer = entry.issuedBy();

        if (issuer == null) {
            entry.issuedBy(entry.certificate().getIssuerX500Principal());
            issuer = entry.issuedBy();
        }

        if (issuer.certificate() == null) {

            URL url = getIssuerCaUrl(entry.certificate());

            if (url == null) {
                LOG.info("There's no remote download location for [" + issuer.dn() + "].");
                entry.last(issuer);
                return entry;
            }

            LOG.info("Downloading issuer [" + entry.issuedBy().dn() + "] certificate from [" + url + "]");
            X509Certificate certificate = downloadX509Certificate(url);
            issuer.apply(certificate, ResolverSource.REMOTE);
        }

        resolve(issuer);

        return entry;
    }
}
