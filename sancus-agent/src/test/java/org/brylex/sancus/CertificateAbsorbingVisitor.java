package org.brylex.sancus;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class CertificateAbsorbingVisitor implements ChainEntry.Visitor {

    final Set<X500Principal> set;
    private final KeyStore jks;

    public CertificateAbsorbingVisitor(KeyStore jks) {
        this.jks = jks;
        set = new HashSet<>();
        try {

            Enumeration<String> aliases = jks.aliases();
            while (aliases.hasMoreElements()) {
                X509Certificate issuer = (X509Certificate) jks.getCertificate(aliases.nextElement());
                set.add(issuer.getSubjectX500Principal());
            }

        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to enumerate KeyStore aliases.", e);
        }
    }

    private boolean isCA(X509Certificate certificate) {

        if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return true;
        }

        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage[5];
    }

    @Override
    public void visit(ChainEntry entry) {

        X500Principal dn = entry.dn();
        if (!set.contains(dn)) {
            X509Certificate certificate = entry.certificate();
            if (certificate != null && isCA(certificate)) {
                try {
                    jks.setCertificateEntry(UUID.randomUUID().toString(), entry.certificate());
                    System.out.println("ADDED [" + dn + "]");
                } catch (KeyStoreException e) {
                    throw new RuntimeException("Unable to add certificate entry to KeyStore.", e);
                }
            }
        }
    }
}
