package org.brylex.sancus;

import com.google.common.collect.Sets;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Set;
import java.util.UUID;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 13/04/2017.
 */
public class CertificateAbsorbingVisitor implements ChainEntry.Visitor {

    final Set<Principal> set;
    private final KeyStore jks;

    public CertificateAbsorbingVisitor(KeyStore jks) {
        this.jks = jks;
        set = Sets.newHashSet();
        try {

            Enumeration<String> aliases = jks.aliases();
            while (aliases.hasMoreElements()) {
                X509Certificate issuer = (X509Certificate) jks.getCertificate(aliases.nextElement());
                set.add(issuer.getSubjectDN());
            }

        } catch (KeyStoreException e) {
            throw new RuntimeException("JALLA", e);
        }
    }

    private boolean isCA(X509Certificate certificate) {

        if (certificate.getSubjectDN().equals(certificate.getIssuerDN())) {
            return true;
        }

        boolean[] keyUsage = certificate.getKeyUsage();
        return keyUsage[5];
    }

    @Override
    public void visit(ChainEntry entry) {

        Principal dn = entry.dn();
        if (!set.contains(dn)) {
            X509Certificate certificate = entry.certificate();
            if (certificate != null && isCA(certificate)) {
                try {
                    jks.setCertificateEntry(UUID.randomUUID().toString(), entry.certificate());
                    System.out.println("ADDED [" + dn + "]");
                } catch (KeyStoreException e) {
                    throw new RuntimeException("BALLA", e);
                }
            }
        }
    }
}
