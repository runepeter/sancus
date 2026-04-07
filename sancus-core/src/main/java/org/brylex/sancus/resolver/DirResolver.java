package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.ResolverSource;

import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 21/05/2017.
 */
public class DirResolver implements CertificateChain.Resolver {

    private final Path dir;

    public DirResolver(Path dir) {

        if (dir == null) {
            throw new IllegalArgumentException("Cannot specify NULL certificate directory.");
        }

        this.dir = dir;
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {

        if (chain == null) {
            throw new IllegalArgumentException("Cannot resolve NULL certificate chain.");
        }

        final Map<X500Principal, X509Certificate> map = new HashMap<>();

        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");

            try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                stream.forEach(path -> {

                    if (path.toString().endsWith(".pem")) {

                        try (InputStream is = Files.newInputStream(path)) {
                            X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
                            map.put(certificate.getSubjectX500Principal(), certificate);
                        } catch (Exception e) {
                            throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
                        }
                    }

                });
            }

        } catch (Exception e) {
            throw new RuntimeException("Unable to resolve CertificateChain from directory [" + dir.toAbsolutePath() + "].", e);
        }

        ChainEntry issuer = chain.issuedBy();
        if (issuer.certificate() == null && map.containsKey(issuer.dn())) {
            X509Certificate issuerCertificate = map.get(issuer.dn());
            issuer.apply(issuerCertificate, ResolverSource.DIR);
        }

        resolve(issuer, map);

        return chain;
    }

    private ChainEntry resolve(ChainEntry entry, Map<X500Principal, X509Certificate> map) {

        if (entry.certificate() == null) {
            return entry;
        } else if (entry.certificate().getSubjectX500Principal().equals(entry.certificate().getIssuerX500Principal())) {
            return entry;
        }

        ChainEntry issuer = entry.issuedBy();
        if (issuer == null) {

            X500Principal issuerDN = entry.certificate().getIssuerX500Principal();
            if (map.containsKey(issuerDN)) {
                issuer = entry.issuedBy(map.get(issuerDN));
                issuer.resolvedBy(ResolverSource.DIR);
            } else {
                issuer = entry.issuedBy(issuerDN);
                issuer.resolvedBy(ResolverSource.MISSING);
            }
        }

        if (issuer.certificate() == null && map.containsKey(issuer.dn())) {
            issuer.apply(map.get(issuer.dn()), ResolverSource.DIR);
        }

        resolve(issuer, map);

        return entry;
    }
}
