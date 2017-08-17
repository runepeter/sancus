package org.brylex.sancus.resolver;

import com.google.common.collect.Maps;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 21/05/2017.
 */
public class DirResolver implements CertificateChain.Resolver {

    private final Path dir;

    public DirResolver(Path dir) {

        checkArgument(dir != null, "Cannot specify NULL certificate directory.");

        this.dir = dir;
    }

    @Override
    public CertificateChain resolve(CertificateChain chain) {

        checkArgument(chain != null, "Cannot resolve NULL certificate chain.");

        final Map<Principal, X509Certificate> map = Maps.newHashMap();

        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");

            Files.newDirectoryStream(dir).forEach(path -> {

                if (path.toString().endsWith(".pem")) {

                    try (InputStream is = Files.newInputStream(path)) {
                        X509Certificate certificate = (X509Certificate) factory.generateCertificate(is);
                        map.put(certificate.getSubjectDN(), certificate);
                    } catch (Exception e) {
                        throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
                    }
                }

            });

        } catch (Exception e) {
            throw new RuntimeException("Unable to resolve CertificateChain from directory [" + dir.toAbsolutePath() + "].", e);
        }

        ChainEntry issuer = chain.issuedBy();
        if (issuer.certificate() == null && map.containsKey(issuer.dn())) {
            X509Certificate issuerCertificate = map.get(issuer.dn());
            issuer.apply(issuerCertificate, "DIR");
        }

        resolve(issuer, map);

        return chain;
    }

    private ChainEntry resolve(ChainEntry entry, Map<Principal, X509Certificate> map) {

        if (entry.certificate() == null) {
            return entry;
        } else if (entry.certificate().getSubjectDN().equals(entry.certificate().getIssuerDN())) {
            return entry;
        }

        ChainEntry issuer = entry.issuedBy();
        if (issuer == null) {

            Principal issuerDN = entry.certificate().getIssuerDN();
            if (map.containsKey(issuerDN)) {
                issuer = entry.issuedBy(map.get(issuerDN));
                issuer.resolvedBy("DIR");
            } else {
                issuer = entry.issuedBy(issuerDN);
                issuer.resolvedBy("MISSING");
            }
        }

        if (issuer.certificate() == null && map.containsKey(issuer.dn())) {
            issuer.apply(map.get(issuer.dn()), "DIR");
        }

        resolve(issuer, map);

        return entry;
    }
}
