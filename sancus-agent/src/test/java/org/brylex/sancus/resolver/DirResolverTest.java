package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.CertificateChainTest;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.brylex.sancus.util.Certificates.AWS_AMAZON;
import static org.brylex.sancus.util.Certificates.DIGGERDETTE;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 21/05/2017.
 */
public class DirResolverTest {

    private static X509Certificate loadCertificate(String path) {
        try (InputStream is = CertificateChainTest.class.getResourceAsStream(path)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            throw new RuntimeException("Unable to load certificate from classpath resources [" + path + "].", e);
        }
    }

    @Test
    void nullDirShouldThrowException() {
        assertThrows(IllegalArgumentException.class, () -> new DirResolver(null));
    }

    @Test
    void resolveNullChainShouldThrowException() {
        final Path dir = Paths.get("src/test/resources/");
        assertThrows(IllegalArgumentException.class, () -> new DirResolver(dir).resolve(null));
    }

    @Test
    void fullyResolve1() throws Exception {

        final Path dir = Paths.get("src/test/resources/");

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE);

        new DirResolver(dir).resolve(chain);
        Util.printChain(chain);

        assertTrue(chain.isComplete());
        assertNotNull(chain.last().certificate());
        assertTrue(chain.last().dn().getName().contains("DST Root CA X3"));
        assertEquals(3, chain.toList().size());
    }

    @Test
    void fullyResolve2() throws Exception {

        final Path dir = Paths.get("src/test/resources/");

        final CertificateChain chain = CertificateChain.create(AWS_AMAZON);

        new DirResolver(dir).resolve(chain);
        Util.printChain(chain);
        assertTrue(chain.isComplete());
        assertEquals(Certificates.VALICERT_CLASS2, chain.last().certificate());
        assertEquals(6, chain.toList().size());
    }
}