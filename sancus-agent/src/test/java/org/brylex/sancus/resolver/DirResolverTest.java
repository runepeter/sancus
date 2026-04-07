package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.brylex.sancus.util.Certificates.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 21/05/2017.
 */
public class DirResolverTest {

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