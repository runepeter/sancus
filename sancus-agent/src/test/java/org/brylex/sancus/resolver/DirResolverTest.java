package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.CertificateChainTest;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.Util;
import org.junit.Test;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.brylex.sancus.util.Certificates.AWS_AMAZON;
import static org.brylex.sancus.util.Certificates.DIGGERDETTE;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;

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

    @Test(expected = IllegalArgumentException.class)
    public void nullDirShouldThrowException() throws Exception {
        new DirResolver(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void resolveNullChainShouldThrowException() throws Exception {

        final Path dir = Paths.get("src/test/resources/");

        new DirResolver(dir).resolve(null);
    }

    @Test
    public void fullyResolve1() throws Exception {

        final Path dir = Paths.get("src/test/resources/");

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE);

        new DirResolver(dir).resolve(chain);
        Util.printChain(chain);

        assertTrue(chain.isComplete());
        assertThat(chain.last().certificate(), notNullValue());
        assertThat(chain.last().dn().getName(), containsString("DST Root CA X3"));
        assertThat(chain.toList().size(), equalTo(3));
    }

    @Test
    public void fullyResolve2() throws Exception {

        final Path dir = Paths.get("src/test/resources/");

        final CertificateChain chain = CertificateChain.create(AWS_AMAZON);

        new DirResolver(dir).resolve(chain);
        Util.printChain(chain);
        assertTrue(chain.isComplete());
        assertThat(chain.last().certificate(), is(Certificates.VALICERT_CLASS2));
        assertThat(chain.toList().size(), equalTo(6));
    }
}