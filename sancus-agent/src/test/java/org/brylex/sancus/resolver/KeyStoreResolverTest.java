package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.security.KeyStore;

import static org.brylex.sancus.util.Certificates.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 17/08/2017.
 */
public class KeyStoreResolverTest {
    @Test
    public void server_returns_partial_completed_using_keystore() throws Exception {

        final CertificateChain chain = CertificateChain.create(AWS_AMAZON, AMAZON_CA, AMAZON_ROOT, STARFIELD_G2);
        Util.printChain(chain);
        assertNull(chain.last().certificate());
        assertTrue(chain.last().dn().getName().contains("Starfield Class 2 Certification Authority"));
        assertEquals("MISSING", chain.last().resolvedBy());

        KeyStore jks = Util.loadKeyStore(Paths.get("src/test/resources/jks/aws.jks"), "changeit");
        new KeyStoreResolver("TEST", jks).resolve(chain);
        Util.printChain(chain);
        assertTrue(chain.isComplete());
        assertEquals(VALICERT_CLASS2, chain.last().certificate());
        assertEquals("TEST", chain.last().resolvedBy());
    }
}
