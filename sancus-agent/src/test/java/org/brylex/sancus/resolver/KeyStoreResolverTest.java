package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.util.Util;
import org.junit.Test;

import java.nio.file.Paths;
import java.security.KeyStore;

import static org.brylex.sancus.util.Certificates.*;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 17/08/2017.
 */
public class KeyStoreResolverTest {
    @Test
    public void server_returns_partial_completed_using_keystore() throws Exception {

        final CertificateChain chain = CertificateChain.create(AWS_AMAZON, AMAZON_CA, AMAZON_ROOT, STARFIELD_G2);
        Util.printChain(chain);
        assertThat(chain.last().certificate(), nullValue());
        assertThat(chain.last().dn().getName(), containsString("Starfield Class 2 Certification Authority"));
        assertThat(chain.last().resolvedBy(), equalTo("MISSING"));

        KeyStore jks = Util.loadKeyStore(Paths.get("src/test/resources/jks/aws.jks"), "changeit");
        new KeyStoreResolver("TEST", jks).resolve(chain);
        Util.printChain(chain);
        assertTrue(chain.isComplete());
        assertThat(chain.last().certificate(), is(VALICERT_CLASS2));
        assertThat(chain.last().resolvedBy(), equalTo("TEST"));
    }
}
