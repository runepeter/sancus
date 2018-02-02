package org.brylex.sancus.cli.command;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.TrustMarkerVisitor;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.UserInput;
import org.brylex.sancus.util.Util;
import org.junit.Test;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Iterator;

import static org.brylex.sancus.util.Certificates.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 25/08/2017.
 */
public class SaveCommandHandlerTest {

    @Test
    public void name() throws Exception {

        final KeyStore jks = create(LETSENCRYPT);

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE, LETSENCRYPT, DST_ROOT);

        chain.visit(new TrustMarkerVisitor(jks));

        final Iterator<String> input = Arrays.asList("3", "q", "target/junit.jks").iterator();

        final SaveCommandHandler handler = new SaveCommandHandler(new UserInput() {
            @Override
            public String input(String prompt) {
                System.out.print(prompt + ": ");
                return input.next();
            }
        });

        handler.handle(chain, jks);

        Util.printChain(chain);
    }

    private static KeyStore create(X509Certificate certificate, X509Certificate ... certificates) {

        try {
            final KeyStore jks = KeyStore.getInstance("JKS");
            jks.load(null);

            jks.setCertificateEntry("test0", certificate);

            for (int i=0;i<certificates.length;i++) {
                jks.setCertificateEntry("test" + (i + 1), certificate);
            }

            return jks;

        } catch (Exception e) {
            throw new RuntimeException("Unable to create JKS.", e);
        }
    }

}
