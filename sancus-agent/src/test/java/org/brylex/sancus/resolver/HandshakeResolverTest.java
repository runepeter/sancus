package org.brylex.sancus.resolver;

import org.brylex.sancus.CertificateChain;
import org.junit.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 15/08/2017.
 */
public class HandshakeResolverTest {

    @Test
    public void name() throws Exception {

        HandshakeResolver resolver = new HandshakeResolver("diggerdette.no", 443);

        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null);

        CertificateChain chain = resolver.resolve(CertificateChain.create(jks));
        System.out.println(chain);

    }

    private Path resolveDefaultJksPath() {

        Path path = getEffectiveDefaultJksPath();

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("DEFAULT").reset().a(" [").bold().a(path.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return path;
    }

    private Path getEffectiveDefaultJksPath() {
        String javaHome = System.getProperty("java.home");

        Path path = Paths.get(javaHome, "lib/security/jssecacerts");
        if (!path.toFile().exists()) {
            path = Paths.get(javaHome, "lib/security/cacerts");
        }
        return path;
    }
}
