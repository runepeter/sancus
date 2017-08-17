package org.brylex.sancus.util;

import com.google.common.base.Strings;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.fusesource.jansi.Ansi;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.Principal;
import java.util.List;

import static org.fusesource.jansi.Ansi.Color.RED;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 17/08/2017.
 */
public class Util {

    private Util() {
    }

    public static boolean equals(Principal left, Principal right) {
        try {
            List<Rdn> rdn1 = new LdapName(left.getName()).getRdns();
            List<Rdn> rdn2 = new LdapName(right.getName()).getRdns();

            if(rdn1.size() != rdn2.size()) {
                return false;
            }

            return rdn1.containsAll(rdn2);
        } catch (InvalidNameException e) {
            throw new RuntimeException("Unable to compare certificate subjects.", e);
        }
    }

    public static KeyStore loadKeyStore(Path path, String password) {
        try (InputStream is = Files.newInputStream(path, StandardOpenOption.READ)) {

            KeyStore jks = KeyStore.getInstance("JKS");
            jks.load(is, password.toCharArray());

            return jks;

        } catch (Exception e) {
            throw new RuntimeException("Unable to load KeyStore [" + path.toAbsolutePath() + "].", e);
        }
    }


    public static Path getEffectiveDefaultJksPath() {
        String javaHome = System.getProperty("java.home");

        Path path = Paths.get(javaHome, "lib/security/jssecacerts");
        if (!path.toFile().exists()) {
            path = Paths.get(javaHome, "lib/security/cacerts");
        }
        return path;
    }

    public static void printChain(CertificateChain chain) {
        chain.visit(new ChainEntry.Visitor() {
            @Override
            public void visit(ChainEntry entry) {

                boolean trusted = !entry.trustedBy().equals("NOT");
                String r = Strings.padEnd(entry.resolvedBy(), 7, ' ');
                Ansi.Color rc = r.equals("DEFAULT") ? Ansi.Color.YELLOW : Ansi.Color.BLUE;
                rc = r.equals("MISSING") ? RED : rc;

                String t = trusted ? "T" : "U";
                Ansi.Color tc = trusted ? Ansi.Color.GREEN : RED;

                Ansi ansi = ansi()
                        .a("[").bold().fg(rc).a(r).reset().a("]")
                        .a("[").bold().fg(tc).a(t).reset().a("]")
                        .a(" " + entry.dn());
                System.out.println(ansi);
            }
        });
        System.out.println();
    }
}
