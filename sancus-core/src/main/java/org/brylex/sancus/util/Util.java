package org.brylex.sancus.util;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 17/08/2017.
 */
public class Util {

    public static final String DEFAULT_KEYSTORE_PASSWORD = "changeit";

    private Util() {
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
}
