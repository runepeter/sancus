package org.brylex.sancus.cli.command;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.util.Certificates;
import org.brylex.sancus.util.Util;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

class ExportKeystoreTest {

    @Test
    void writesJksWithCertificates(@TempDir Path tempDir) throws Exception {
        Path keystoreFile = tempDir.resolve("test.jks");

        CertificateChain chain = CertificateChain.create(
                Certificates.DIGGERDETTE, Certificates.LETSENCRYPT, Certificates.DST_ROOT);

        ResolveCommand cmd = new ResolveCommand();
        cmd.keystorePath = keystoreFile;

        int exitCode = cmd.exportKeystore(chain);

        assertEquals(0, exitCode);
        assertTrue(keystoreFile.toFile().exists());

        KeyStore ks = Util.loadKeyStore(keystoreFile, "changeit");
        assertEquals(3, Collections.list(ks.aliases()).size());
    }

    @Test
    void returnsExitCode2ForEmptyChain(@TempDir Path tempDir) {
        Path keystoreFile = tempDir.resolve("test.jks");

        ResolveCommand cmd = new ResolveCommand();
        cmd.keystorePath = keystoreFile;

        // Create chain with no certificates applied (head is null → toList() is empty)
        KeyStore emptyJks;
        try {
            emptyJks = KeyStore.getInstance("JKS");
            emptyJks.load(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        CertificateChain chain = CertificateChain.create(emptyJks);

        int exitCode = cmd.exportKeystore(chain);

        assertEquals(2, exitCode);
        assertFalse(keystoreFile.toFile().exists());
    }

    @Test
    void keystoreIsJksFormat(@TempDir Path tempDir) throws Exception {
        Path keystoreFile = tempDir.resolve("test.jks");

        CertificateChain chain = CertificateChain.create(Certificates.DIGGERDETTE);

        ResolveCommand cmd = new ResolveCommand();
        cmd.keystorePath = keystoreFile;

        cmd.exportKeystore(chain);

        // Verify the file is loadable as JKS specifically (not PKCS12)
        KeyStore ks = KeyStore.getInstance("JKS");
        try (var is = java.nio.file.Files.newInputStream(keystoreFile)) {
            ks.load(is, Util.DEFAULT_KEYSTORE_PASSWORD.toCharArray());
        }
        assertEquals("jks", ks.getType().toLowerCase());
    }
}
