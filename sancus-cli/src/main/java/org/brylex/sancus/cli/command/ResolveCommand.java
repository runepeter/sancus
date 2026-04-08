package org.brylex.sancus.cli.command;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ResolverSource;
import org.brylex.sancus.TrustMarkerVisitor;
import org.brylex.sancus.cli.ConsoleUtil;
import org.brylex.sancus.resolver.DirResolver;
import org.brylex.sancus.resolver.HandshakeResolver;
import org.brylex.sancus.resolver.KeyStoreResolver;
import org.brylex.sancus.resolver.RemoteResolver;
import org.brylex.sancus.util.Util;
import org.fusesource.jansi.Ansi;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import javax.net.ssl.*;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Callable;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.ansi;

@Command(name = "resolve", description = "Resolve and inspect TLS certificate chains")
public class ResolveCommand implements Callable<Integer> {

    @Option(names = "--help", usageHelp = true, description = "Show this help message and exit.")
    boolean helpRequested;

    @Option(names = {"--host", "-h"}, description = "Hostname to connect to")
    String host;

    @Option(names = {"--port", "-p"}, description = "Port to connect to", defaultValue = "443")
    int port;

    @Option(names = {"--cert", "-c"}, description = "Certificate to trust")
    Path certificate;

    @Option(names = {"--truststore", "-t"}, description = "Truststore to validate against")
    Path trustStore;

    @Option(names = {"--truststorepwd", "-k"}, description = "Truststore password")
    String trustStorePassword = Util.DEFAULT_KEYSTORE_PASSWORD;

    @Option(names = {"--interactive", "-i"}, description = "Interactive mode")
    boolean interactiveMode = false;

    @Option(names = {"--keystore"}, description = "Write resolved chain to JKS keystore (non-interactive)")
    Path keystorePath;

    @Override
    public Integer call() {
        CertificateChain chain = resolveCertificateChain();

        if (keystorePath != null) {
            return exportKeystore(chain);
        }

        String command;
        while (true) {
            command = ConsoleUtil.consoleInput("Operation");

            if ("q".equalsIgnoreCase(command)) {
                return 1;
            }
            if ("r".equalsIgnoreCase(command)) {
                resolveCommandHandler(chain);
            }
            if ("h".equalsIgnoreCase(command)) {
                handshakeCommandHandler(chain);
            }
            if ("s".equalsIgnoreCase(command)) {
                saveCommandHandler(chain);
            }
        }
    }

    Integer exportKeystore(CertificateChain chain) {
        if (chain.toList().isEmpty()) {
            System.err.println("Error: No certificates received from handshake. Cannot write keystore.");
            return 2;
        }

        try {
            new RemoteResolver().resolve(chain);
        } catch (Exception e) {
            System.err.println("Warning: AIA resolution failed: " + e.getMessage());
        }

        List<X509Certificate> resolvedCerts = chain.toList();

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null);

            for (X509Certificate cert : resolvedCerts) {
                String cn = cert.getSubjectX500Principal().getName();
                String alias = cn.length() > 64 ? cn.substring(0, 64) : cn;
                int i = 1;
                String uniqueAlias = alias;
                while (ks.containsAlias(uniqueAlias)) {
                    uniqueAlias = alias + "_" + i++;
                }
                ks.setCertificateEntry(uniqueAlias, cert);
            }

            try (OutputStream os = Files.newOutputStream(keystorePath, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ks.store(os, Util.DEFAULT_KEYSTORE_PASSWORD.toCharArray());
            }

            System.out.println("Wrote " + resolvedCerts.size() + " certificate(s) to [" + keystorePath.toAbsolutePath() + "].");
            return 0;
        } catch (Exception e) {
            System.err.println("Error: Failed to write keystore: " + e.getMessage());
            return 2;
        }
    }

    private void saveCommandHandler(CertificateChain chain) {
        System.out.println();

        try {
            if (chain.jks().size() == 1 && chain.jks().containsAlias("dummy-sancus")) {
                System.out.println("KeyStore is empty. Nothing to save.\n");
                return;
            }
        } catch (KeyStoreException e) {
            throw new RuntimeException("Unable to inspect KeyStore.", e);
        }

        String dir = ConsoleUtil.consoleInput("Path [" + (trustStore != null ? trustStore.toAbsolutePath() : "") + "]");
        System.out.println();

        Path path = "".equals(dir) ? trustStore : Paths.get(dir);

        try (OutputStream os = Files.newOutputStream(path, StandardOpenOption.CREATE)) {
            if (chain.jks().containsAlias("dummy-sancus")) {
                chain.jks().deleteEntry("dummy-sancus");
            }

            chain.jks().store(os, trustStorePassword.toCharArray());
            System.out.println("Successfully saved KeyStore at [" + path.toAbsolutePath() + "].\n");
        } catch (Exception e) {
            throw new RuntimeException("Unable to save KeyStore at [" + path.toAbsolutePath() + "].", e);
        }
    }

    private void handshakeCommandHandler(CertificateChain chain) {
        System.out.println("\nPerforming SSL Handshake with [" + host + ":" + port + "] ...");

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(chain.jks());

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = context.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(5000);
                socket.startHandshake();
            }

            System.out.println(ansi().a("Status: ").fg(Ansi.Color.GREEN).a("SUCCESS").reset());
        } catch (Exception e) {
            if (e instanceof UnknownHostException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("UNKNOWN_HOST_EXCEPTION").reset());
            } else if (e instanceof SocketTimeoutException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("TIMEOUT_EXCEPTION").reset());
            } else if (e instanceof SSLHandshakeException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("SSL_HANDSHAKE_EXCEPTION").reset());
                System.out.println(ansi().a(" Cause: ").fg(Ansi.Color.YELLOW).a(e.getCause()).reset());
            } else {
                throw new RuntimeException(e);
            }
        }

        chain.visit(new TrustMarkerVisitor(chain.jks()));

        System.out.println();
        ConsoleUtil.printChain(chain);
    }

    private void resolveCommandHandler(CertificateChain chain) {
        Ansi a = ansi()
                .a("\nResolve missing certificates from one of the following sources:\n\n")
                .bold().fg(Ansi.Color.GREEN).a("1. ").fgBlue().a("DEFAULT").reset().a(" jks [").a(Util.getEffectiveDefaultJksPath().toString()).a("].\n")
                .bold().fg(Ansi.Color.GREEN).a("2. ").reset().a("Remotely resolve issuer from certificate extension value (requires Internet access).\n")
                .bold().fg(Ansi.Color.GREEN).a("3. ").reset().a("JKS file.").a('\n')
                .bold().fg(Ansi.Color.GREEN).a("4. ").reset().a("From file folder with PEMs.");

        System.out.println(a);
        System.out.println();

        String option = ConsoleUtil.consoleInput("Option");
        if ("1".equalsIgnoreCase(option)) {
            KeyStore defaultKeyStore = Util.loadKeyStore(resolveDefaultJksPath(), trustStorePassword);
            new KeyStoreResolver(ResolverSource.DEFAULT, defaultKeyStore).resolve(chain);
            ConsoleUtil.printChain(chain);
        } else if ("2".equalsIgnoreCase(option)) {
            final RemoteResolver resolver = new RemoteResolver();
            resolver.resolve(chain);
            ConsoleUtil.printChain(chain);
        } else if ("3".equalsIgnoreCase(option)) {
            System.out.println(ansi().fgRed().a("Option [").bold().a(option).boldOff().a("] NOT implemented.").reset());
        } else if ("4".equalsIgnoreCase(option)) {
            System.out.println();
            String dir = ConsoleUtil.consoleInput("Path");
            System.out.println();

            Path path = Paths.get(dir);
            new DirResolver(path).resolve(chain);
            ConsoleUtil.printChain(chain);
        } else {
            System.out.println(ansi().fgRed().a("Unknown option [").bold().a(option).boldOff().a("].").reset());
        }
    }

    private CertificateChain resolveCertificateChain() {
        final KeyStore jks = initKeyStore();
        CertificateChain certificateChain = CertificateChain.create(jks);
        new HandshakeResolver(host, port).resolve(certificateChain);
        return certificateChain;
    }

    private KeyStore initKeyStore() {
        Path jksPath = resolveJksPath();

        KeyStore jks;
        if (jksPath.toFile().isFile()) {
            jks = Util.loadKeyStore(jksPath, trustStorePassword);
            System.out.println("Loaded KeyStore [" + jksPath.toAbsolutePath() + "].");
        } else {
            try {
                jks = KeyStore.getInstance("JKS");
                jks.load(null);
                System.out.println("Initializing brand new KeyStore at [" + jksPath.toAbsolutePath() + "].");
            } catch (Exception e) {
                throw new RuntimeException("Unable to load KeyStore [" + jksPath.toAbsolutePath() + "].", e);
            }
        }
        return jks;
    }

    private Path resolveJksPath() {
        if (trustStore == null) {
            return resolveDefaultJksPath();
        }

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("JKS").reset().a(" [").bold().a(trustStore.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return trustStore;
    }

    private Path resolveDefaultJksPath() {
        Path path = Util.getEffectiveDefaultJksPath();

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("DEFAULT").reset().a(" [").bold().a(path.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return path;
    }
}
