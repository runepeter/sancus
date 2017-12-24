package org.brylex.sancus.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.*;
import org.brylex.sancus.resolver.DirResolver;
import org.brylex.sancus.resolver.HandshakeResolver;
import org.brylex.sancus.resolver.KeyStoreResolver;
import org.brylex.sancus.resolver.RemoteResolver;
import org.brylex.sancus.util.Util;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import javax.net.ssl.*;
import java.io.*;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.concurrent.TimeoutException;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 14/04/2017.
 */
public class SancusCli implements CertificateChain.Callback {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Option(name = "--host", aliases = "-h", usage = "Hostname to connect to", forbids = "--cert")
    public String host;
    @Option(name = "-port", usage = "Port to connect to")
    public int port = 443;
    @Option(name = "--cert", aliases = "-c", usage = "Certificate to trust", forbids = "--host")
    public Path certificate;
    @Option(name = "-truststore", usage = "Truststore to validate against")
    public Path trustStore;
    @Option(name = "-truststorepwd", usage = "Truststore password")
    public String trustStorePassword = "changeit";
    @Option(name = "-i", usage = "Interactive mode")
    public boolean interactiveMode = false;

    public static void main(String[] args) throws InterruptedException {

        final SancusCli cli = new SancusCli();

        CmdLineParser parser = new CmdLineParser(cli);
        try {
            parser.parseArgument(args);
        } catch (CmdLineException e) {
            parser.printUsage(System.err);
            System.exit(-1);
        }

        AnsiConsole.systemInstall();

        cli.doIt();
    }

    private void doIt() {

        CertificateChain chain = resolveCertificateChain();
        Util.printChain(chain);

        String command;

        while (true) {

            command = Util.consoleInput("Operation");

            if ("q".equalsIgnoreCase(command)) {
                System.exit(1);
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

        try (OutputStream os = Files.newOutputStream(trustStore, StandardOpenOption.CREATE)) {

            if (chain.jks().containsAlias("dummy-sancus")) {
                chain.jks().deleteEntry("dummy-sancus");
            }

            chain.jks().store(os, trustStorePassword.toCharArray());
            System.out.println("Successfully saved KeyStore at [" + trustStore.toAbsolutePath() + "].\n");

        } catch (Exception e) {
            throw new RuntimeException("Unable to save KeyStore at [" + trustStore.toAbsolutePath() + "].", e);
        }
    }

    private void handshakeCommandHandler(CertificateChain chain) {

        System.out.println("\nPerforming SSL Handshake with [" + host + ":" + port + "] ...");

        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(chain.jks());

            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, tmf.getTrustManagers(), null);

            SSLSocketFactory factory = context.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(5000);
            socket.startHandshake();
            socket.close();

            System.out.println(ansi().a("Status: ").fg(Ansi.Color.GREEN).a("SUCCESS").reset());

        } catch (Exception e) {

            if (e instanceof UnknownHostException) {
                System.out.println(ansi().a("Status: ").fg(Ansi.Color.RED).a("UNKNOWN_HOST_EXCEPTION").reset());
            } else if (e instanceof TimeoutException) {
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
        Util.printChain(chain);
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

        String option = Util.consoleInput("Option");
        if ("1".equalsIgnoreCase(option)) {

            KeyStore defaultKeyStore = Util.loadKeyStore(resolveDefaultJksPath(), "changeit");

            new KeyStoreResolver("DEFAULT", defaultKeyStore).resolve(chain);

            Util.printChain(chain);

        } else if ("2".equalsIgnoreCase(option)) {

            final RemoteResolver resolver = new RemoteResolver();
            resolver.resolve(chain);

            Util.printChain(chain);

        } else if ("3".equalsIgnoreCase(option)) {
            System.out.println(ansi().fgRed().a("Option [").bold().a(option).boldOff().a("] NOT implemented.").reset());
        } else if ("4".equalsIgnoreCase(option)) {

            System.out.println();
            String dir = Util.consoleInput("Path");
            System.out.println();

            Path path = Paths.get(dir);
            new DirResolver(path).resolve(chain);
            Util.printChain(chain);

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

            try (InputStream is = Files.newInputStream(jksPath, StandardOpenOption.READ)) {
                jks = KeyStore.getInstance("JKS");
                jks.load(is, trustStorePassword.toCharArray());
                System.out.println("Loaded KeyStore [" + jksPath.toAbsolutePath() + "].");
            } catch (Exception e) {
                throw new RuntimeException("Unable to initialize empty KeyStore [" + jksPath + "].", e);
            }

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

    @Override
    public void onCertificateChain(CertificateChain chain) {
        Util.printChain(chain);
    }

}
