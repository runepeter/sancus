package org.brylex.sancus.cli;

import com.google.common.base.Strings;
import io.vertx.core.net.JksOptions;
import io.vertx.rxjava.core.Vertx;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.RemoteResolver;
import org.brylex.sancus.SancusTrustOptions;
import org.brylex.sancus.resolver.DirResolver;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.Color.RED;
import static org.fusesource.jansi.Ansi.ansi;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 14/04/2017.
 */
public class SancusCli implements CertificateChain.Callback {

    @Option(name = "-host", usage = "Hostname to connect to", required = true)
    public String host;

    @Option(name = "-port", usage = "Port to connect to")
    public int port = 443;

    @Option(name = "-truststore", usage = "Truststore to validate against")
    public Path trustStore;

    @Option(name = "-truststorepwd", usage = "Truststore password")
    public String trustStorePassword = "changeit";

    @Option(name = "-i", usage = "Interactive mode")
    public boolean interactiveMode = false;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

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

        final Vertx vertx = Vertx.vertx();

        CertificateChain chain = resolveCertificateChain(vertx);
        printChain(chain);

        String command;

        while (true) {

            command = consoleInput("Operation");

            if ("q".equalsIgnoreCase(command)) {
                System.exit(1);
            }
            if ("r".equalsIgnoreCase(command)) {
                resolveCommandHandler(chain);
            }
        }
    }

    private String consoleInput(String prompt) {

        try {

            String line;

            final Console console = System.console();
            if (console != null) {
                System.out.print(prompt + ": ");
                System.out.flush();
                line = console.readLine();
            } else {
                System.out.print(prompt + ": ");
                System.out.flush();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    line = reader.readLine();
                } catch (IOException e) {
                    throw new RuntimeException("Unable to read input from console.", e);
                }
            }

            return Strings.nullToEmpty(line).trim();

        } catch (Throwable t) {
            throw new RuntimeException("Unable to get console input.", t);
        }
    }


    private void resolveCommandHandler(CertificateChain chain) {

        Ansi a = ansi()
                .a("\nResolve missing certificates from one of the following sources:\n\n")
                .bold().fg(Ansi.Color.GREEN).a("1. ").fgBlue().a("DEFAULT").reset().a(" jks [").a(getEffectiveDefaultJksPath().toString()).a("].\n")
                .bold().fg(Ansi.Color.GREEN).a("2. ").reset().a("Remotely resolve issuer from certificate extension value (requires Internet access).\n")
                .bold().fg(Ansi.Color.GREEN).a("3. ").reset().a("JKS file.").a('\n')
                .bold().fg(Ansi.Color.GREEN).a("4. ").reset().a("From file folder with PEMs.");

        System.out.println(a);
        System.out.println();

        String option = consoleInput("Option");
        if ("1".equalsIgnoreCase(option)) {
            System.out.println(ansi().fgRed().a("Option [").bold().a(option).boldOff().a("] NOT implemented.").reset());
        } else if ("2".equalsIgnoreCase(option)) {

            final RemoteResolver resolver = new RemoteResolver();
            resolver.resolve(chain);

            printChain(chain);

        } else if ("3".equalsIgnoreCase(option)) {
            System.out.println(ansi().fgRed().a("Option [").bold().a(option).boldOff().a("] NOT implemented.").reset());
        } else if ("4".equalsIgnoreCase(option)) {

            System.out.println();
            String dir = consoleInput("Path");
            System.out.println();
            
            Path path = Paths.get(dir);
            new DirResolver(path).resolve(chain);
            printChain(chain);

        } else {
            System.out.println(ansi().fgRed().a("Unknown option [").bold().a(option).boldOff().a("].").reset());
        }
        System.out.println();
    }

    private CertificateChain resolveCertificateChain(Vertx vertx) {

        final AtomicReference<CertificateChain> certificateChain = new AtomicReference<>();

        JksOptions jksOptions = new JksOptions();
        jksOptions.setPath(resolveJksPath().toAbsolutePath().toString());
        jksOptions.setPassword(trustStorePassword);

        SancusTrustOptions sancusTrustOptions = new SancusTrustOptions(jksOptions);
        sancusTrustOptions.setCallback(new CertificateChain.Callback() {
            @Override
            public void onCertificateChain(CertificateChain chain) {
                certificateChain.set(chain);
            }
        });

        try {
            TrustManagerFactory trustManagerFactory = sancusTrustOptions.getTrustManagerFactory(vertx.getDelegate());

            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, trustManagerFactory.getTrustManagers(), null);

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
            } else {
                throw new RuntimeException(e);
            }
        }

        System.out.println();

        return certificateChain.get();
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

    @Override
    public void onCertificateChain(CertificateChain chain) {
        printChain(chain);
    }

    private void printChain(CertificateChain chain) {
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
