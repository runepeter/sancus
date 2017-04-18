package org.brylex.sancus.cli;

import com.google.common.base.Strings;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.net.JksOptions;
import io.vertx.rxjava.core.Vertx;
import io.vertx.rxjava.core.http.HttpClient;
import io.vertx.rxjava.core.http.HttpClientRequest;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.SancusTrustOptions;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.AnsiConsole;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import javax.net.ssl.SSLHandshakeException;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeoutException;

import static org.fusesource.jansi.Ansi.Color.BLUE;
import static org.fusesource.jansi.Ansi.Color.GREEN;
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

    public static void main(String[] args) {

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

        JksOptions jksOptions = new JksOptions();
        jksOptions.setPath(resolveJksPath().toAbsolutePath().toString());
        jksOptions.setPassword(trustStorePassword);

        SancusTrustOptions sancusTrustOptions = new SancusTrustOptions(jksOptions);
        sancusTrustOptions.setCallback(this);

        HttpClientOptions options = new HttpClientOptions();
        options.setSsl(true);
        options.setTrustStoreOptions(sancusTrustOptions);

        final Vertx vertx = Vertx.vertx();

        final HttpClient client = vertx.createHttpClient(options);
        final HttpClientRequest request = client.request(HttpMethod.GET, port, host, "/");
        request.setTimeout(5000).toObservable().subscribe(
                r -> {
                    System.out.println(ansi().fg(GREEN).a("OK").reset());
                    vertx.close();
                },
                e -> {
                    if (e instanceof UnknownHostException) {
                        System.out.println("UNKNOWN_HOST(...)");
                    } else if (e instanceof TimeoutException) {
                        System.out.println("NOT_LISTENING(...)");
                    } else if (e instanceof SSLHandshakeException) {
                        System.out.println(ansi().fg(RED).a("SSL_HANDSHAKE").reset());
                    } else {
                        System.out.println("ERROR");
                    }
                    vertx.close();
                }
        );
        request.end();
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

        String javaHome = System.getProperty("java.home");

        Path path = Paths.get(javaHome, "lib/security/jssecacerts");
        if (!path.toFile().exists()) {
            path = Paths.get(javaHome, "lib/security/cacerts");
        }

        System.out.println(ansi().a("Verifying trust using ").fg(BLUE).a("DEFAULT").reset().a(" [").bold().a(path.toAbsolutePath()).boldOff().a("]."));
        System.out.println();

        return path;
    }

    @Override
    public void onCertificateChain(CertificateChain chain) {
        chain.visit(new ChainEntry.Visitor() {
            @Override
            public void visit(ChainEntry entry) {

                boolean trusted = !entry.trustedBy().equals("NOT");
                String r = Strings.padEnd(entry.resolvedBy(), 7, ' ');
                Ansi.Color rc = r.equals("DEFAULT") ? Ansi.Color.YELLOW : Ansi.Color.BLUE;
                rc = r.equals("MISSING") ? Ansi.Color.RED : rc;

                String t = trusted ? "T" : "U";
                Ansi.Color tc = trusted ? Ansi.Color.GREEN : Ansi.Color.RED;

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
