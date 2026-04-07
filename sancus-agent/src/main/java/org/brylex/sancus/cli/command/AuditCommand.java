package org.brylex.sancus.cli.command;

import org.brylex.sancus.audit.*;
import org.brylex.sancus.audit.check.*;
import org.brylex.sancus.audit.output.OutputFormat;
import org.brylex.sancus.audit.output.OutputFormatter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(name = "audit", description = "Perform a TLS audit of a remote host", mixinStandardHelpOptions = true)
public class AuditCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Hostname to audit")
    String host;

    @Option(names = "--port", defaultValue = "443", description = "Port to connect to")
    int port;

    @Option(names = "--format", defaultValue = "ANSI", description = "Output format: ANSI or JSON")
    OutputFormat format;

    private static final List<AuditCheck> CHECKS = List.of(
            new ExpiryCheck(),
            new WeakAlgorithmCheck(),
            new ProtocolCheck(),
            new ChainCompletenessCheck(),
            new OcspCheck(),
            new TransparencyCheck()
    );

    @Override
    public Integer call() {
        HandshakeInfo handshakeInfo;
        try {
            handshakeInfo = AuditHandshakeResolver.connect(host, port);
        } catch (AuditHandshakeResolver.AuditConnectionException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        }

        X509Certificate[] chain = handshakeInfo.serverChain();

        List<Finding> findings = new ArrayList<>();
        for (AuditCheck check : CHECKS) {
            findings.addAll(check.check(handshakeInfo, chain));
        }

        AuditReport report = new AuditReport(host, port, Instant.now(), findings);

        OutputFormatter formatter = OutputFormatter.forFormat(format);
        formatter.format(report, System.out);

        return report.exitCode();
    }

}
