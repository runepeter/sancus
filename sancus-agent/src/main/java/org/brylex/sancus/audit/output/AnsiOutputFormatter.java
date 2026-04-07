package org.brylex.sancus.audit.output;

import org.brylex.sancus.audit.AuditReport;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Severity;
import org.fusesource.jansi.Ansi;

import java.io.PrintStream;

import static org.fusesource.jansi.Ansi.ansi;

public final class AnsiOutputFormatter implements OutputFormatter {

    @Override
    public void format(AuditReport report, PrintStream out) {
        out.println(ansi().bold().a("\n\u2550\u2550 Sancus TLS Audit: " + report.host() + ":" + report.port() + " \u2550\u2550").reset());
        out.println();

        for (Finding finding : report.findings()) {
            Ansi.Color color = colorFor(finding.severity());
            String symbol = symbolFor(finding.severity());
            String checkName = checkNameFor(finding);
            out.println(ansi()
                    .fg(color).a(symbol).reset()
                    .a(" ")
                    .bold().a(checkName).reset()
                    .a(": ").a(finding.summary()));
        }

        out.println();
        Severity overall = report.overallSeverity();
        Ansi.Color overallColor = colorFor(overall);
        String label = switch (overall) {
            case OK -> "OK";
            case WARNING -> "WARNING";
            case CRITICAL -> "CRITICAL";
        };
        out.println(ansi()
                .a("Overall: ")
                .fg(overallColor).bold().a(label).reset()
                .a(" (exit code " + report.exitCode() + ")"));
        out.println();
    }

    private static String checkNameFor(Finding finding) {
        return switch (finding) {
            case Finding.ExpiryFinding _ -> "Expiry";
            case Finding.RevocationFinding _ -> "OCSP";
            case Finding.WeakAlgorithmFinding _ -> "WeakAlgorithm";
            case Finding.ChainFinding _ -> "ChainCompleteness";
            case Finding.ProtocolFinding _ -> "Protocol";
            case Finding.TransparencyFinding _ -> "Transparency";
        };
    }

    private static String symbolFor(Severity severity) {
        return switch (severity) {
            case OK -> "\u2713";
            case WARNING -> "\u26A0";
            case CRITICAL -> "\u2717";
        };
    }

    private static Ansi.Color colorFor(Severity severity) {
        return switch (severity) {
            case OK -> Ansi.Color.GREEN;
            case WARNING -> Ansi.Color.YELLOW;
            case CRITICAL -> Ansi.Color.RED;
        };
    }
}
