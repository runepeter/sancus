package org.brylex.sancus.cli;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.ResolverSource;
import org.brylex.sancus.TrustStatus;
import org.fusesource.jansi.Ansi;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

import static org.fusesource.jansi.Ansi.Color.RED;
import static org.fusesource.jansi.Ansi.ansi;

public class ConsoleUtil {

    private ConsoleUtil() {
    }

    public static void printChain(CertificateChain chain) {
        chain.visit(new ChainEntry.Visitor() {
            @Override
            public void visit(ChainEntry entry) {

                boolean trusted = entry.trustedBy() != TrustStatus.UNTRUSTED;
                String r = String.format("%-7s", entry.resolvedBy().name());
                Ansi.Color rc = entry.resolvedBy() == ResolverSource.DEFAULT ? Ansi.Color.YELLOW : Ansi.Color.BLUE;
                rc = entry.resolvedBy() == ResolverSource.MISSING ? RED : rc;

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

    public static String consoleInput(String prompt) {

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
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                try {
                    line = reader.readLine();
                } catch (IOException e) {
                    throw new RuntimeException("Unable to read input from console.", e);
                }
            }

            return (line == null ? "" : line).trim();

        } catch (Throwable t) {
            throw new RuntimeException("Unable to get console input.", t);
        }
    }
}
