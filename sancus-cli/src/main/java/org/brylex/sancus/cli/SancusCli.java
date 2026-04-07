package org.brylex.sancus.cli;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.brylex.sancus.cli.command.AuditCommand;
import org.brylex.sancus.cli.command.ResolveCommand;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.security.Security;

@Command(
        name = "sancus",
        description = "Sancus TLS certificate toolkit",
        mixinStandardHelpOptions = true,
        subcommands = {ResolveCommand.class, AuditCommand.class}
)
public class SancusCli {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        AnsiConsole.systemInstall();
        CommandLine cmd = new CommandLine(new SancusCli());
        cmd.setCaseInsensitiveEnumValuesAllowed(true);
        System.exit(cmd.execute(args));
    }
}
