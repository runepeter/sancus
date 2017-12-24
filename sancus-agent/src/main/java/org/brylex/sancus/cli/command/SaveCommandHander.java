package org.brylex.sancus.cli.command;

import com.google.common.collect.Lists;
import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.ChainEntry;
import org.brylex.sancus.util.UserInput;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.fusesource.jansi.Ansi.ansi;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 25/08/2017.
 */
public class SaveCommandHander {

    private final UserInput userInput;

    public SaveCommandHander(UserInput userInput) {
        this.userInput = userInput;
    }

    public void handle(final CertificateChain chain, final KeyStore jks) {

        final List<ChainEntry> entryList = Lists.newArrayList();

        chain.visit(new ChainEntry.Visitor() {
            @Override
            public void visit(ChainEntry entry) {
                entryList.add(entry);
            }
        });

        String input = "";

        while (!"q".equalsIgnoreCase(input)) {
            for (int i = 0; i < entryList.size(); i++) {

                ChainEntry entry = entryList.get(i);

                if ("JKS".equals(entry.resolvedBy())) {
                    System.out.println("     " + entry.dn());
                } else {
                    System.out.println(ansi().bold().fgRed().a((i + 1)).reset() + " :: " + entry.dn());
                }
            }

            System.out.println();
            input = userInput.input("Trust certificate");
            System.out.println(input);

            if (!"q".equalsIgnoreCase(input)) {
                ChainEntry chainEntry = entryList.get(Integer.parseInt(input) - 1);
                X509Certificate certificate = chainEntry.certificate();
                chainEntry.resolvedBy("JKS");
                chainEntry.trustedBy("JKS");

                System.out.println();
                System.out.println("Trust added: [" + ansi().fgGreen().a(certificate.getSubjectDN()).reset() + "]");
                System.out.println();
            }
        }
    }

}
