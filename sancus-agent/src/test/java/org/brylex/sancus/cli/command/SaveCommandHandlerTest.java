package org.brylex.sancus.cli.command;

import org.brylex.sancus.CertificateChain;
import org.brylex.sancus.util.UserInput;
import org.brylex.sancus.util.Util;
import org.junit.Test;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import static org.brylex.sancus.util.Certificates.*;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 25/08/2017.
 */
public class SaveCommandHandlerTest {

    @Test
    public void name() throws Exception {

        final CertificateChain chain = CertificateChain.create(DIGGERDETTE, LETSENCRYPT, DST_ROOT);

        final Iterator<String> input = Arrays.asList("3", "q").iterator();

        final SaveCommandHander handler = new SaveCommandHander(new UserInput() {
            @Override
            public String input(String prompt) {
                System.out.print(prompt + ": ");
                return input.next();
            }
        });

        Util.printChain(chain);

        handler.handle(chain, null);

        Util.printChain(chain);
    }
}
