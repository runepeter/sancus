package org.brylex.sancus.cli;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 18/04/2017.
 */
public class SancusCliTest {
    public static void main(String[] args) throws InterruptedException {

        String[] a = {
            "-host", "aws.amazon.com"
        };

        SancusCli.main(a);
    }
}
