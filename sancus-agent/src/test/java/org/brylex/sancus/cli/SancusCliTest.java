package org.brylex.sancus.cli;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 18/04/2017.
 */
public class SancusCliTest {
    public static void main(String[] args) throws InterruptedException {

        String[] a = {
            "-h", "10.40.3.187", "-port", "7443", "-truststore", "src/test/resources/jks/selfsigned.jks"
        };

        SancusCli.main(a);
    }
}
