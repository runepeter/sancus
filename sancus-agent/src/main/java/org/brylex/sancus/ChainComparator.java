package org.brylex.sancus;

import java.security.cert.X509Certificate;
import java.util.Comparator;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 20/02/2017.
 */
public class ChainComparator implements Comparator<X509Certificate> {

    @Override
    public int compare(X509Certificate left, X509Certificate right) {

        if (left.equals(right)) {
            return 0;
        } else if (left.getIssuerDN().equals(right.getSubjectDN())) {
            return -1;
        } else if (left.getSubjectDN().equals(right.getIssuerDN())) {
            return 1;
        } else {
            return 0;
        }
    }
}
