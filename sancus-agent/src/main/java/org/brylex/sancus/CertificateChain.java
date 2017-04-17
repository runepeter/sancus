package org.brylex.sancus;

import com.google.common.collect.Lists;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * Created by <a href="mailto:rpbjo@nets.eu">Rune Peter Bjørnstad</a> on 12/04/2017.
 */
public class CertificateChain {

    private final KeyStore jks;
    private final ChainEntry head;
    private ChainEntry last;
    private CertificateChain(X509Certificate certificate) {
        this.head = new ChainEntry(certificate, this);
        try {
            this.jks = KeyStore.getInstance("JKS");
            this.jks.load(null);
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize empty JKS.", e);
        }
    }

    public static CertificateChain create(X509Certificate... chain) {

        checkArgument(chain != null);
        checkArgument(chain.length > 0);

        List<X509Certificate> list = Arrays.asList(chain);
        Collections.sort(list, new ChainComparator());

        Iterator<X509Certificate> iterator = list.iterator();

        CertificateChain c = new CertificateChain(iterator.next());

        ChainEntry entry = c.head;
        while (iterator.hasNext()) {
            X509Certificate next = iterator.next();
            entry = entry.issuedBy(next);
        }

        c.last = entry;

        return c;
    }

    public ChainEntry issuedBy() {
        return head.issuedBy();
    }

    KeyStore jks() {
        return jks;
    }

    public boolean isComplete() {

        // TODO rpbjo: This one does not need to be resolved each time.
        List<X509Certificate> list = toList();
        X509Certificate last = list.get(list.size() - 1);

        return last.getSubjectDN().equals(last.getIssuerDN());
    }

    public List<X509Certificate> toList() {

        final List<X509Certificate> list = Lists.newArrayList();

        ChainEntry entry = head;
        while (entry != null) {

            if (entry.certificate() != null) {
                list.add(entry.certificate());
            }

            entry = entry.issuedBy();
        }

        return list;
    }

    public ChainEntry last(ChainEntry entry) {
        this.last = entry;
        return entry;
    }

    public ChainEntry last() {
        return last;
    }

    @Override
    public String toString() {

        StringBuffer buffer = new StringBuffer();

        ChainEntry entry = head;
        while (entry != null) {

            buffer.append(entry.toString()).append('\n');

            entry = entry.issuedBy();
        }

        return buffer.toString();
    }

    public ChainEntry head() {
        return head;
    }

    public void visit(ChainEntry.Visitor visitor) {
        ChainEntry entry = head;
        while (entry != null) {

            entry.visit(visitor);

            entry = entry.issuedBy();
        }
    }

    public interface Callback {
        void onCertificateChain(CertificateChain chain);
    }

    public interface Resolver {

        CertificateChain resolve(CertificateChain chain);

    }

    public interface Truster {

        CertificateChain check(CertificateChain chain);

    }

}
